// Groups E + F: advanced search and structured instruction decoding.
// Operand facts come from the SDK decoder (decode_insn/op_t), never from parsing
// the formatted assembly text. Every scan is range-bounded, deadline-bounded and
// resumable through `next_start`.
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <search.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include "common.hpp"

namespace idamcp {
namespace detail {

const char *optype_name(optype_t t)
{
  switch ( t )
  {
    case o_reg: return "register";
    case o_mem: return "memory";
    case o_phrase: return "phrase";
    case o_displ: return "displacement";
    case o_imm: return "immediate";
    case o_far: return "far_code";
    case o_near: return "near_code";
    case o_void: return "void";
    default: return "processor_specific";
  }
}

std::string reg_name(int reg, size_t width)
{
  qstring q;
  if ( get_reg_name(&q, reg, width) > 0 )
    return to_std(q);
  return std::string();
}

bool decode_at(ea_t ea, insn_t *insn)
{
  return is_code(get_flags(ea)) && decode_insn(insn, ea) > 0;
}

Value decode_json(ea_t ea, const insn_t &insn)
{
  Value o = Value::object();
  o.set("address", hexea(ea));
  qstring mnem;
  print_insn_mnem(&mnem, ea);
  o.set("mnemonic", to_std(mnem));
  const char *canon = insn.get_canon_mnem(PH);
  if ( canon != nullptr && to_std(mnem) != canon )
    o.set("canonical_mnemonic", canon);
  o.set("itype", static_cast<int64_t>(insn.itype));
  o.set("size", static_cast<int64_t>(insn.size));
  o.set("bytes", bytes_hex(ea, insn.size));
  qstring line;
  generate_disasm_line(&line, ea, GENDSM_REMOVE_TAGS);
  o.set("text", to_std(line));

  Value ops = Value::array();
  for ( int i = 0; i < UA_MAXOP; i++ )
  {
    const op_t &op = insn.ops[i];
    if ( op.type == o_void )
      break;
    Value ov = Value::object();
    ov.set("index", i);
    ov.set("type", optype_name(op.type));
    const size_t dsz = get_dtype_size(op.dtype);
    ov.set("size", static_cast<int64_t>(dsz));
    qstring otext;
    if ( print_operand(&otext, ea, i) )
    {
      qstring plain;
      tag_remove(&plain, otext);
      ov.set("text", to_std(plain));
    }
    switch ( op.type )
    {
      case o_reg:
        ov.set("register", reg_name(op.reg, dsz));
        break;
      case o_imm:
        ov.set("value", static_cast<int64_t>(op.value));
        ov.set("value_hex", hexea(op.value));
        break;
      case o_mem:
      case o_near:
      case o_far:
        ov.set("address", hexea(op.addr));
        if ( !ea_name(op.addr).empty() )
          ov.set("target_name", ea_name(op.addr));
        break;
      case o_displ:
        ov.set("base_register", reg_name(op.phrase, inf_is_64bit() ? 8 : 4));
        ov.set("displacement", static_cast<int64_t>(op.addr));
        break;
      case o_phrase:
        // Processor-specific encoding (e.g. x86 SIB); the register below is the phrase base.
        ov.set("base_register", reg_name(op.phrase, inf_is_64bit() ? 8 : 4));
        break;
      default:
        break;
    }
    ops.push(std::move(ov));
  }
  o.set("operands", std::move(ops));

  // Control flow from the SDK's classification + code xrefs (not from text).
  const bool call = is_call_insn(insn);
  const bool ret = is_ret_insn(insn);
  const bool ijump = is_indirect_jump_insn(insn);
  bool has_jump_xref = false;
  Value refs = Value::array();
  xrefblk_t xb;
  for ( bool ok = xb.first_from(ea, XREF_NOFLOW); ok; ok = xb.next_from() )
  {
    Value r = Value::object();
    r.set("to", hexea(xb.to));
    r.set("type", xref_type_name(xb.type, xb.iscode));
    const std::string nm = ea_name(xb.to);
    if ( !nm.empty() ) r.set("name", nm);
    refs.push(std::move(r));
    const uchar t = xb.type & XREF_MASK;
    if ( xb.iscode && (t == fl_JN || t == fl_JF) )
      has_jump_xref = true;
  }
  const bool flows = !ret && is_flow(get_flags(get_item_end(ea)));
  const char *cf = call ? "call"
                 : ret ? "return"
                 : ijump ? "indirect_jump"
                 : has_jump_xref ? (flows ? "conditional_jump" : "jump")
                 : is_basic_block_end(insn, false) ? "stop"
                 : "sequential";
  o.set("control_flow", cf);
  o.set("references", std::move(refs));
  return o;
}

}  // namespace detail

namespace {

using namespace detail;

struct Range
{
  ea_t start;
  ea_t end;
};

// start/end: optional hex strings; defaults to the whole database.
Range p_range(const Call &c)
{
  Range r{inf_get_min_ea(), inf_get_max_ea()};
  const std::string s = p_str(c, "start", false, 32);
  const std::string e = p_str(c, "end", false, 32);
  if ( !s.empty() && !parse_hex_ea(s, &r.start) )
    fail("invalid_params", "start must be a hex address");
  if ( !e.empty() && !parse_hex_ea(e, &r.end) )
    fail("invalid_params", "end must be a hex address");
  if ( r.end <= r.start )
    fail("invalid_params", "end must be greater than start");
  return r;
}

Value search_result(Value matches, ea_t resume, bool truncated, const Range &r)
{
  Value o = Value::object();
  o.set("start", hexea(r.start));
  o.set("end", hexea(r.end));
  o.set("matches", std::move(matches));
  o.set("next_start", resume == BADADDR ? Value() : Value(hexea(resume)));
  o.set("truncated_by_deadline", truncated);
  return o;
}

Value match_line(ea_t ea)
{
  Value m = Value::object();
  m.set("address", hexea(ea));
  m.set("function", func_ref(ea));
  qstring line;
  generate_disasm_line(&line, ea, GENDSM_REMOVE_TAGS);
  m.set("text", to_std(line));
  return m;
}

Value h_decode_instruction(Call &c)
{
  const ea_t ea = p_ea(c, "address");
  const int64_t count = p_int(c, "count", 1, 1, 200);
  Value list = Value::array();
  ea_t cur = get_item_head(ea);
  for ( int64_t i = 0; i < count && cur != BADADDR && cur < inf_get_max_ea(); i++ )
  {
    insn_t insn;
    if ( !decode_at(cur, &insn) )
    {
      if ( i == 0 )
        fail("not_code", hexea(cur) + " is not an instruction (see ida_get_item_info; ida_define_code converts bytes)");
      break;
    }
    list.push(decode_json(cur, insn));
    cur = next_head(cur, inf_get_max_ea());
  }
  if ( count == 1 )
    return list.as_array()[0];
  Value o = Value::object();
  o.set("instructions", std::move(list));
  return o;
}

Value h_search_immediate(Call &c)
{
  const Range r = p_range(c);
  const int64_t max = p_int(c, "max_results", 100, 1, kMaxSearchResults);
  const Value *vv = param(c, "value");
  if ( vv == nullptr || !(vv->is_int() || vv->is_string()) )
    fail("invalid_params", "value is required (integer, or hex string like \"0x67452301\")");
  uval_t value;
  if ( vv->is_int() )
  {
    value = static_cast<uval_t>(vv->as_int());
  }
  else
  {
    ea_t tmp;
    if ( !parse_hex_ea(vv->as_string(), &tmp) )
      fail("invalid_params", "value string must be hex like 0x67452301");
    value = static_cast<uval_t>(tmp);
  }
  Value matches = Value::array();
  bool truncated = false;
  ea_t resume = BADADDR;
  ea_t ea = r.start;
  // find_imm(SEARCH_NEXT) skips `ea` itself, so start one byte before when possible.
  ea_t from = ea > inf_get_min_ea() ? ea - 1 : ea;
  for ( ;; )
  {
    if ( c.expired() )
    {
      truncated = true;
      resume = from + 1;
      break;
    }
    int opnum = -1;
    const ea_t hit = find_imm(from, SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOBRK | SEARCH_NOSHOW, value, &opnum);
    if ( hit == BADADDR || hit >= r.end )
      break;
    if ( hit < r.start )
    {
      from = hit;
      continue;
    }
    if ( static_cast<int64_t>(matches.as_array().size()) >= max )
    {
      resume = hit;
      break;
    }
    Value m = match_line(hit);
    m.set("operand", opnum);
    matches.push(std::move(m));
    from = hit;
  }
  Value o = search_result(std::move(matches), resume, truncated, r);
  o.set("value", hexea(value));
  return o;
}

bool ieq(const std::string &a, const std::string &b)
{
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
         });
}

Value h_search_instructions(Call &c)
{
  const Range r = p_range(c);
  const int64_t max = p_int(c, "max_results", 100, 1, kMaxSearchResults);
  const std::string mnem = p_str(c, "mnemonic", false, 32);
  const std::string optype = p_str(c, "operand_type", false, 24);
  const std::string reg = p_str(c, "register", false, 32);
  const Value *immv = param(c, "immediate");
  const std::string target_s = p_str(c, "target", false, 32);
  const bool restrict_to_functions = p_bool(c, "functions_only", false);
  if ( mnem.empty() && optype.empty() && reg.empty() && immv == nullptr && target_s.empty() )
    fail("invalid_params", "give at least one filter: mnemonic, operand_type, register, immediate, target");
  static const char *const kTypes[] = {"register", "memory", "phrase", "displacement", "immediate",
                                       "far_code", "near_code"};
  if ( !optype.empty() && std::none_of(std::begin(kTypes), std::end(kTypes), [&](const char *t) { return optype == t; }) )
    fail("invalid_params", "operand_type must be one of: register, memory, phrase, displacement, immediate, "
                           "far_code, near_code");
  bool want_imm = false;
  uval_t imm = 0;
  if ( immv != nullptr )
  {
    want_imm = true;
    if ( immv->is_int() ) imm = static_cast<uval_t>(immv->as_int());
    else
    {
      ea_t tmp;
      if ( !immv->is_string() || !parse_hex_ea(immv->as_string(), &tmp) )
        fail("invalid_params", "immediate must be an integer or a hex string");
      imm = static_cast<uval_t>(tmp);
    }
  }
  ea_t target = BADADDR;
  if ( !target_s.empty() && !parse_hex_ea(target_s, &target) )
    fail("invalid_params", "target must be a hex address");

  Value matches = Value::array();
  bool truncated = false;
  ea_t resume = BADADDR;
  int64_t scanned = 0;
  ea_t ea = r.start;
  if ( !is_head(get_flags(ea)) )
    ea = next_head(ea, r.end);
  for ( ; ea != BADADDR && ea < r.end; ea = next_head(ea, r.end) )
  {
    if ( (++scanned & 0x3FF) == 0 && c.expired() )
    {
      truncated = true;
      resume = ea;
      break;
    }
    if ( !is_code(get_flags(ea)) )
      continue;
    if ( restrict_to_functions && get_func_start(ea) == BADADDR )
      continue;
    insn_t insn;
    if ( decode_insn(&insn, ea) <= 0 )
      continue;
    if ( !mnem.empty() )
    {
      qstring m;
      print_insn_mnem(&m, ea);
      const char *canon = insn.get_canon_mnem(PH);
      if ( !ieq(to_std(m), mnem) && !(canon != nullptr && ieq(canon, mnem)) )
        continue;
    }
    if ( !optype.empty() || !reg.empty() || want_imm || target != BADADDR )
    {
      bool hit = false;
      for ( int i = 0; i < UA_MAXOP && !hit; i++ )
      {
        const op_t &op = insn.ops[i];
        if ( op.type == o_void )
          break;
        if ( !optype.empty() && optype != optype_name(op.type) )
          continue;
        if ( !reg.empty() )
        {
          const size_t dsz = get_dtype_size(op.dtype);
          const bool is_reg_op = op.type == o_reg && ieq(reg_name(op.reg, dsz), reg);
          const bool is_base = (op.type == o_phrase || op.type == o_displ)
                            && ieq(reg_name(op.phrase, inf_is_64bit() ? 8 : 4), reg);
          if ( !is_reg_op && !is_base )
            continue;
        }
        if ( want_imm && !(op.type == o_imm && op.value == imm) )
          continue;
        if ( target != BADADDR && !((op.type == o_mem || op.type == o_near || op.type == o_far) && op.addr == target) )
          continue;
        hit = true;
      }
      if ( !hit )
        continue;
    }
    if ( static_cast<int64_t>(matches.as_array().size()) >= max )
    {
      resume = ea;
      break;
    }
    matches.push(match_line(ea));
  }
  return search_result(std::move(matches), resume, truncated, r);
}

Value h_search_disassembly(Call &c)
{
  const Range r = p_range(c);
  const int64_t max = p_int(c, "max_results", 100, 1, kMaxSearchResults);
  const std::string text = p_str(c, "text", true, 256);
  const bool case_sensitive = p_bool(c, "case_sensitive", false);
  const bool code_only = p_bool(c, "code_only", true);
  if ( text.empty() )
    fail("invalid_params", "text must not be empty");
  const std::string needle = case_sensitive ? text : lower(text);
  Value matches = Value::array();
  bool truncated = false;
  ea_t resume = BADADDR;
  int64_t scanned = 0;
  ea_t ea = r.start;
  if ( !is_head(get_flags(ea)) )
    ea = next_head(ea, r.end);
  for ( ; ea != BADADDR && ea < r.end; ea = next_head(ea, r.end) )
  {
    if ( (++scanned & 0xFF) == 0 && c.expired() )
    {
      truncated = true;
      resume = ea;
      break;
    }
    if ( code_only && !is_code(get_flags(ea)) )
      continue;
    qstring line;
    generate_disasm_line(&line, ea, GENDSM_REMOVE_TAGS);
    const std::string s = to_std(line);
    const bool hit = case_sensitive ? s.find(needle) != std::string::npos : icontains(s, needle);
    if ( !hit )
      continue;
    if ( static_cast<int64_t>(matches.as_array().size()) >= max )
    {
      resume = ea;
      break;
    }
    matches.push(match_line(ea));
  }
  return search_result(std::move(matches), resume, truncated, r);
}

Value h_search_pointers(Call &c)
{
  const ea_t target = p_ea(c, "target");
  const Range r = p_range(c);
  const int64_t max = p_int(c, "max_results", 100, 1, kMaxSearchResults);
  const bool aligned_only = p_bool(c, "aligned_only", true);
  const int psize = inf_is_64bit() ? 8 : (inf_get_app_bitness() == 16 ? 2 : 4);

  // 1) References IDA already recognised as offsets/pointers to the target.
  Value recognised = Value::array();
  xrefblk_t xb;
  for ( bool ok = xb.first_to(target, XREF_DATA); ok; ok = xb.next_to() )
  {
    if ( (xb.type & XREF_MASK) != dr_O || xb.from < r.start || xb.from >= r.end )
      continue;
    if ( static_cast<int64_t>(recognised.as_array().size()) >= max )
      break;
    Value m = match_line(xb.from);
    m.set("is_code", is_code(get_flags(xb.from)));
    recognised.push(std::move(m));
  }

  // 2) Raw pointer-sized values equal to the target anywhere in the range.
  uchar pat[8];
  for ( int i = 0; i < psize; i++ )
    pat[i] = static_cast<uchar>((static_cast<uint64>(target) >> (inf_is_be() ? 8 * (psize - 1 - i) : 8 * i)) & 0xFF);
  compiled_binpat_vec_t bv;
  compiled_binpat_t &b = bv.push_back();
  b.bytes.append(pat, psize);
  Value raw = Value::array();
  bool truncated = false;
  ea_t resume = BADADDR;
  ea_t cur = r.start;
  while ( cur < r.end )
  {
    if ( c.expired() )
    {
      truncated = true;
      resume = cur;
      break;
    }
    const ea_t chunk_end = (r.end - cur > kSearchChunk) ? cur + kSearchChunk : r.end;
    const ea_t window_end = std::min<ea_t>(r.end, chunk_end + psize - 1);
    const ea_t hit = bin_search(cur, window_end, bv, BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW);
    if ( hit == BADADDR || hit >= chunk_end )
    {
      cur = chunk_end;
      continue;
    }
    cur = hit + 1;
    if ( aligned_only && (hit % psize) != 0 )
      continue;
    if ( static_cast<int64_t>(raw.as_array().size()) >= max )
    {
      resume = hit;
      break;
    }
    Value m = Value::object();
    m.set("address", hexea(hit));
    m.set("function", func_ref(hit));
    qstring seg;
    get_segment_name(&seg, hit);
    m.set("segment", to_std(seg));
    m.set("defined_as", is_code(get_flags(hit)) ? "code" : is_data(get_flags(get_item_head(hit))) ? "data" : "unknown");
    raw.push(std::move(m));
  }
  Value o = Value::object();
  o.set("target", hexea(target));
  o.set("pointer_size", psize);
  o.set("recognized_references", std::move(recognised));
  o.set("raw_matches", std::move(raw));
  o.set("next_start", resume == BADADDR ? Value() : Value(hexea(resume)));
  o.set("truncated_by_deadline", truncated);
  return o;
}

const MethodDef kSearchMethods[] = {
  {"decode_instruction", h_decode_instruction, false},
  {"search_immediate", h_search_immediate, false},
  {"search_instructions", h_search_instructions, false},
  {"search_disassembly", h_search_disassembly, false},
  {"search_pointers", h_search_pointers, false},
};

}  // namespace

MethodTable search_methods() { return {kSearchMethods, qnumber(kSearchMethods)}; }

}  // namespace idamcp
