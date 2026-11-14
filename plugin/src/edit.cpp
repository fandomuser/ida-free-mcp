// Group D: code/data definition, undefine, reanalysis, item classification.
// All modifications need explicit addresses, are range-checked and logged.
#include <string>

#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>

#include "common.hpp"

namespace idamcp {
namespace {

using namespace detail;

constexpr asize_t kMaxEditRange = 64 * 1024;          // define/undefine
constexpr asize_t kMaxReanalyzeRange = 64u << 20;     // reanalysis scheduling

void require_mapped_range(ea_t ea, asize_t size)
{
  if ( size == 0 )
    fail("invalid_params", "size must be > 0");
  if ( ea + size < ea )
    fail("invalid_params", "range overflows the address space");
  for ( ea_t a = ea; a < ea + size; a++ )
    if ( !is_mapped(a) )
      fail("invalid_address", "range " + hexea(ea) + ".." + hexea(ea + size) + " is not fully mapped (first gap at "
                              + hexea(a) + ")");
}

const char *data_kind(flags64_t f)
{
  if ( is_byte(f) ) return "byte";
  if ( is_word(f) ) return "word";
  if ( is_dword(f) ) return "dword";
  if ( is_qword(f) ) return "qword";
  if ( is_oword(f) ) return "oword";
  if ( is_float(f) ) return "float";
  if ( is_double(f) ) return "double";
  if ( is_strlit(f) ) return "string";
  if ( is_struct(f) ) return "struct";
  if ( is_align(f) ) return "align";
  return "other";
}

Value item_info(ea_t ea)
{
  const ea_t head = get_item_head(ea);
  const flags64_t f = get_flags(head);
  Value o = Value::object();
  o.set("address", hexea(ea));
  o.set("item_start", hexea(head));
  o.set("item_end", hexea(get_item_end(head)));
  o.set("item_size", static_cast<int64_t>(get_item_size(head)));
  const char *cls = is_code(f) ? "code" : is_data(f) ? "data" : is_tail(get_flags(ea)) ? "tail" : "unknown";
  o.set("class", is_unknown(f) ? "unknown" : cls);
  if ( is_data(f) )
  {
    o.set("data_type", data_kind(f));
    const asize_t elsz = get_data_elsize(head, f);
    if ( elsz > 0 )
      o.set("element_count", static_cast<int64_t>(get_item_size(head) / elsz));
  }
  if ( is_code(f) )
    o.set("flow_from_previous", is_flow(f));
  o.set("function", func_ref(head));
  o.set("is_function_start", get_func_start(head) == head);
  const std::string nm = ea_name(head);
  if ( !nm.empty() ) o.set("name", nm);
  o.set("has_user_name", has_user_name(f));
  o.set("has_comment", has_cmt(f));
  o.set("has_xrefs_to", has_xref(f));
  qstring ts;
  if ( print_type(&ts, head, PRTYPE_1LINE) )
    o.set("type", to_std(ts));
  qstring seg;
  get_segment_name(&seg, head);
  o.set("segment", to_std(seg));
  qstring line;
  generate_disasm_line(&line, head, GENDSM_REMOVE_TAGS);
  o.set("line", to_std(line));
  return o;
}

Value h_get_item_info(Call &c)
{
  return item_info(p_ea(c, "address"));
}

Value h_define_code(Call &c)
{
  const ea_t ea = p_ea(c, "address");
  const int64_t max_insns = p_int(c, "max_instructions", 1, 1, 4096);
  const std::string end_s = p_str(c, "end", false, 32);
  ea_t end = BADADDR;
  if ( !end_s.empty() && (!parse_hex_ea(end_s, &end) || end <= ea) )
    fail("invalid_params", "end must be a hex address greater than address");
  if ( end != BADADDR )
  {
    if ( end - ea > kMaxEditRange )
      fail("invalid_params", "range too large (max 64 KiB per call)");
    require_mapped_range(ea, end - ea);
  }
  if ( end == BADADDR && is_code(get_flags(ea)) && get_item_head(ea) == ea )
  {
    Value o = Value::object();
    o.set("address", hexea(ea));
    o.set("instructions_created", 0);
    o.set("already_code", true);
    o.set("item", item_info(ea));
    return o;
  }
  // Walk forward creating instructions; existing code is skipped. Stops at `end`,
  // after max_instructions new instructions, at the first non-decodable byte, or at the deadline.
  ea_t cur = ea;
  int64_t created = 0;
  Value failed_at = Value();
  while ( created < max_insns && (end == BADADDR || cur < end) && !c.expired() )
  {
    if ( is_code(get_flags(cur)) && get_item_head(cur) == cur )
    {
      cur = get_item_end(cur);
      continue;
    }
    insn_t insn;
    const int len = create_insn(cur, &insn);
    if ( len <= 0 )
    {
      failed_at = Value(hexea(cur));
      break;
    }
    created++;
    cur += len;
  }
  if ( created == 0 && end == BADADDR )
    fail("ida_rejected", "IDA could not create an instruction at " + hexea(ea)
                         + " (bytes do not decode, or a data item is in the way; ida_undefine it first)");
  msg("[idamcp] defined %lld instruction(s) at %s\n", static_cast<long long>(created), hexea(ea).c_str());
  Value o = Value::object();
  o.set("address", hexea(ea));
  o.set("instructions_created", created);
  o.set("next_address", hexea(cur));
  if ( !failed_at.is_null() )
    o.set("stopped_at", failed_at);
  o.set("item", item_info(ea));
  return o;
}

Value h_define_data(Call &c)
{
  const ea_t ea = p_ea(c, "address");
  const std::string type = p_str(c, "type", true, 16);
  const int64_t count = p_int(c, "count", 1, 1, 65536);
  const int64_t str_len = p_int(c, "length", 0, 0, 65536);
  asize_t elsz;
  flags64_t ff;
  if ( type == "byte" ) { elsz = 1; ff = byte_flag(); }
  else if ( type == "word" ) { elsz = 2; ff = word_flag(); }
  else if ( type == "dword" ) { elsz = 4; ff = dword_flag(); }
  else if ( type == "qword" ) { elsz = 8; ff = qword_flag(); }
  else if ( type == "float" ) { elsz = 4; ff = float_flag(); }
  else if ( type == "double" ) { elsz = 8; ff = double_flag(); }
  else if ( type == "string" || type == "string16" )
  {
    const int32 strtype = type == "string" ? STRTYPE_C : STRTYPE_C_16;
    if ( str_len > 0 )
      require_mapped_range(ea, static_cast<asize_t>(str_len));
    if ( !create_strlit(ea, static_cast<size_t>(str_len), strtype) )
      fail("ida_rejected", "IDA could not create a string at " + hexea(ea)
                           + " (no terminator found, or existing items are in the way; ida_undefine them first)");
    msg("[idamcp] defined %s at %s\n", type.c_str(), hexea(ea).c_str());
    Value o = Value::object();
    o.set("item", item_info(ea));
    qstring txt;
    get_strlit_contents(&txt, ea, get_item_size(ea), strtype, nullptr, STRCONV_ESCAPE);
    o.set("text", to_std(txt));
    return o;
  }
  else
  {
    fail("invalid_params", "type must be one of: byte, word, dword, qword, float, double, string, string16");
  }
  const asize_t total = elsz * static_cast<asize_t>(count);
  if ( total > kMaxEditRange )
    fail("invalid_params", "data too large (max 64 KiB per call)");
  require_mapped_range(ea, total);
  if ( get_func_start(ea) != BADADDR && is_code(get_flags(ea)) )
    fail("invalid_params", hexea(ea) + " is code inside a function; ida_undefine it first if this is intended");
  if ( !create_data(ea, ff, total, BADNODE) )
    fail("ida_rejected", "IDA could not define " + std::to_string(count) + " " + type + "(s) at " + hexea(ea)
                         + " (existing items are in the way; ida_undefine them first)");
  msg("[idamcp] defined %lld %s(s) at %s\n", static_cast<long long>(count), type.c_str(), hexea(ea).c_str());
  Value o = Value::object();
  o.set("item", item_info(ea));
  return o;
}

Value h_undefine(Call &c)
{
  const ea_t ea = p_ea(c, "address");
  const int64_t size = p_int(c, "size", 0, 1, kMaxEditRange);
  if ( size <= 0 )
    fail("invalid_params", "missing required parameter 'size' (bytes to undefine, max 65536)");
  const bool allow_functions = p_bool(c, "allow_function_code", false);
  require_mapped_range(ea, static_cast<asize_t>(size));
  if ( !allow_functions )
  {
    for ( ea_t a = ea; a < ea + size; a = next_head(a, ea + size) )
    {
      if ( a == BADADDR ) break;
      if ( is_code(get_flags(a)) && get_func_start(a) != BADADDR )
        fail("invalid_params", "range contains code of function " + func_name(a) + " at " + hexea(a)
                               + "; pass allow_function_code=true to undefine it anyway");
    }
  }
  if ( !del_items(ea, DELIT_SIMPLE, static_cast<asize_t>(size)) )
    fail("ida_rejected", "IDA could not undefine " + hexea(ea) + ".." + hexea(ea + size));
  msg("[idamcp] undefined %s..%s\n", hexea(ea).c_str(), hexea(ea + size).c_str());
  Value o = Value::object();
  o.set("start", hexea(ea));
  o.set("end", hexea(ea + size));
  o.set("item", item_info(ea));
  return o;
}

Value h_reanalyze_range(Call &c)
{
  const ea_t start = p_ea(c, "start");
  const std::string end_s = p_str(c, "end", true, 32);
  ea_t end;
  if ( !parse_hex_ea(end_s, &end) || end <= start )
    fail("invalid_params", "end must be a hex address greater than start");
  if ( end - start > kMaxReanalyzeRange )
    fail("invalid_params", "range too large (max 64 MiB)");
  if ( !is_mapped(end - 1) )
    fail("invalid_address", hexea(end - 1) + " is not mapped");
  plan_range(start, end);
  msg("[idamcp] scheduled reanalysis of %s..%s\n", hexea(start).c_str(), hexea(end).c_str());
  Value o = Value::object();
  o.set("start", hexea(start));
  o.set("end", hexea(end));
  o.set("scheduled", true);
  o.set("note", "IDA's auto-analysis processes the range in the background; check auto_analysis_complete "
                "in ida_status");
  return o;
}

const MethodDef kEditMethods[] = {
  {"get_item_info", h_get_item_info, false},
  {"define_code", h_define_code, true},
  {"define_data", h_define_data, true},
  {"undefine", h_undefine, true},
  {"reanalyze_range", h_reanalyze_range, true},
};

}  // namespace

MethodTable edit_methods() { return {kEditMethods, qnumber(kEditMethods)}; }

}  // namespace idamcp
