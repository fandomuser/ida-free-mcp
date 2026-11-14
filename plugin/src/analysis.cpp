// Groups G + I (+ fingerprints for H): function intelligence built from one
// SDK-decoded pass over a function's instructions. Heuristic results (crypto,
// similarity inputs) are labelled as candidates, never as proof.
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include "common.hpp"

namespace idamcp {
namespace {

using namespace detail;

// ---------------------------------------------------------------- known constants
struct KnownConst
{
  uint64 value;
  const char *algorithm;
  const char *what;
};

// Immediates that strongly suggest specific algorithms (candidates only).
const KnownConst kKnownImmediates[] = {
  {0x67452301, "MD5/SHA-1", "initial state A"},
  {0xEFCDAB89, "MD5/SHA-1", "initial state B"},
  {0x98BADCFE, "MD5/SHA-1", "initial state C"},
  {0x10325476, "MD5/SHA-1", "initial state D"},
  {0xC3D2E1F0, "SHA-1", "initial state E"},
  {0x5A827999, "SHA-1", "round constant"},
  {0x6ED9EBA1, "SHA-1", "round constant"},
  {0x8F1BBCDC, "SHA-1", "round constant"},
  {0xCA62C1D6, "SHA-1", "round constant"},
  {0xD76AA478, "MD5", "T[1]"},
  {0x6A09E667, "SHA-256", "initial state H0"},
  {0xBB67AE85, "SHA-256", "initial state H1"},
  {0x428A2F98, "SHA-256", "K[0]"},
  {0x6A09E667F3BCC908ULL, "SHA-512", "initial state H0"},
  {0x9E3779B9, "TEA/XTEA (golden ratio)", "delta"},
  {0x61C88647, "TEA/XTEA", "negated delta"},
  {0xEDB88320, "CRC-32", "reflected polynomial"},
  {0x04C11DB7, "CRC-32", "polynomial"},
  {0x82F63B78, "CRC-32C", "reflected polynomial"},
  {0x811C9DC5, "FNV-1a 32", "offset basis"},
  {0x01000193, "FNV-1/FNV-1a 32", "prime"},
  {0xCBF29CE484222325ULL, "FNV-1a 64", "offset basis"},
  {0x100000001B3ULL, "FNV-1/FNV-1a 64", "prime"},
  {0xCC9E2D51, "MurmurHash3", "c1"},
  {0x1B873593, "MurmurHash3", "c2"},
  {0x9E3779B1, "xxHash32", "PRIME32_1"},
  {0x85EBCA77, "xxHash32", "PRIME32_2"},
  {0x243F6A88, "Blowfish", "P-array[0]"},
  {0x61707865, "Salsa20/ChaCha20", "\"expa\" constant"},
  {0x3320646E, "Salsa20/ChaCha20", "\"nd 3\" constant"},
  {0x79622D32, "Salsa20/ChaCha20", "\"2-by\" constant"},
  {0x6B206574, "Salsa20/ChaCha20", "\"te k\" constant"},
};

const KnownConst *known_immediate(uint64 v)
{
  for ( const auto &k : kKnownImmediates )
    if ( k.value == v || (k.value <= 0xFFFFFFFFULL && (v & 0xFFFFFFFFULL) == k.value && v > 0xFFFFFFFFULL
                          && (v >> 32) == 0xFFFFFFFFULL) )
      return &k;
  return nullptr;
}

struct KnownTable
{
  const char *algorithm;
  const char *what;
  const char *pattern;  // IDA byte pattern (validated hex)
};

// Byte signatures of well-known tables/strings (little-endian where multi-byte).
const KnownTable kKnownTables[] = {
  {"AES", "forward S-box", "63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76"},
  {"AES", "inverse S-box", "52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB"},
  {"CRC-32", "lookup table (LE)", "00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99"},
  {"SHA-256", "K table (LE dwords)", "98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9"},
  {"SHA-256", "K table (BE dwords)", "42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5"},
  {"MD5", "T table (LE dwords)", "78 A4 6A D7 56 B7 C7 E8 DB 70 20 24 EE CE BD C1"},
  {"MD5/SHA-1", "initial state (LE)", "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10"},
  {"SHA-256", "initial state (LE)", "67 E6 09 6A 85 AE 67 BB 72 F3 6E 3C 3A F5 4F A5"},
  {"SHA-512", "K table (LE qwords)", "22 AE 28 D7 98 2F 8A 42 CD 65 EF 23 91 44 37 71"},
  {"Blowfish", "P-array (LE)", "88 6A 3F 24 D3 08 A3 85 2E 8A 19 13 44 73 70 03"},
  {"Salsa20/ChaCha20", "sigma string", "\"expand 32-byte k\""},
  {"Salsa20/ChaCha20", "tau string", "\"expand 16-byte k\""},
  {"Base64", "standard alphabet", "\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\""},
  {"DES", "S-box 1 (as bytes)", "0E 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07"},
};

// ---------------------------------------------------------------- one-pass scan
struct FuncScan
{
  ea_t start = BADADDR;
  int64_t insns = 0;
  std::map<std::string, int64_t> mnemonics;        // canonical mnemonic -> count
  std::map<uint64, int64_t> constants;             // immediate -> uses
  std::map<uint64, std::vector<ea_t>> const_sites;
  std::vector<std::pair<ea_t, ea_t>> callees;      // (site, target)
  std::set<ea_t> callee_targets;
  std::set<ea_t> imports;                          // import slots referenced
  std::set<ea_t> strings;                          // string literals referenced
  std::set<ea_t> globals;                          // other data referenced
  int64_t xor_ops = 0, shift_ops = 0, rotate_ops = 0, arith_ops = 0, mem_ops = 0;
  uint64 exact_hash = 1469598103934665603ULL;      // FNV-1a 64 over bytes
  uint64 norm_hash = 1469598103934665603ULL;       // FNV-1a 64 over (mnemonic, operand types)
  bool truncated = false;
};

inline void fnv(uint64 &h, const void *p, size_t n)
{
  const uchar *b = static_cast<const uchar *>(p);
  for ( size_t i = 0; i < n; i++ )
  {
    h ^= b[i];
    h *= 1099511628211ULL;
  }
}

std::string hex64(uint64 v)
{
  char b[24];
  qsnprintf(b, sizeof(b), "%016llx", static_cast<unsigned long long>(v));
  return b;
}

std::set<ea_t> import_slots()
{
  std::set<ea_t> s;
  const uint n = get_import_module_qty();
  for ( uint m = 0; m < n; m++ )
    enum_import_names(static_cast<int>(m), [](ea_t ea, const char *, uval_t, void *p) -> int {
      static_cast<std::set<ea_t> *>(p)->insert(ea);
      return 1;
    }, &s);
  return s;
}

bool mnem_in(const std::string &m, std::initializer_list<const char *> set)
{
  for ( const char *s : set )
    if ( m == s )
      return true;
  return false;
}

FuncScan scan_function(func_t *pfn, const std::set<ea_t> &imports, const Call &c)
{
  FuncScan fs;
  fs.start = pfn->start_ea;
  rangeset_t ranges;
  get_func_ranges_ea(&ranges, pfn->start_ea);
  for ( size_t ri = 0; ri < ranges.nranges(); ri++ )
  {
    const range_t &r = ranges.getrange(static_cast<int>(ri));
    // Exact byte hash over each chunk.
    std::vector<uchar> buf(static_cast<size_t>(std::min<asize_t>(r.size(), 1u << 20)));
    if ( !buf.empty() && get_bytes(buf.data(), buf.size(), r.start_ea, GMB_READALL) > 0 )
      fnv(fs.exact_hash, buf.data(), buf.size());
  }
  for_each_func_head(pfn, 0, [&](ea_t ea) {
    if ( (fs.insns & 0x3FF) == 0x3FF && c.expired() )
    {
      fs.truncated = true;
      return false;
    }
    if ( !is_code(get_flags(ea)) )
      return true;
    insn_t insn;
    if ( decode_insn(&insn, ea) <= 0 )
      return true;
    fs.insns++;
    const char *cm = insn.get_canon_mnem(PH);
    const std::string mn = cm != nullptr ? cm : "?";
    fs.mnemonics[mn]++;
    fnv(fs.norm_hash, mn.data(), mn.size());
    if ( mnem_in(mn, {"xor", "pxor", "xorps", "eor"}) ) fs.xor_ops++;
    if ( mnem_in(mn, {"shl", "shr", "sar", "sal", "lsl", "lsr", "asr", "shld", "shrd"}) ) fs.shift_ops++;
    if ( mnem_in(mn, {"rol", "ror", "rcl", "rcr"}) ) fs.rotate_ops++;
    if ( mnem_in(mn, {"add", "sub", "imul", "mul", "adc", "sbb", "not", "and", "or"}) ) fs.arith_ops++;
    for ( int i = 0; i < UA_MAXOP; i++ )
    {
      const op_t &op = insn.ops[i];
      if ( op.type == o_void )
        break;
      const uchar ot = static_cast<uchar>(op.type);
      fnv(fs.norm_hash, &ot, 1);
      if ( op.type == o_mem || op.type == o_phrase || op.type == o_displ )
        fs.mem_ops++;
      if ( op.type == o_imm )
      {
        // Ignore immediates that are really addresses (offsets into the image).
        if ( !(is_mapped(static_cast<ea_t>(op.value)) && op.value > 0xFFFF) )
        {
          fs.constants[op.value]++;
          auto &sites = fs.const_sites[op.value];
          if ( sites.size() < 8 ) sites.push_back(ea);
        }
      }
    }
    const bool is_call = is_call_insn(insn);
    xrefblk_t xb;
    for ( bool ok = xb.first_from(ea, XREF_NOFLOW); ok; ok = xb.next_from() )
    {
      const ea_t to = xb.to;
      if ( xb.iscode )
      {
        const uchar t = xb.type & XREF_MASK;
        if ( t == fl_CN || t == fl_CF )
        {
          fs.callees.emplace_back(ea, to);
          fs.callee_targets.insert(to);
        }
        continue;
      }
      if ( imports.count(to) != 0 )
      {
        fs.imports.insert(to);
        if ( is_call )
        {
          fs.callees.emplace_back(ea, to);
          fs.callee_targets.insert(to);
        }
      }
      else if ( is_strlit(get_flags(to)) )
        fs.strings.insert(to);
      else if ( !is_code(get_flags(to)) )
        fs.globals.insert(to);
    }
    return true;
  });
  return fs;
}

struct CfgSummary
{
  int64_t blocks = 0, edges = 0, back_edges = 0, return_blocks = 0, max_out = 0;
  Value block_list = Value::array();
};

CfgSummary cfg_summary(func_t *pfn, bool want_blocks, int64_t max_blocks)
{
  CfgSummary s;
  qflow_chart_t fc("", pfn, BADADDR, BADADDR, FC_NOEXT);
  s.blocks = fc.size();
  for ( int i = 0; i < fc.size(); i++ )
  {
    const qbasic_block_t &bb = fc.blocks[i];
    s.edges += static_cast<int64_t>(bb.succ.size());
    s.max_out = std::max<int64_t>(s.max_out, static_cast<int64_t>(bb.succ.size()));
    for ( int t : bb.succ )
      if ( t >= 0 && t < fc.size() && fc.blocks[t].start_ea <= bb.start_ea )
        s.back_edges++;
    if ( fc.is_ret_block(i) )
      s.return_blocks++;
    if ( want_blocks && static_cast<int64_t>(s.block_list.as_array().size()) < max_blocks )
    {
      Value b = Value::object();
      b.set("id", i);
      b.set("start", hexea(bb.start_ea));
      b.set("end", hexea(bb.end_ea));
      Value succ = Value::array();
      for ( int t : bb.succ ) succ.push(t);
      b.set("successors", std::move(succ));
      s.block_list.push(std::move(b));
    }
  }
  return s;
}

Value crypto_assessment(const FuncScan &fs, const CfgSummary &cfg)
{
  Value reasons = Value::array();
  std::set<std::string> algos;
  for ( const auto &kv : fs.constants )
    if ( const KnownConst *k = known_immediate(kv.first) )
    {
      algos.insert(k->algorithm);
      reasons.push(std::string("uses ") + hexea(kv.first) + " (" + k->algorithm + " " + k->what + ")");
    }
  const int64_t bitops = fs.xor_ops + fs.shift_ops + fs.rotate_ops;
  const double density = fs.insns > 0 ? static_cast<double>(bitops) / static_cast<double>(fs.insns) : 0.0;
  if ( cfg.back_edges > 0 && bitops >= 3 )
    reasons.push("loop with " + std::to_string(bitops) + " xor/shift/rotate operations");
  if ( fs.rotate_ops > 0 )
    reasons.push(std::to_string(fs.rotate_ops) + " rotate instruction(s)");
  if ( cfg.back_edges > 0 && fs.xor_ops > 0 && fs.mem_ops > 0 && fs.insns < 120 )
    reasons.push("small loop combining xor with memory access (possible encode/decode loop)");
  double score = 0.0;
  score += algos.empty() ? 0.0 : 0.6;
  score += std::min(0.3, density * 1.5);
  score += cfg.back_edges > 0 ? 0.1 : 0.0;
  score = std::min(score, 1.0);
  Value o = Value::object();
  o.set("is_candidate", score >= 0.35 || !algos.empty());
  o.set("score", score);
  Value al = Value::array();
  for ( const auto &a : algos ) al.push(a);
  o.set("algorithm_candidates", std::move(al));
  o.set("reasons", std::move(reasons));
  o.set("note", "heuristic: constants and instruction patterns suggest, but do not prove, the algorithm");
  return o;
}

Value string_ref(ea_t ea)
{
  Value s = Value::object();
  s.set("address", hexea(ea));
  qstring txt;
  const flags64_t f = get_flags(ea);
  if ( is_strlit(f) )
  {
    get_strlit_contents(&txt, ea, get_item_size(ea), get_str_type(ea), nullptr, STRCONV_ESCAPE);
    std::string t = to_std(txt);
    if ( t.size() > 200 ) t.resize(200);
    s.set("text", t);
  }
  return s;
}

Value named_ref(ea_t ea)
{
  Value o = Value::object();
  o.set("address", hexea(ea));
  const std::string nm = ea_name(ea);
  if ( !nm.empty() ) o.set("name", nm);
  return o;
}

template <typename Set, typename Fn>
Value capped(const Set &set, size_t cap, Fn fn, bool *trunc)
{
  Value a = Value::array();
  size_t n = 0;
  for ( const auto &x : set )
  {
    if ( n++ >= cap ) { *trunc = true; break; }
    a.push(fn(x));
  }
  return a;
}

// ---------------------------------------------------------------- handlers
Value h_analyze_function(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const std::string detail = p_str(c, "detail", false, 16, "standard");
  if ( detail != "brief" && detail != "standard" && detail != "deep" )
    fail("invalid_params", "detail must be one of: brief, standard, deep");
  const bool std_ = detail != "brief";
  const bool deep = detail == "deep";
  const size_t cap = deep ? 200 : std_ ? 40 : 15;
  const ea_t fea = pfn->start_ea;

  const std::set<ea_t> imports = import_slots();
  const FuncScan fs = scan_function(pfn, imports, c);
  const CfgSummary cfg = cfg_summary(pfn, deep, 300);
  bool trunc = fs.truncated;

  Value o = Value::object();
  o.set("detail", detail);
  o.set("address", hexea(fea));
  o.set("name", func_name(fea));
  o.set("size", static_cast<int64_t>(calc_func_size_ea(fea)));
  o.set("instruction_count", fs.insns);
  o.set("flags", func_flags(pfn->flags));

  tinfo_t tif;
  bool guessed = false;
  if ( !get_tinfo(&tif, fea) )
    guessed = guess_tinfo(&tif, fea) == GUESS_FUNC_OK;
  if ( !tif.empty() )
  {
    qstring decl;
    tif.print(&decl, func_name(fea).c_str(), PRTYPE_1LINE | PRTYPE_SEMI);
    o.set("prototype", to_std(decl));
    o.set("prototype_guessed", guessed);
    func_type_data_t fi;
    if ( tif.get_func_details(&fi) )
    {
      static const std::map<int, const char *> kCC = {
        {CM_CC_CDECL, "cdecl"}, {CM_CC_STDCALL, "stdcall"}, {CM_CC_FASTCALL, "fastcall"},
        {CM_CC_THISCALL, "thiscall"}, {CM_CC_SPECIAL, "usercall"}, {CM_CC_ELLIPSIS, "cdecl_varargs"},
        {CM_CC_VOIDARG, "voidarg"}};
      auto it = kCC.find(fi.get_cc() & CM_CC_MASK);
      o.set("calling_convention", it != kCC.end() ? it->second : "other");
      if ( std_ )
      {
        Value args = Value::array();
        for ( const funcarg_t &a : fi )
        {
          Value av = Value::object();
          av.set("name", to_std(a.name));
          qstring ts;
          a.type.print(&ts);
          av.set("type", to_std(ts));
          args.push(std::move(av));
        }
        o.set("arguments", std::move(args));
      }
    }
  }

  // Control flow
  Value cf = Value::object();
  cf.set("basic_blocks", cfg.blocks);
  cf.set("edges", cfg.edges);
  cf.set("cyclomatic_complexity", cfg.edges - cfg.blocks + 2);
  cf.set("loops_back_edges", cfg.back_edges);
  cf.set("return_blocks", cfg.return_blocks);
  if ( deep )
    cf.set("blocks", cfg.block_list);
  o.set("control_flow", std::move(cf));

  // Calls
  std::vector<ea_t> callee_list(fs.callee_targets.begin(), fs.callee_targets.end());
  o.set("callees", capped(callee_list, cap, [&](ea_t t) {
    Value v = named_ref(t);
    v.set("is_import", imports.count(t) != 0);
    return v;
  }, &trunc));
  std::set<ea_t> caller_funcs;
  int64_t caller_sites = 0;
  xrefblk_t xb;
  for ( bool ok = xb.first_to(fea, XREF_NOFLOW); ok; ok = xb.next_to() )
    if ( xb.iscode )
    {
      caller_sites++;
      const ea_t f = get_func_start(xb.from);
      caller_funcs.insert(f != BADADDR ? f : xb.from);
    }
  o.set("callers", capped(caller_funcs, cap, [&](ea_t f) { return named_ref(f); }, &trunc));
  o.set("caller_sites", caller_sites);
  o.set("imports", capped(fs.imports, cap, [&](ea_t t) { return named_ref(t); }, &trunc));
  o.set("strings", capped(fs.strings, cap, [&](ea_t s) { return string_ref(s); }, &trunc));

  if ( std_ )
  {
    o.set("globals", capped(fs.globals, cap, [&](ea_t g) { return named_ref(g); }, &trunc));
    // Constants, most used first.
    std::vector<std::pair<uint64, int64_t>> consts(fs.constants.begin(), fs.constants.end());
    std::sort(consts.begin(), consts.end(), [](auto &a, auto &b) { return a.second > b.second; });
    Value cv = Value::array();
    for ( size_t i = 0; i < consts.size() && i < (deep ? 300u : 50u); i++ )
    {
      Value k = Value::object();
      k.set("value", hexea(consts[i].first));
      k.set("uses", consts[i].second);
      if ( const KnownConst *kc = known_immediate(consts[i].first) )
        k.set("known", std::string(kc->algorithm) + " " + kc->what);
      cv.push(std::move(k));
    }
    o.set("constants", std::move(cv));
    // Stack frame summary.
    tinfo_t frame;
    if ( get_func_frame_ea(&frame, fea) )
    {
      Value fr = Value::object();
      fr.set("frame_size", static_cast<int64_t>(get_frame_size_ea(fea)));
      fr.set("locals_size", static_cast<int64_t>(pfn->frsize));
      fr.set("member_count", static_cast<int64_t>(frame.get_udt_nmembers()));
      o.set("stack_frame", std::move(fr));
    }
    // Comments.
    Value cm = Value::array();
    qstring q;
    if ( get_func_cmt_ea(&q, fea, false) > 0 ) cm.push(Value(std::string("function: ") + to_std(q)));
    if ( get_func_cmt_ea(&q, fea, true) > 0 ) cm.push(Value(std::string("function (repeatable): ") + to_std(q)));
    int64_t n = 0;
    for_each_func_head(pfn, 0, [&](ea_t ea) {
      if ( n >= static_cast<int64_t>(cap) ) return false;
      qstring t;
      if ( get_cmt(&t, ea, false) > 0 || get_cmt(&t, ea, true) > 0 )
      {
        Value e = Value::object();
        e.set("address", hexea(ea));
        e.set("comment", to_std(t));
        cm.push(std::move(e));
        n++;
      }
      return true;
    });
    o.set("comments", std::move(cm));
    o.set("crypto_heuristic", crypto_assessment(fs, cfg));
  }
  if ( deep )
  {
    Value hist = Value::object();
    for ( const auto &kv : fs.mnemonics ) hist.set(kv.first, kv.second);
    o.set("mnemonic_histogram", std::move(hist));
    Value sites = Value::array();
    for ( size_t i = 0; i < fs.callees.size() && i < 300; i++ )
    {
      Value s = Value::object();
      s.set("site", hexea(fs.callees[i].first));
      s.set("target", named_ref(fs.callees[i].second));
      sites.push(std::move(s));
    }
    o.set("call_sites", std::move(sites));
  }
  o.set("truncated", trunc);
  return o;
}

Value h_get_function_constants(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const bool include_small = p_bool(c, "include_small", false);
  const int64_t limit = p_int(c, "limit", 200, 1, kMaxPage);
  const FuncScan fs = scan_function(pfn, import_slots(), c);
  std::vector<std::pair<uint64, int64_t>> consts;
  for ( const auto &kv : fs.constants )
    if ( include_small || kv.first > 0xFF )
      consts.push_back(kv);
  std::sort(consts.begin(), consts.end(), [](auto &a, auto &b) { return a.second > b.second || (a.second == b.second && a.first < b.first); });
  Value items = Value::array();
  for ( size_t i = 0; i < consts.size() && static_cast<int64_t>(i) < limit; i++ )
  {
    Value k = Value::object();
    k.set("value", hexea(consts[i].first));
    k.set("decimal", static_cast<int64_t>(consts[i].first));
    k.set("uses", consts[i].second);
    Value sites = Value::array();
    for ( ea_t s : fs.const_sites.at(consts[i].first) ) sites.push(hexea(s));
    k.set("sites", std::move(sites));
    if ( const KnownConst *kc = known_immediate(consts[i].first) )
    {
      k.set("known_algorithm_candidate", kc->algorithm);
      k.set("known_meaning", kc->what);
    }
    items.push(std::move(k));
  }
  Value o = Value::object();
  o.set("function", func_ref(pfn->start_ea));
  o.set("constants", std::move(items));
  o.set("distinct_constants", static_cast<int64_t>(consts.size()));
  o.set("truncated_by_deadline", fs.truncated);
  return o;
}

Value h_find_crypto_constants(Call &c)
{
  ea_t start = inf_get_min_ea();
  ea_t end = inf_get_max_ea();
  const std::string ss = p_str(c, "start", false, 32);
  const std::string es = p_str(c, "end", false, 32);
  if ( !ss.empty() && !parse_hex_ea(ss, &start) ) fail("invalid_params", "start must be a hex address");
  if ( !es.empty() && !parse_hex_ea(es, &end) ) fail("invalid_params", "end must be a hex address");
  if ( end <= start ) fail("invalid_params", "end must be greater than start");
  const int64_t max = p_int(c, "max_results", 200, 1, kMaxSearchResults);
  const bool skip_tables = p_bool(c, "skip_tables", false);

  Value tables = Value::array();
  if ( !skip_tables )
  {
    for ( const auto &kt : kKnownTables )
    {
      if ( c.expired() ) break;
      compiled_binpat_vec_t pat;
      if ( !parse_binpat_str(&pat, start, kt.pattern, 16, PBSENC_DEF1BPU, nullptr) )
        continue;
      ea_t cur = start;
      int found = 0;
      while ( cur < end && found < 16 && !c.expired() )
      {
        const ea_t hit = bin_search(cur, end, pat, BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW
                                                 | BIN_SEARCH_CASE);
        if ( hit == BADADDR || hit >= end )
          break;
        Value m = Value::object();
        m.set("address", hexea(hit));
        m.set("algorithm_candidate", kt.algorithm);
        m.set("evidence", kt.what);
        m.set("kind", "data_signature");
        const std::string nm = ea_name(hit);
        if ( !nm.empty() ) m.set("name", nm);
        // Functions referencing the table.
        Value users = Value::array();
        xrefblk_t xb;
        for ( bool ok = xb.first_to(hit, XREF_DATA); ok && users.as_array().size() < 10; ok = xb.next_to() )
          users.push(func_ref(xb.from));
        m.set("referenced_by", std::move(users));
        tables.push(std::move(m));
        found++;
        cur = hit + 1;
      }
    }
  }

  // Immediate operands in code.
  Value imms = Value::array();
  bool truncated = false;
  ea_t resume = BADADDR;
  int64_t scanned = 0;
  ea_t ea = start;
  if ( !is_head(get_flags(ea)) ) ea = next_head(ea, end);
  for ( ; ea != BADADDR && ea < end; ea = next_head(ea, end) )
  {
    if ( (++scanned & 0x3FF) == 0 && c.expired() )
    {
      truncated = true;
      resume = ea;
      break;
    }
    if ( !is_code(get_flags(ea)) )
      continue;
    insn_t insn;
    if ( decode_insn(&insn, ea) <= 0 )
      continue;
    for ( int i = 0; i < UA_MAXOP; i++ )
    {
      const op_t &op = insn.ops[i];
      if ( op.type == o_void ) break;
      if ( op.type != o_imm ) continue;
      const KnownConst *k = known_immediate(op.value);
      if ( k == nullptr ) continue;
      if ( static_cast<int64_t>(imms.as_array().size()) >= max )
      {
        resume = ea;
        break;
      }
      Value m = Value::object();
      m.set("address", hexea(ea));
      m.set("value", hexea(op.value));
      m.set("algorithm_candidate", k->algorithm);
      m.set("evidence", k->what);
      m.set("kind", "immediate");
      m.set("function", func_ref(ea));
      imms.push(std::move(m));
    }
    if ( resume != BADADDR ) break;
  }
  // Group immediates per function for a quick overview.
  std::map<std::string, std::set<std::string>> per_func;
  for ( const auto &m : imms.as_array() )
  {
    const Value *f = m.find("function");
    const std::string key = (f != nullptr && !f->is_null()) ? f->find("name")->as_string() : std::string("(no function)");
    per_func[key].insert(m.find("algorithm_candidate")->as_string());
  }
  Value summary = Value::array();
  for ( const auto &kv : per_func )
  {
    Value s = Value::object();
    s.set("function", kv.first);
    Value al = Value::array();
    for ( const auto &a : kv.second ) al.push(a);
    s.set("algorithm_candidates", std::move(al));
    summary.push(std::move(s));
  }
  Value o = Value::object();
  o.set("start", hexea(start));
  o.set("end", hexea(end));
  o.set("table_matches", std::move(tables));
  o.set("immediate_matches", std::move(imms));
  o.set("functions", std::move(summary));
  o.set("next_start", resume == BADADDR ? Value() : Value(hexea(resume)));
  o.set("truncated_by_deadline", truncated);
  o.set("note", "candidates only: a known constant suggests an algorithm but does not prove it");
  return o;
}

Value h_function_fingerprints(Call &c)
{
  const int64_t offset = p_int(c, "offset", 0, 0, INT64_MAX);
  const int64_t limit = p_int(c, "limit", 100, 1, 500);
  const int64_t qty = static_cast<int64_t>(get_func_qty());
  const std::set<ea_t> imports = import_slots();
  Value items = Value::array();
  int64_t n = offset;
  bool truncated = false;
  for ( ; n < qty && static_cast<int64_t>(items.as_array().size()) < limit; n++ )
  {
    if ( c.expired() )
    {
      truncated = true;
      break;
    }
    const ea_t fea = get_func_ea_by_num(static_cast<size_t>(n));
    func_t *pfn = get_func(fea);
    if ( pfn == nullptr )
      continue;
    const FuncScan fs = scan_function(pfn, imports, c);
    if ( fs.truncated )
    {
      truncated = true;
      break;
    }
    const CfgSummary cfg = cfg_summary(pfn, false, 0);
    Value f = Value::object();
    f.set("address", hexea(fea));
    f.set("name", func_name(fea));
    f.set("named", has_user_name(get_flags(fea)) || (get_func_flags(fea) & FUNC_LIB) != 0);
    f.set("size", static_cast<int64_t>(calc_func_size_ea(fea)));
    f.set("instructions", fs.insns);
    f.set("blocks", cfg.blocks);
    f.set("edges", cfg.edges);
    f.set("exact_hash", hex64(fs.exact_hash));
    f.set("normalized_hash", hex64(fs.norm_hash));
    Value hist = Value::object();
    for ( const auto &kv : fs.mnemonics ) hist.set(kv.first, kv.second);
    f.set("mnemonics", std::move(hist));
    Value callees = Value::array();
    int k = 0;
    for ( ea_t t : fs.callee_targets )
    {
      if ( k++ >= 32 ) break;
      const std::string nm = ea_name(t);
      callees.push(nm.empty() ? hexea(t) : nm);
    }
    f.set("callees", std::move(callees));
    Value strs = Value::array();
    k = 0;
    for ( ea_t s : fs.strings )
    {
      if ( k++ >= 16 ) break;
      qstring txt;
      get_strlit_contents(&txt, s, get_item_size(s), get_str_type(s), nullptr, STRCONV_ESCAPE);
      std::string t = to_std(txt);
      if ( t.size() > 80 ) t.resize(80);
      strs.push(t);
    }
    f.set("strings", std::move(strs));
    items.push(std::move(f));
  }
  return page(std::move(items), offset, n < qty ? n : -1, qty, truncated);
}

const MethodDef kAnalysisMethods[] = {
  {"analyze_function", h_analyze_function, false},
  {"get_function_constants", h_get_function_constants, false},
  {"find_crypto_constants", h_find_crypto_constants, false},
  {"function_fingerprints", h_function_fingerprints, false},
};

}  // namespace

MethodTable analysis_methods() { return {kAnalysisMethods, qnumber(kAnalysisMethods)}; }

}  // namespace idamcp
