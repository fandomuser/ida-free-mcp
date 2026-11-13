// Standard headers first: the IDA SDK poisons some libc names via macros.
#include <algorithm>
#include <cctype>
#include <map>
#include <string>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <strlist.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include "handlers.hpp"
#include "version.hpp"

namespace idamcp {
namespace {

using mj::Value;

// Hard caps that keep each main-thread request short regardless of input.
constexpr int64_t kMaxPage = 1000;
constexpr int64_t kMaxDisasmLines = 2000;
constexpr int64_t kMaxBytes = 65536;
constexpr int64_t kMaxSearchResults = 1000;
constexpr size_t kMaxNameLen = 511;
constexpr size_t kMaxCommentLen = 8192;
constexpr size_t kMaxStringPreview = 1024;
constexpr asize_t kSearchChunk = 8u << 20;  // bin_search chunk between deadline checks

[[noreturn]] void fail(const char *code, const std::string &msg)
{
  throw BridgeError{code, msg};
}

std::string hexea(ea_t ea)
{
  char b[32];
  qsnprintf(b, sizeof(b), "0x%llX", static_cast<unsigned long long>(ea));
  return b;
}

std::string to_std(const qstring &q)
{
  return std::string(q.c_str(), q.length());
}

std::string lower(std::string s)
{
  for ( auto &ch : s )
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  return s;
}

// -------- parameter access & validation -----------------------------------
const Value *param(const Call &c, const char *key)
{
  const Value *v = c.params.find(key);
  return (v == nullptr || v->is_null()) ? nullptr : v;
}

std::string p_str(const Call &c, const char *key, bool required, size_t max_len,
                  const std::string &def = std::string())
{
  const Value *v = param(c, key);
  if ( v == nullptr )
  {
    if ( required )
      fail("invalid_params", std::string("missing required parameter '") + key + "'");
    return def;
  }
  if ( !v->is_string() )
    fail("invalid_params", std::string("parameter '") + key + "' must be a string");
  if ( v->as_string().size() > max_len )
    fail("invalid_params", std::string("parameter '") + key + "' exceeds " + std::to_string(max_len) + " bytes");
  return v->as_string();
}

int64_t p_int(const Call &c, const char *key, int64_t def, int64_t lo, int64_t hi)
{
  const Value *v = param(c, key);
  if ( v == nullptr )
    return def;
  if ( !v->is_int() )
    fail("invalid_params", std::string("parameter '") + key + "' must be an integer");
  const int64_t x = v->as_int();
  if ( x < lo || x > hi )
    fail("invalid_params", std::string("parameter '") + key + "' must be in [" + std::to_string(lo) + ", "
                         + std::to_string(hi) + "]");
  return x;
}

bool p_bool(const Call &c, const char *key, bool def)
{
  const Value *v = param(c, key);
  if ( v == nullptr )
    return def;
  if ( !v->is_bool() )
    fail("invalid_params", std::string("parameter '") + key + "' must be a boolean");
  return v->as_bool();
}

bool parse_hex_ea(const std::string &s, ea_t *out)
{
  if ( s.size() < 3 || s.size() > 18 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') )
    return false;
  uint64 v = 0;
  for ( size_t i = 2; i < s.size(); i++ )
  {
    const char ch = s[i];
    int d;
    if ( ch >= '0' && ch <= '9' ) d = ch - '0';
    else if ( ch >= 'a' && ch <= 'f' ) d = ch - 'a' + 10;
    else if ( ch >= 'A' && ch <= 'F' ) d = ch - 'A' + 10;
    else return false;
    v = (v << 4) | static_cast<uint64>(d);
  }
  *out = static_cast<ea_t>(v);
  return true;
}

// Resolves an address parameter: "0x..." hex, or a symbol name present in the database.
ea_t p_ea(const Call &c, const char *key, bool required = true, ea_t def = BADADDR)
{
  const std::string s = p_str(c, key, required, kMaxNameLen + 1);
  if ( s.empty() )
  {
    if ( required )
      fail("invalid_params", std::string("parameter '") + key + "' must not be empty");
    return def;
  }
  ea_t ea;
  if ( !parse_hex_ea(s, &ea) )
  {
    ea = get_name_ea(BADADDR, s.c_str());
    if ( ea == BADADDR )
      fail("not_found", "no symbol named '" + s + "'; pass a hex address like 0x140001000 "
                        "or use ida_get_names / ida_list_functions to find the right name");
  }
  if ( !is_mapped(ea) )
    fail("invalid_address", hexea(ea) + " is not mapped in the database (valid range "
                            + hexea(inf_get_min_ea()) + ".." + hexea(inf_get_max_ea()) + ")");
  return ea;
}

func_t *p_func(const Call &c, const char *key)
{
  const ea_t ea = p_ea(c, key);
  func_t *pfn = get_func(ea);
  if ( pfn == nullptr )
    fail("not_a_function", hexea(ea) + " is not inside a function; use ida_list_functions, or "
                           "ida_create_function if this is undiscovered code");
  return pfn;
}

// -------- shared formatting ------------------------------------------------
std::string ea_name(ea_t ea)
{
  qstring q;
  get_name(&q, ea);
  return to_std(q);
}

std::string func_name(ea_t ea)
{
  qstring q;
  get_func_name(&q, ea);
  return to_std(q);
}

Value func_ref(ea_t any_ea)
{
  const ea_t start = get_func_start(any_ea);
  if ( start == BADADDR )
    return Value();
  Value o = Value::object();
  o.set("address", hexea(start));
  o.set("name", func_name(start));
  return o;
}

Value func_flags(uint64 f)
{
  Value a = Value::array();
  if ( f & FUNC_NORET ) a.push("noreturn");
  if ( f & FUNC_LIB ) a.push("library");
  if ( f & FUNC_THUNK ) a.push("thunk");
  if ( f & FUNC_FRAME ) a.push("frame");
  if ( f & FUNC_HIDDEN ) a.push("hidden");
  if ( f & FUNC_STATICDEF ) a.push("static");
  return a;
}

std::string bytes_hex(ea_t ea, size_t n)
{
  static const char hex[] = "0123456789abcdef";
  std::vector<uchar> buf(n);
  if ( n == 0 || get_bytes(buf.data(), static_cast<ssize_t>(n), ea, GMB_READALL) <= 0 )
    return std::string();
  std::string out;
  out.reserve(n * 2);
  for ( uchar b : buf )
  {
    out += hex[b >> 4];
    out += hex[b & 0xF];
  }
  return out;
}

Value disasm_line(ea_t ea)
{
  Value o = Value::object();
  o.set("address", hexea(ea));
  const flags64_t f = get_flags(ea);
  if ( has_any_name(f) )
    o.set("label", ea_name(ea));
  const asize_t sz = get_item_size(ea);
  o.set("bytes", bytes_hex(ea, static_cast<size_t>(std::min<asize_t>(sz, 16))));
  qstring line;
  generate_disasm_line(&line, ea, GENDSM_REMOVE_TAGS);
  o.set("text", to_std(line));
  return o;
}

// Calls fn(ea) for every item head in the function's chunks, ascending, starting at `from`.
// Stops when fn returns false.
template <typename Fn>
void for_each_func_head(func_t *pfn, ea_t from, Fn fn)
{
  rangeset_t ranges;
  get_func_ranges_ea(&ranges, pfn->start_ea);
  for ( size_t i = 0; i < ranges.nranges(); i++ )
  {
    const range_t &r = ranges.getrange(static_cast<int>(i));
    if ( r.end_ea <= from )
      continue;
    ea_t ea = std::max(r.start_ea, from);
    if ( !is_head(get_flags(ea)) )
      ea = next_head(ea, r.end_ea);
    for ( ; ea != BADADDR && ea < r.end_ea; ea = next_head(ea, r.end_ea) )
      if ( !fn(ea) )
        return;
  }
}

bool icontains(const std::string &hay, const std::string &needle_lower)
{
  if ( needle_lower.empty() )
    return true;
  auto it = std::search(hay.begin(), hay.end(), needle_lower.begin(), needle_lower.end(),
                        [](char a, char b) {
                          return std::tolower(static_cast<unsigned char>(a)) == b;
                        });
  return it != hay.end();
}

Value page(Value items, int64_t offset, int64_t next_offset, int64_t total, bool truncated)
{
  Value o = Value::object();
  o.set("items", std::move(items));
  o.set("offset", offset);
  o.set("next_offset", next_offset >= 0 ? Value(next_offset) : Value());
  if ( total >= 0 )
    o.set("total", total);
  o.set("truncated_by_deadline", truncated);
  return o;
}

const char *xref_type_name(uchar t, bool iscode)
{
  if ( iscode )
  {
    switch ( t & XREF_MASK )
    {
      case fl_CF: return "call_far";
      case fl_CN: return "call";
      case fl_JF: return "jump_far";
      case fl_JN: return "jump";
      case fl_F: return "flow";
      default: return "code";
    }
  }
  switch ( t & XREF_MASK )
  {
    case dr_O: return "offset";
    case dr_W: return "write";
    case dr_R: return "read";
    case dr_T: return "text";
    case dr_I: return "info";
    default: return "data";
  }
}

int xref_flags_for(const std::string &kind, bool include_flow)
{
  int fl = include_flow ? XREF_FLOW : XREF_NOFLOW;
  if ( kind == "code" ) fl |= XREF_CODE;
  else if ( kind == "data" ) fl |= XREF_DATA;
  else if ( kind != "all" ) fail("invalid_params", "kind must be one of: all, code, data");
  return fl;
}

// =========================================================================
// Read-only handlers
// =========================================================================
Value h_status(Call &)
{
  Value o = Value::object();
  o.set("database_open", true);
  o.set("idb_path", get_path(PATH_TYPE_IDB));
  char in[QMAXPATH] = {0};
  get_input_file_path(in, sizeof(in));
  o.set("input_file", in);
  o.set("auto_analysis_complete", auto_is_ok());
  o.set("function_count", static_cast<int64_t>(get_func_qty()));
  o.set("segment_count", get_segm_qty());
  char ver[64] = {0};
  get_kernel_version(ver, sizeof(ver));
  o.set("ida_version", ver);
  o.set("bridge_version", IDAMCP_VERSION);
  return o;
}

Value h_metadata(Call &)
{
  Value o = Value::object();
  char in[QMAXPATH] = {0};
  get_input_file_path(in, sizeof(in));
  o.set("input_file", in);
  char root[QMAXPATH] = {0};
  get_root_filename(root, sizeof(root));
  o.set("file_name", root);
  o.set("idb_path", get_path(PATH_TYPE_IDB));
  o.set("input_size", static_cast<int64_t>(retrieve_input_file_size()));
  static const char hex[] = "0123456789abcdef";
  auto tohex = [](const uchar *p, size_t n) {
    std::string s;
    for ( size_t i = 0; i < n; i++ ) { s += hex[p[i] >> 4]; s += hex[p[i] & 0xF]; }
    return s;
  };
  uchar md5[16];
  if ( retrieve_input_file_md5(md5) ) o.set("md5", tohex(md5, 16));
  uchar sha[32];
  if ( retrieve_input_file_sha256(sha) ) o.set("sha256", tohex(sha, 32));
  char ftn[256] = {0};
  get_file_type_name(ftn, sizeof(ftn));
  o.set("file_type", ftn);
  o.set("processor", to_std(inf_get_procname()));
  o.set("bitness", static_cast<int64_t>(inf_get_app_bitness()));
  o.set("big_endian", inf_is_be());
  o.set("image_base", hexea(get_imagebase()));
  o.set("min_address", hexea(inf_get_min_ea()));
  o.set("max_address", hexea(inf_get_max_ea()));
  const ea_t start = inf_get_start_ea();
  o.set("entry_point", start == BADADDR ? Value() : Value(hexea(start)));
  const ea_t mainea = inf_get_main();
  o.set("main", mainea == BADADDR ? Value() : Value(hexea(mainea)));
  compiler_info_t cc;
  if ( inf_get_cc(&cc) )
  {
    const char *cn = get_compiler_name(cc.id);
    o.set("compiler", cn != nullptr ? cn : "");
  }
  o.set("function_count", static_cast<int64_t>(get_func_qty()));
  o.set("segment_count", get_segm_qty());
  o.set("entry_count", static_cast<int64_t>(get_entry_qty()));
  o.set("import_module_count", static_cast<int64_t>(get_import_module_qty()));
  o.set("auto_analysis_complete", auto_is_ok());
  return o;
}

Value h_list_segments(Call &c)
{
  const int64_t offset = p_int(c, "offset", 0, 0, INT32_MAX);
  const int64_t limit = p_int(c, "limit", 100, 1, kMaxPage);
  const int qty = get_segm_qty();
  Value items = Value::array();
  int64_t n = offset;
  for ( ; n < qty && static_cast<int64_t>(items.as_array().size()) < limit; n++ )
  {
    segment_info_t si;
    if ( !get_segment_info_by_num(&si, static_cast<int>(n), GSI_NAME | GSI_SCLASS) )
      continue;
    Value s = Value::object();
    s.set("name", si.get_name());
    s.set("class", si.get_sclass());
    s.set("start", hexea(si.start_ea));
    s.set("end", hexea(si.end_ea));
    s.set("size", static_cast<int64_t>(si.end_ea - si.start_ea));
    const uchar p = si.get_perm();
    std::string perm;
    perm += (p & SEGPERM_READ) ? 'r' : '-';
    perm += (p & SEGPERM_WRITE) ? 'w' : '-';
    perm += (p & SEGPERM_EXEC) ? 'x' : '-';
    s.set("permissions", p == 0 ? std::string("unknown") : perm);
    s.set("bitness", static_cast<int64_t>(si.abits()));
    const char *types[] = {"normal", "extern", "code", "data", "impl", "?", "group", "null", "undefined",
                           "bss", "abssym", "comm", "imem"};
    const uchar t = si.get_type();
    s.set("type", t < qnumber(types) ? types[t] : "other");
    items.push(std::move(s));
  }
  return page(std::move(items), offset, n < qty ? n : -1, qty, false);
}

Value h_list_functions(Call &c)
{
  const int64_t offset = p_int(c, "offset", 0, 0, INT64_MAX);
  const int64_t limit = p_int(c, "limit", 100, 1, kMaxPage);
  const std::string filter = lower(p_str(c, "filter", false, kMaxNameLen));
  const int64_t qty = static_cast<int64_t>(get_func_qty());
  Value items = Value::array();
  int64_t n = offset;
  bool truncated = false;
  for ( ; n < qty && static_cast<int64_t>(items.as_array().size()) < limit; n++ )
  {
    if ( (n & 0xFF) == 0 && c.expired() )
    {
      truncated = true;
      break;
    }
    const ea_t ea = get_func_ea_by_num(static_cast<size_t>(n));
    if ( ea == BADADDR )
      continue;
    const std::string name = func_name(ea);
    if ( !filter.empty() && !icontains(name, filter) )
      continue;
    Value f = Value::object();
    f.set("address", hexea(ea));
    f.set("name", name);
    f.set("size", static_cast<int64_t>(calc_func_size_ea(ea)));
    f.set("flags", func_flags(get_func_flags(ea)));
    items.push(std::move(f));
  }
  return page(std::move(items), offset, n < qty ? n : -1, qty, truncated);
}

Value h_get_function(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const ea_t start = pfn->start_ea;
  Value o = Value::object();
  o.set("address", hexea(start));
  o.set("name", func_name(start));
  qstring dem;
  get_long_name(&dem, start);
  if ( !dem.empty() && to_std(dem) != func_name(start) )
    o.set("demangled", to_std(dem));
  o.set("end", hexea(pfn->end_ea));
  o.set("size", static_cast<int64_t>(calc_func_size_ea(start)));
  o.set("flags", func_flags(pfn->flags));
  o.set("bitness", static_cast<int64_t>(get_func_bits_ea(start)));
  rangeset_t ranges;
  get_func_ranges_ea(&ranges, start);
  Value chunks = Value::array();
  for ( size_t i = 0; i < ranges.nranges(); i++ )
  {
    const range_t &r = ranges.getrange(static_cast<int>(i));
    Value ch = Value::object();
    ch.set("start", hexea(r.start_ea));
    ch.set("end", hexea(r.end_ea));
    chunks.push(std::move(ch));
  }
  o.set("chunks", std::move(chunks));
  qstring cmt;
  if ( get_func_cmt_ea(&cmt, start, false) > 0 ) o.set("comment", to_std(cmt));
  if ( get_func_cmt_ea(&cmt, start, true) > 0 ) o.set("repeatable_comment", to_std(cmt));
  int64_t insn_count = 0;
  for_each_func_head(pfn, 0, [&](ea_t ea) {
    if ( is_code(get_flags(ea)) )
      insn_count++;
    return true;
  });
  o.set("instruction_count", insn_count);
  return o;
}

Value h_get_disassembly(Call &c)
{
  const int64_t max_lines = p_int(c, "max_lines", 200, 1, kMaxDisasmLines);
  const std::string mode = p_str(c, "mode", false, 16, "function");
  Value items = Value::array();
  bool truncated = false;
  ea_t next = BADADDR;
  if ( mode == "function" )
  {
    func_t *pfn = p_func(c, "address");
    const ea_t from = p_ea(c, "start_from", false, pfn->start_ea);
    for_each_func_head(pfn, from, [&](ea_t ea) {
      if ( static_cast<int64_t>(items.as_array().size()) >= max_lines || c.expired() )
      {
        truncated = c.expired();
        next = ea;
        return false;
      }
      items.push(disasm_line(ea));
      return true;
    });
    Value o = Value::object();
    o.set("function", func_ref(pfn->start_ea));
    o.set("lines", std::move(items));
    o.set("next_address", next == BADADDR ? Value() : Value(hexea(next)));
    o.set("truncated_by_deadline", truncated);
    return o;
  }
  if ( mode != "linear" )
    fail("invalid_params", "mode must be 'function' or 'linear'");
  ea_t ea = p_ea(c, "address");
  ea = get_item_head(ea);
  const ea_t maxea = inf_get_max_ea();
  while ( ea != BADADDR && ea < maxea )
  {
    if ( static_cast<int64_t>(items.as_array().size()) >= max_lines || c.expired() )
    {
      truncated = c.expired();
      next = ea;
      break;
    }
    items.push(disasm_line(ea));
    ea = next_head(ea, maxea);
  }
  Value o = Value::object();
  o.set("lines", std::move(items));
  o.set("next_address", next == BADADDR ? Value() : Value(hexea(next)));
  o.set("truncated_by_deadline", truncated);
  return o;
}

Value h_get_bytes(Call &c)
{
  const ea_t ea = p_ea(c, "address");
  const int64_t size = p_int(c, "size", 256, 1, kMaxBytes);
  std::vector<uchar> buf(static_cast<size_t>(size));
  std::vector<uchar> mask((static_cast<size_t>(size) + 7) / 8);
  const ssize_t got = get_bytes(buf.data(), size, ea, GMB_READALL, mask.data());
  if ( got < 0 )
    fail("read_failed", "could not read bytes at " + hexea(ea));
  static const char hex[] = "0123456789abcdef";
  std::string out;
  int64_t loaded = 0;
  Value unloaded = Value::array();
  int64_t run_start = -1;
  for ( int64_t i = 0; i < size; i++ )
  {
    const bool ok = (mask[static_cast<size_t>(i / 8)] & (1u << (i % 8))) != 0;
    out += hex[buf[static_cast<size_t>(i)] >> 4];
    out += hex[buf[static_cast<size_t>(i)] & 0xF];
    if ( ok )
    {
      loaded++;
      if ( run_start >= 0 )
      {
        Value r = Value::object();
        r.set("offset", run_start);
        r.set("length", i - run_start);
        unloaded.push(std::move(r));
        run_start = -1;
      }
    }
    else if ( run_start < 0 )
    {
      run_start = i;
    }
  }
  if ( run_start >= 0 )
  {
    Value r = Value::object();
    r.set("offset", run_start);
    r.set("length", size - run_start);
    unloaded.push(std::move(r));
  }
  Value o = Value::object();
  o.set("address", hexea(ea));
  o.set("size", size);
  o.set("hex", out);
  o.set("loaded_bytes", loaded);
  o.set("unloaded_ranges", std::move(unloaded));
  return o;
}

Value h_strings(Call &c)
{
  const int64_t offset = p_int(c, "offset", 0, 0, INT64_MAX);
  const int64_t limit = p_int(c, "limit", 100, 1, kMaxPage);
  const int64_t min_len = p_int(c, "min_length", 0, 0, 1 << 20);
  const std::string query = p_str(c, "query", false, 1024);
  const std::string match = p_str(c, "match", false, 16, "contains");
  const bool case_sensitive = p_bool(c, "case_sensitive", false);
  if ( match != "contains" && match != "exact" && match != "prefix" && match != "suffix" )
    fail("invalid_params", "match must be one of: contains, exact, prefix, suffix");
  const std::string q = case_sensitive ? query : lower(query);

  const int64_t qty = static_cast<int64_t>(get_strlist_qty());
  Value items = Value::array();
  int64_t n = offset;
  bool truncated = false;
  for ( ; n < qty && static_cast<int64_t>(items.as_array().size()) < limit; n++ )
  {
    if ( (n & 0x3F) == 0 && c.expired() )
    {
      truncated = true;
      break;
    }
    string_info_t si;
    if ( !get_strlist_item(&si, static_cast<size_t>(n)) )
      continue;
    if ( si.length < min_len )
      continue;
    qstring txt;
    get_strlit_contents(&txt, si.ea, si.length, si.type, nullptr, STRCONV_ESCAPE);
    std::string text = to_std(txt);
    if ( !q.empty() )
    {
      const std::string hay = case_sensitive ? text : lower(text);
      bool hit;
      if ( match == "exact" ) hit = hay == q;
      else if ( match == "prefix" ) hit = hay.compare(0, q.size(), q) == 0;
      else if ( match == "suffix" ) hit = hay.size() >= q.size() && hay.compare(hay.size() - q.size(), q.size(), q) == 0;
      else hit = hay.find(q) != std::string::npos;
      if ( !hit )
        continue;
    }
    Value s = Value::object();
    s.set("address", hexea(si.ea));
    s.set("length", static_cast<int64_t>(si.length));
    const int width = si.type & STRWIDTH_MASK;
    s.set("encoding", width == STRWIDTH_2B ? "utf-16" : width == STRWIDTH_4B ? "utf-32" : "8-bit");
    if ( text.size() > kMaxStringPreview )
    {
      text.resize(kMaxStringPreview);
      s.set("text_truncated", true);
    }
    s.set("text", text);
    items.push(std::move(s));
  }
  return page(std::move(items), offset, n < qty ? n : -1, qty, truncated);
}

struct ImportRow
{
  ea_t ea;
  std::string name;
  uval_t ord;
  int module;
};

int idaapi import_cb(ea_t ea, const char *name, uval_t ord, void *param)
{
  auto *rows = static_cast<std::vector<ImportRow> *>(param);
  rows->push_back({ea, name != nullptr ? name : "", ord, -1});
  return 1;
}

Value h_imports(Call &c)
{
  const int64_t offset = p_int(c, "offset", 0, 0, INT64_MAX);
  const int64_t limit = p_int(c, "limit", 100, 1, kMaxPage);
  const std::string filter = lower(p_str(c, "filter", false, kMaxNameLen));
  std::vector<std::string> modules;
  std::vector<ImportRow> rows;
  const uint nmods = get_import_module_qty();
  for ( uint m = 0; m < nmods; m++ )
  {
    qstring mn;
    get_import_module_name(&mn, static_cast<int>(m));
    modules.push_back(to_std(mn));
    const size_t before = rows.size();
    enum_import_names(static_cast<int>(m), import_cb, &rows);
    for ( size_t i = before; i < rows.size(); i++ )
      rows[i].module = static_cast<int>(m);
  }
  std::vector<const ImportRow *> sel;
  for ( const auto &r : rows )
    if ( filter.empty() || icontains(r.name, filter) || icontains(modules[static_cast<size_t>(r.module)], filter) )
      sel.push_back(&r);
  Value items = Value::array();
  const int64_t total = static_cast<int64_t>(sel.size());
  int64_t n = offset;
  for ( ; n < total && static_cast<int64_t>(items.as_array().size()) < limit; n++ )
  {
    const ImportRow &r = *sel[static_cast<size_t>(n)];
    Value o = Value::object();
    o.set("address", hexea(r.ea));
    o.set("name", r.name);
    if ( r.name.empty() || r.ord != 0 )
      o.set("ordinal", static_cast<int64_t>(r.ord));
    o.set("module", modules[static_cast<size_t>(r.module)]);
    items.push(std::move(o));
  }
  return page(std::move(items), offset, n < total ? n : -1, total, false);
}

Value h_entries(Call &c)
{
  const int64_t offset = p_int(c, "offset", 0, 0, INT64_MAX);
  const int64_t limit = p_int(c, "limit", 100, 1, kMaxPage);
  const std::string kind = p_str(c, "kind", false, 16, "all");
  const std::string filter = lower(p_str(c, "filter", false, kMaxNameLen));
  if ( kind != "all" && kind != "exports" )
    fail("invalid_params", "kind must be 'all' or 'exports'");
  const ea_t start = inf_get_start_ea();
  const size_t qty = get_entry_qty();
  Value all = Value::array();
  for ( size_t i = 0; i < qty; i++ )
  {
    const uval_t ord = get_entry_ordinal(i);
    const ea_t ea = get_entry(ord);
    // IDA records the program entry point (and other non-exported entries) with
    // ordinal == address; real exports carry their export ordinal.
    const bool is_export = ord != static_cast<uval_t>(ea);
    if ( kind == "exports" && !is_export )
      continue;
    qstring nm;
    get_entry_name(&nm, ord);
    const std::string name = to_std(nm);
    if ( !filter.empty() && !icontains(name, filter) )
      continue;
    Value o = Value::object();
    o.set("address", hexea(ea));
    o.set("name", name);
    if ( is_export )
      o.set("ordinal", static_cast<int64_t>(ord));
    o.set("is_export", is_export);
    o.set("is_program_entry", ea == start);
    qstring fwd;
    if ( get_entry_forwarder(&fwd, ord) > 0 )
      o.set("forwarder", to_std(fwd));
    all.push(std::move(o));
  }
  const int64_t total = static_cast<int64_t>(all.as_array().size());
  Value items = Value::array();
  int64_t n = offset;
  for ( ; n < total && static_cast<int64_t>(items.as_array().size()) < limit; n++ )
    items.push(all.as_array()[static_cast<size_t>(n)]);
  return page(std::move(items), offset, n < total ? n : -1, total, false);
}

Value h_xrefs(Call &c, bool to)
{
  const ea_t ea = p_ea(c, "address");
  const int64_t offset = p_int(c, "offset", 0, 0, INT32_MAX);
  const int64_t limit = p_int(c, "limit", 100, 1, kMaxPage);
  const std::string kind = p_str(c, "kind", false, 8, "all");
  const bool include_flow = p_bool(c, "include_flow", false);
  const int fl = xref_flags_for(kind, include_flow);
  Value items = Value::array();
  int64_t idx = 0;
  bool more = false;
  bool truncated = false;
  xrefblk_t xb;
  for ( bool ok = to ? xb.first_to(ea, fl) : xb.first_from(ea, fl); ok; ok = to ? xb.next_to() : xb.next_from() )
  {
    if ( (idx & 0xFF) == 0 && c.expired() )
    {
      truncated = true;
      break;
    }
    if ( idx++ < offset )
      continue;
    if ( static_cast<int64_t>(items.as_array().size()) >= limit )
    {
      more = true;
      break;
    }
    const ea_t other = to ? xb.from : xb.to;
    Value o = Value::object();
    o.set("from", hexea(xb.from));
    o.set("to", hexea(xb.to));
    o.set("type", xref_type_name(xb.type, xb.iscode));
    o.set("is_code", xb.iscode);
    if ( xb.user )
      o.set("user_defined", true);
    const std::string nm = ea_name(other);
    if ( !nm.empty() )
      o.set(to ? "from_name" : "to_name", nm);
    o.set(to ? "from_function" : "to_function", func_ref(other));
    items.push(std::move(o));
  }
  const int64_t next = truncated ? std::max<int64_t>(idx, offset) : more ? offset + limit : -1;
  Value r = page(std::move(items), offset, next, -1, truncated);
  r.set("address", hexea(ea));
  return r;
}

Value h_xrefs_to(Call &c) { return h_xrefs(c, true); }
Value h_xrefs_from(Call &c) { return h_xrefs(c, false); }

Value h_callers(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const ea_t target = pfn->start_ea;
  const int64_t limit = p_int(c, "limit", 200, 1, kMaxPage);
  std::map<ea_t, size_t> index;  // caller function start (or site for non-function code) -> slot
  Value callers = Value::array();
  Value data_refs = Value::array();
  bool truncated = false;
  bool more = false;
  xrefblk_t xb;
  for ( bool ok = xb.first_to(target, XREF_NOFLOW); ok; ok = xb.next_to() )
  {
    if ( c.expired() )
    {
      truncated = true;
      break;
    }
    if ( !xb.iscode )
    {
      if ( static_cast<int64_t>(data_refs.as_array().size()) < limit )
      {
        Value d = Value::object();
        d.set("from", hexea(xb.from));
        d.set("type", xref_type_name(xb.type, false));
        d.set("function", func_ref(xb.from));
        data_refs.push(std::move(d));
      }
      continue;
    }
    const ea_t fstart = get_func_start(xb.from);
    const ea_t key = fstart != BADADDR ? fstart : xb.from;
    auto it = index.find(key);
    if ( it == index.end() )
    {
      if ( static_cast<int64_t>(callers.as_array().size()) >= limit )
      {
        more = true;
        continue;
      }
      Value o = Value::object();
      o.set("function", fstart != BADADDR ? func_ref(fstart) : Value());
      o.set("call_sites", Value::array());
      index[key] = callers.as_array().size();
      callers.push(std::move(o));
      it = index.find(key);
    }
    Value site = Value::object();
    site.set("address", hexea(xb.from));
    site.set("type", xref_type_name(xb.type, true));
    Value &slot = callers.as_array()[it->second];
    Value sites = *slot.find("call_sites");
    sites.push(std::move(site));
    slot.set("call_sites", std::move(sites));
  }
  Value o = Value::object();
  o.set("function", func_ref(target));
  o.set("callers", std::move(callers));
  o.set("data_references", std::move(data_refs));
  o.set("more_available", more);
  o.set("truncated_by_deadline", truncated);
  return o;
}

Value h_callees(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const ea_t self = pfn->start_ea;
  const int64_t limit = p_int(c, "limit", 200, 1, kMaxPage);
  struct Callee
  {
    ea_t target;
    std::string kind;
    std::vector<ea_t> sites;
  };
  std::vector<Callee> out;
  std::map<std::pair<ea_t, std::string>, size_t> index;
  bool truncated = false;
  auto add = [&](ea_t target, const char *kind, ea_t site) {
    auto key = std::make_pair(target, std::string(kind));
    auto it = index.find(key);
    if ( it == index.end() )
    {
      index[key] = out.size();
      out.push_back({target, kind, {site}});
    }
    else
    {
      out[it->second].sites.push_back(site);
    }
  };
  for_each_func_head(pfn, 0, [&](ea_t ea) {
    if ( c.expired() )
    {
      truncated = true;
      return false;
    }
    if ( !is_code(get_flags(ea)) )
      return true;
    insn_t insn;
    const bool is_call = decode_insn(&insn, ea) > 0 && is_call_insn(insn);
    bool had_code_call = false;
    xrefblk_t xb;
    for ( bool ok = xb.first_from(ea, XREF_NOFLOW); ok; ok = xb.next_from() )
    {
      if ( xb.iscode )
      {
        const uchar t = xb.type & XREF_MASK;
        if ( t == fl_CN || t == fl_CF )
        {
          add(xb.to, "call", ea);
          had_code_call = true;
        }
        else if ( (t == fl_JN || t == fl_JF) && get_func_start(xb.to) != self )
        {
          add(xb.to, "tail_jump", ea);
        }
      }
      else if ( is_call && !had_code_call )
      {
        // e.g. `call cs:__imp_GetTickCount` -> data read of the import pointer.
        add(xb.to, "indirect_call", ea);
      }
    }
    return true;
  });
  Value items = Value::array();
  for ( const auto &e : out )
  {
    if ( static_cast<int64_t>(items.as_array().size()) >= limit )
      break;
    Value o = Value::object();
    o.set("address", hexea(e.target));
    o.set("name", ea_name(e.target));
    o.set("kind", e.kind);
    o.set("function", func_ref(e.target));
    Value sites = Value::array();
    for ( ea_t s : e.sites )
      sites.push(hexea(s));
    o.set("call_sites", std::move(sites));
    items.push(std::move(o));
  }
  Value o = Value::object();
  o.set("function", func_ref(self));
  o.set("callees", std::move(items));
  o.set("more_available", static_cast<int64_t>(out.size()) > limit);
  o.set("truncated_by_deadline", truncated);
  return o;
}

Value h_flowchart(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const bool with_insns = p_bool(c, "include_instructions", false);
  const int64_t max_blocks = p_int(c, "max_blocks", 500, 1, 5000);
  const int64_t max_insns = p_int(c, "max_instructions", 1000, 1, kMaxDisasmLines);
  qflow_chart_t fc("", pfn, BADADDR, BADADDR, FC_NOEXT);
  static const char *const btypes[] = {"normal", "indirect_jump", "return", "conditional_return",
                                       "noreturn", "external_noreturn", "external", "error"};
  Value blocks = Value::array();
  Value edges = Value::array();
  int64_t insns_emitted = 0;
  bool insns_truncated = false;
  const int64_t nblocks = fc.size();
  for ( int i = 0; i < nblocks && i < max_blocks; i++ )
  {
    const qbasic_block_t &bb = fc.blocks[i];
    Value b = Value::object();
    b.set("id", i);
    b.set("start", hexea(bb.start_ea));
    b.set("end", hexea(bb.end_ea));
    const fc_block_type_t bt = fc.calc_block_type(i);
    b.set("type", bt >= 0 && bt < static_cast<int>(qnumber(btypes)) ? btypes[bt] : "unknown");
    Value succ = Value::array();
    for ( int s : bb.succ )
    {
      succ.push(s);
      Value e = Value::object();
      e.set("from", i);
      e.set("to", s);
      edges.push(std::move(e));
    }
    Value pred = Value::array();
    for ( int p : bb.pred )
      pred.push(p);
    b.set("successors", std::move(succ));
    b.set("predecessors", std::move(pred));
    if ( with_insns )
    {
      Value lines = Value::array();
      for ( ea_t ea = bb.start_ea; ea != BADADDR && ea < bb.end_ea; ea = next_head(ea, bb.end_ea) )
      {
        if ( insns_emitted >= max_insns || c.expired() )
        {
          insns_truncated = true;
          break;
        }
        lines.push(disasm_line(ea));
        insns_emitted++;
      }
      b.set("instructions", std::move(lines));
    }
    blocks.push(std::move(b));
  }
  Value o = Value::object();
  o.set("function", func_ref(pfn->start_ea));
  o.set("block_count", nblocks);
  o.set("blocks", std::move(blocks));
  o.set("edges", std::move(edges));
  o.set("blocks_truncated", nblocks > max_blocks);
  if ( with_insns )
    o.set("instructions_truncated", insns_truncated);
  return o;
}

// parse_binpat_str() shows an interactive "search as text?" question on bad
// input, which would block IDA's main thread. Accept only a strict grammar:
// whitespace-separated hex tokens with '?' nibble wildcards, or "quoted strings"
// (backslash escapes allowed). Everything else is rejected up front.
bool validate_binpat(const std::string &p, std::string *why)
{
  size_t i = 0;
  bool any = false;
  while ( i < p.size() )
  {
    const char ch = p[i];
    if ( ch == ' ' || ch == '\t' || ch == ',' )
    {
      i++;
      continue;
    }
    if ( ch == '"' )
    {
      size_t j = i + 1;
      bool closed = false;
      while ( j < p.size() )
      {
        if ( p[j] == '\\' ) { j += 2; continue; }
        if ( p[j] == '"' ) { closed = true; break; }
        if ( static_cast<unsigned char>(p[j]) < 0x20 ) { *why = "control character in quoted string"; return false; }
        j++;
      }
      if ( !closed )
      {
        *why = "unterminated quoted string";
        return false;
      }
      if ( j == i + 1 )
      {
        *why = "empty quoted string";
        return false;
      }
      i = j + 1;
      any = true;
      continue;
    }
    size_t j = i;
    while ( j < p.size() && (std::isxdigit(static_cast<unsigned char>(p[j])) || p[j] == '?') )
      j++;
    if ( j == i )
    {
      *why = std::string("unexpected character '") + ch + "' (use hex bytes, ?? wildcards, or \"quoted text\")";
      return false;
    }
    if ( j - i > 16 )
    {
      *why = "hex token longer than 16 digits; separate bytes with spaces";
      return false;
    }
    if ( j < p.size() && p[j] != ' ' && p[j] != '\t' && p[j] != ',' )
    {
      *why = std::string("unexpected character '") + p[j] + "' after hex token";
      return false;
    }
    i = j;
    any = true;
  }
  if ( !any )
    *why = "pattern is empty";
  return any;
}

Value h_search_bytes(Call &c)
{
  const std::string pattern = p_str(c, "pattern", true, 1024);
  std::string why;
  if ( !validate_binpat(pattern, &why) )
    fail("invalid_params", "invalid byte pattern: " + why + " (examples: \"48 8B ?? 24\", \"DE AD BE EF\", "
                           "\"\\\"text\\\"\")");
  const int64_t max_results = p_int(c, "max_results", 100, 1, kMaxSearchResults);
  const ea_t start = p_ea(c, "start", false, inf_get_min_ea());
  const std::string end_s = p_str(c, "end", false, 32);
  ea_t end = inf_get_max_ea();
  if ( !end_s.empty() && !parse_hex_ea(end_s, &end) )
    fail("invalid_params", "end must be a hex address like 0x140010000");
  if ( end <= start )
    fail("invalid_params", "end must be greater than start");
  compiled_binpat_vec_t pat;
  qstring err;
  if ( !parse_binpat_str(&pat, start, pattern.c_str(), 16, PBSENC_DEF1BPU, &err) || pat.empty() )
    fail("invalid_params", "invalid byte pattern: " + to_std(err) + " (examples: \"48 8B ?? 24\", "
                           "\"DE AD BE EF\", \"\\\"text\\\"\")");
  size_t patlen = 0;
  for ( const auto &p : pat )
    patlen = std::max(patlen, p.bytes.size());
  Value items = Value::array();
  bool truncated = false;
  ea_t cur = start;
  ea_t resume = BADADDR;
  while ( cur < end )
  {
    if ( c.expired() )
    {
      truncated = true;
      resume = cur;
      break;
    }
    // Accept only matches starting inside [cur, chunk_end); the search window extends
    // patlen-1 bytes further so matches straddling the chunk boundary are not lost.
    const ea_t chunk_end = (end - cur > kSearchChunk) ? cur + kSearchChunk : end;
    const ea_t window_end = std::min<ea_t>(end, chunk_end + (patlen > 0 ? patlen - 1 : 0));
    const ea_t hit = bin_search(cur, window_end, pat, BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK
                                                       | BIN_SEARCH_NOSHOW | BIN_SEARCH_CASE);
    if ( hit == BADADDR || hit >= chunk_end )
    {
      cur = chunk_end;
      continue;
    }
    if ( static_cast<int64_t>(items.as_array().size()) >= max_results )
    {
      resume = hit;
      break;
    }
    Value o = Value::object();
    o.set("address", hexea(hit));
    o.set("function", func_ref(hit));
    qstring seg;
    get_segment_name(&seg, hit);
    o.set("segment", to_std(seg));
    items.push(std::move(o));
    cur = hit + 1;
  }
  Value o = Value::object();
  o.set("pattern", pattern);
  o.set("matches", std::move(items));
  o.set("next_start", resume == BADADDR ? Value() : Value(hexea(resume)));
  o.set("truncated_by_deadline", truncated);
  return o;
}

Value h_names(Call &c)
{
  const int64_t offset = p_int(c, "offset", 0, 0, INT64_MAX);
  const int64_t limit = p_int(c, "limit", 100, 1, kMaxPage);
  const std::string filter = lower(p_str(c, "filter", false, kMaxNameLen));
  const int64_t qty = static_cast<int64_t>(get_nlist_size());
  Value items = Value::array();
  int64_t n = offset;
  bool truncated = false;
  for ( ; n < qty && static_cast<int64_t>(items.as_array().size()) < limit; n++ )
  {
    if ( (n & 0xFF) == 0 && c.expired() )
    {
      truncated = true;
      break;
    }
    const char *nm = get_nlist_name(static_cast<size_t>(n));
    const std::string name = nm != nullptr ? nm : "";
    if ( !filter.empty() && !icontains(name, filter) )
      continue;
    const ea_t ea = get_nlist_ea(static_cast<size_t>(n));
    Value o = Value::object();
    o.set("address", hexea(ea));
    o.set("name", name);
    qstring sh;
    get_short_name(&sh, ea);
    if ( !sh.empty() && to_std(sh) != name )
      o.set("demangled", to_std(sh));
    const flags64_t f = get_flags(ea);
    const char *kind = get_func_start(ea) == ea ? "function"
                     : is_code(f) ? "code"
                     : is_strlit(f) ? "string"
                     : is_data(f) ? "data"
                     : "unknown";
    o.set("kind", kind);
    items.push(std::move(o));
  }
  return page(std::move(items), offset, n < qty ? n : -1, qty, truncated);
}

Value h_comments(Call &c)
{
  const ea_t start_in = p_ea(c, "address");
  const int64_t limit = p_int(c, "limit", 200, 1, kMaxPage);
  const std::string end_s = p_str(c, "end", false, 32);
  ea_t start = start_in;
  ea_t end;
  Value fn = Value();
  if ( !end_s.empty() )
  {
    if ( !parse_hex_ea(end_s, &end) || end <= start )
      fail("invalid_params", "end must be a hex address greater than address");
    if ( end - start > (64u << 20) )
      fail("invalid_params", "range too large (max 64 MiB); narrow it or page with a smaller end");
  }
  else if ( func_t *pfn = get_func(start) )
  {
    // Scan from `address` to the end of the containing function. The start is
    // not snapped back, so passing next_address back as `address` resumes.
    end = pfn->end_ea;
    fn = func_ref(pfn->start_ea);
  }
  else
  {
    end = std::min<ea_t>(inf_get_max_ea(), start + 4096);
  }
  Value items = Value::array();
  bool truncated = false;
  ea_t resume = BADADDR;
  ea_t ea = is_head(get_flags(start)) ? start : next_head(start, end);
  for ( ; ea != BADADDR && ea < end; ea = next_head(ea, end) )
  {
    if ( c.expired() )
    {
      truncated = true;
      resume = ea;
      break;
    }
    qstring reg, rpt, fcmt, frpt;
    const bool has_reg = get_cmt(&reg, ea, false) > 0;
    const bool has_rpt = get_cmt(&rpt, ea, true) > 0;
    const bool is_fstart = get_func_start(ea) == ea;
    const bool has_freg = is_fstart && get_func_cmt_ea(&fcmt, ea, false) > 0;
    const bool has_frpt = is_fstart && get_func_cmt_ea(&frpt, ea, true) > 0;
    if ( !(has_reg || has_rpt || has_freg || has_frpt) )
      continue;
    if ( static_cast<int64_t>(items.as_array().size()) >= limit )
    {
      resume = ea;
      break;
    }
    Value o = Value::object();
    o.set("address", hexea(ea));
    if ( has_reg ) o.set("comment", to_std(reg));
    if ( has_rpt ) o.set("repeatable_comment", to_std(rpt));
    if ( has_freg ) o.set("function_comment", to_std(fcmt));
    if ( has_frpt ) o.set("function_repeatable_comment", to_std(frpt));
    items.push(std::move(o));
  }
  Value o = Value::object();
  o.set("start", hexea(start));
  o.set("end", hexea(end));
  if ( !fn.is_null() )
    o.set("function", std::move(fn));
  o.set("comments", std::move(items));
  o.set("next_address", resume == BADADDR ? Value() : Value(hexea(resume)));
  o.set("truncated_by_deadline", truncated);
  return o;
}

// =========================================================================
// Write handlers (only reachable when writes are enabled in the plugin)
// =========================================================================
void validate_name(const std::string &name)
{
  if ( name.size() > kMaxNameLen )
    fail("invalid_params", "name too long (max 511 bytes)");
  for ( unsigned char ch : name )
    if ( ch < 0x21 || ch == 0x7F )
      fail("invalid_params", "name must not contain whitespace or control characters");
}

Value do_rename(Call &c, bool function_only)
{
  const std::string new_name = p_str(c, "new_name", true, kMaxNameLen + 1);
  validate_name(new_name);
  ea_t ea;
  if ( function_only )
  {
    func_t *pfn = p_func(c, "address");
    ea = pfn->start_ea;
    if ( new_name.empty() )
      fail("invalid_params", "new_name must not be empty for a function");
  }
  else
  {
    ea = p_ea(c, "address");
  }
  if ( !new_name.empty() )
  {
    const ea_t existing = get_name_ea(BADADDR, new_name.c_str());
    if ( existing != BADADDR && existing != ea )
      fail("name_in_use", "'" + new_name + "' is already used at " + hexea(existing));
  }
  const std::string old_name = ea_name(ea);
  const int flags = new_name.empty() ? SN_NOWARN : (SN_CHECK | SN_NOWARN | SN_NON_AUTO);
  if ( !set_name(ea, new_name.c_str(), flags) )
    fail("ida_rejected", "IDA rejected the name '" + new_name + "' at " + hexea(ea)
                         + " (invalid characters for this processor, or a reserved name)");
  msg("[idamcp] renamed %s: '%s' -> '%s'\n", hexea(ea).c_str(), old_name.c_str(), new_name.c_str());
  Value o = Value::object();
  o.set("address", hexea(ea));
  o.set("old_name", old_name);
  o.set("new_name", ea_name(ea));
  return o;
}

Value h_rename_function(Call &c) { return do_rename(c, true); }
Value h_rename_symbol(Call &c) { return do_rename(c, false); }

Value h_set_comment(Call &c)
{
  const ea_t ea = p_ea(c, "address");
  const std::string text = p_str(c, "comment", true, kMaxCommentLen);
  const bool rpt = p_bool(c, "repeatable", false);
  qstring old;
  get_cmt(&old, ea, rpt);
  if ( !set_cmt(ea, text.c_str(), rpt) )
    fail("ida_rejected", "IDA could not set the comment at " + hexea(ea));
  msg("[idamcp] %s comment at %s\n", text.empty() ? "deleted" : "set", hexea(ea).c_str());
  Value o = Value::object();
  o.set("address", hexea(ea));
  o.set("repeatable", rpt);
  o.set("old_comment", to_std(old));
  o.set("comment", text);
  return o;
}

Value h_set_function_comment(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const std::string text = p_str(c, "comment", true, kMaxCommentLen);
  const bool rpt = p_bool(c, "repeatable", false);
  qstring old;
  get_func_cmt_ea(&old, pfn->start_ea, rpt);
  if ( !set_func_cmt_ea(pfn->start_ea, text.c_str(), rpt) )
    fail("ida_rejected", "IDA could not set the function comment at " + hexea(pfn->start_ea));
  msg("[idamcp] %s function comment at %s\n", text.empty() ? "deleted" : "set", hexea(pfn->start_ea).c_str());
  Value o = Value::object();
  o.set("function", func_ref(pfn->start_ea));
  o.set("repeatable", rpt);
  o.set("old_comment", to_std(old));
  o.set("comment", text);
  return o;
}

Value h_create_function(Call &c)
{
  const ea_t ea = p_ea(c, "address");
  const std::string end_s = p_str(c, "end", false, 32);
  ea_t end = BADADDR;
  if ( !end_s.empty() && (!parse_hex_ea(end_s, &end) || end <= ea) )
    fail("invalid_params", "end must be a hex address greater than address");
  if ( const ea_t existing = get_func_start(ea); existing != BADADDR )
    fail("already_exists", hexea(ea) + " already belongs to function " + func_name(existing) + " at "
                           + hexea(existing));
  if ( !add_func(ea, end) )
    fail("ida_rejected", "IDA could not create a function at " + hexea(ea)
                         + " (the bytes may not decode as valid code, or overlap another function)");
  msg("[idamcp] created function at %s\n", hexea(ea).c_str());
  Value o = Value::object();
  o.set("function", func_ref(ea));
  const ea_t fs = get_func_start(ea);
  if ( fs != BADADDR )
  {
    o.set("size", static_cast<int64_t>(calc_func_size_ea(fs)));
  }
  return o;
}

const MethodDef kMethods[] = {
  {"status", h_status, false},
  {"get_metadata", h_metadata, false},
  {"list_segments", h_list_segments, false},
  {"list_functions", h_list_functions, false},
  {"get_function", h_get_function, false},
  {"get_disassembly", h_get_disassembly, false},
  {"get_bytes", h_get_bytes, false},
  {"get_strings", h_strings, false},
  {"get_imports", h_imports, false},
  {"get_entries", h_entries, false},
  {"get_xrefs_to", h_xrefs_to, false},
  {"get_xrefs_from", h_xrefs_from, false},
  {"get_callers", h_callers, false},
  {"get_callees", h_callees, false},
  {"get_flowchart", h_flowchart, false},
  {"search_bytes", h_search_bytes, false},
  {"get_names", h_names, false},
  {"get_comments", h_comments, false},
  {"rename_function", h_rename_function, true},
  {"rename_symbol", h_rename_symbol, true},
  {"set_comment", h_set_comment, true},
  {"set_function_comment", h_set_function_comment, true},
  {"create_function", h_create_function, true},
};

}  // namespace

const MethodDef *find_method(const std::string &name)
{
  for ( const auto &m : kMethods )
    if ( name == m.name )
      return &m;
  return nullptr;
}

mj::Value describe_methods()
{
  mj::Value a = mj::Value::array();
  for ( const auto &m : kMethods )
  {
    mj::Value o = mj::Value::object();
    o.set("name", m.name);
    o.set("write", m.write);
    a.push(std::move(o));
  }
  return a;
}

}  // namespace idamcp
