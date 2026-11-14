// Shared helpers for all bridge handler modules (main-thread only).
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

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
#include <hexrays.hpp>  // decompiler API; IDA Free provides it through the cloud decompiler

#include "common.hpp"

namespace idamcp::detail {

using mj::Value;



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
                  const std::string &def)
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
ea_t p_ea(const Call &c, const char *key, bool required, ea_t def)
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

}  // namespace idamcp::detail
