// Group A: function prototypes, local types (structs/unions/enums/typedefs), data types.
// Uses only the public type API of IDA SDK 9.5 (typeinf.hpp, nalt.hpp).
#include <string>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>

#include "common.hpp"

namespace idamcp {
namespace {

using namespace detail;

constexpr size_t kMaxDecl = 16384;      // C declaration input
constexpr int64_t kMaxMembers = 2000;   // members returned per type

const char *cc_name(callcnv_t cc)
{
  switch ( cc & CM_CC_MASK )
  {
    case CM_CC_VOIDARG:  return "voidarg";
    case CM_CC_CDECL:    return "cdecl";
    case CM_CC_ELLIPSIS: return "cdecl_varargs";
    case CM_CC_STDCALL:  return "stdcall";
    case CM_CC_PASCAL:   return "pascal";
    case CM_CC_FASTCALL: return "fastcall";
    case CM_CC_THISCALL: return "thiscall";
    case CM_CC_SWIFT:    return "swift";
    case CM_CC_GOLANG:   return "golang";
    case CM_CC_SPECIAL:  return "usercall";
    case CM_CC_SPECIALE: return "usercall_varargs";
    case CM_CC_SPECIALP: return "usercall_purged";
    case CM_CC_UNKNOWN:  return "unknown";
    default:             return "other";
  }
}

std::string type_str(const tinfo_t &t, int flags = PRTYPE_1LINE)
{
  qstring out;
  t.print(&out, nullptr, flags);
  return to_std(out);
}

const char *kind_of(const tinfo_t &t)
{
  if ( t.is_struct() ) return "struct";
  if ( t.is_union() ) return "union";
  if ( t.is_enum() ) return "enum";
  if ( t.is_func() ) return "function";
  if ( t.is_ptr() ) return "pointer";
  if ( t.is_array() ) return "array";
  if ( t.is_typedef() ) return "typedef";
  return "other";
}

// Parses one C declaration (with or without a trailing ';').
tinfo_t parse_one(const std::string &decl, qstring *name, int extra_flags = 0)
{
  std::string d = decl;
  while ( !d.empty() && (d.back() == ' ' || d.back() == '\n' || d.back() == '\r' || d.back() == '\t') )
    d.pop_back();
  if ( d.empty() )
    fail("invalid_params", "declaration is empty");
  if ( d.back() != ';' )
    d += ';';
  tinfo_t tif;
  if ( !parse_decl(&tif, name, get_idati(), d.c_str(), PT_SIL | extra_flags) )
    fail("parse_error", "IDA could not parse the C declaration: " + d
                        + " (check syntax and that every referenced type exists; see ida_list_types)");
  return tif;
}

// Looks up a local type by name. tinfo_t::get_named_type() also "succeeds" for
// unknown names (it builds an unresolved reference), so check the ordinal first.
bool load_named(const std::string &name, tinfo_t *out)
{
  const int32 ord = get_type_ordinal(get_idati(), name.c_str());
  return ord > 0 && out->get_numbered_type(get_idati(), static_cast<uint32>(ord));
}

Value func_details(const tinfo_t &tif)
{
  Value o = Value::object();
  func_type_data_t fi;
  if ( !tif.get_func_details(&fi) )
    return o;
  o.set("return_type", type_str(fi.rettype));
  o.set("calling_convention", cc_name(fi.get_cc()));
  o.set("noreturn", fi.is_noret());
  Value args = Value::array();
  for ( size_t i = 0; i < fi.size(); i++ )
  {
    const funcarg_t &a = fi[i];
    Value av = Value::object();
    av.set("index", static_cast<int64_t>(i));
    av.set("name", to_std(a.name));
    av.set("type", type_str(a.type));
    char loc[128] = {0};
    print_argloc(loc, sizeof(loc), a.argloc, static_cast<int>(a.type.get_size()), PRALOC_STKOFF);
    av.set("location", loc);
    args.push(std::move(av));
  }
  o.set("arguments", std::move(args));
  return o;
}

Value members_of(const tinfo_t &tif, int64_t limit, bool *truncated)
{
  Value members = Value::array();
  *truncated = false;
  if ( tif.is_udt() )
  {
    udt_type_data_t udt;
    if ( tif.get_udt_details(&udt) )
    {
      for ( size_t i = 0; i < udt.size(); i++ )
      {
        if ( static_cast<int64_t>(i) >= limit ) { *truncated = true; break; }
        const udm_t &m = udt[i];
        Value mv = Value::object();
        mv.set("index", static_cast<int64_t>(i));
        mv.set("name", to_std(m.name));
        mv.set("offset", static_cast<int64_t>(m.offset / 8));
        mv.set("size", static_cast<int64_t>(m.size / 8));
        if ( m.offset % 8 != 0 || m.size % 8 != 0 )
        {
          mv.set("bit_offset", static_cast<int64_t>(m.offset));
          mv.set("bit_size", static_cast<int64_t>(m.size));
        }
        mv.set("type", type_str(m.type));
        if ( !m.cmt.empty() ) mv.set("comment", to_std(m.cmt));
        members.push(std::move(mv));
      }
    }
  }
  else if ( tif.is_enum() )
  {
    enum_type_data_t ei;
    if ( tif.get_enum_details(&ei) )
    {
      for ( size_t i = 0; i < ei.size(); i++ )
      {
        if ( static_cast<int64_t>(i) >= limit ) { *truncated = true; break; }
        Value mv = Value::object();
        mv.set("name", to_std(ei[i].name));
        mv.set("value", static_cast<int64_t>(ei[i].value));
        char hx[32];
        qsnprintf(hx, sizeof(hx), "0x%llX", static_cast<unsigned long long>(ei[i].value));
        mv.set("hex", hx);
        members.push(std::move(mv));
      }
    }
  }
  return members;
}

Value describe_named(const tinfo_t &tif, const std::string &name, int64_t limit)
{
  Value o = Value::object();
  o.set("name", name);
  o.set("kind", kind_of(tif));
  o.set("size", static_cast<int64_t>(tif.get_size()));
  o.set("ordinal", static_cast<int64_t>(tif.get_ordinal()));
  qstring decl;
  tif.print(&decl, name.c_str(), PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_DEF | PRTYPE_SEMI);
  o.set("declaration", to_std(decl));
  bool trunc = false;
  if ( tif.is_udt() || tif.is_enum() )
  {
    o.set("members", members_of(tif, limit, &trunc));
    o.set("members_truncated", trunc);
  }
  if ( tif.is_func() )
    o.set("function", func_details(tif));
  return o;
}

// ------------------------------------------------------------------- handlers
Value h_get_function_type(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const ea_t ea = pfn->start_ea;
  Value o = Value::object();
  o.set("function", func_ref(ea));
  tinfo_t tif;
  const bool has_type = get_tinfo(&tif, ea);
  bool guessed = false;
  if ( !has_type )
  {
    guessed = guess_tinfo(&tif, ea) == GUESS_FUNC_OK;
    if ( !guessed )
    {
      o.set("has_type", false);
      o.set("guessed", false);
      o.set("note", "IDA has no prototype for this function and could not guess one");
      return o;
    }
  }
  o.set("has_type", has_type);
  o.set("guessed", guessed);
  const std::string nm = func_name(ea);
  qstring decl;
  tif.print(&decl, nm.c_str(), PRTYPE_1LINE | PRTYPE_SEMI);
  o.set("declaration", to_std(decl));
  if ( tif.is_func() )
  {
    Value d = func_details(tif);
    for ( const auto &kv : d.as_object() )
      o.set(kv.first, kv.second);
  }
  return o;
}

Value h_set_function_type(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const std::string decl = p_str(c, "declaration", true, kMaxDecl);
  qstring name;
  tinfo_t tif = parse_one(decl, &name);
  if ( !tif.is_func() )
    fail("invalid_params", "declaration is not a function prototype, e.g. "
                           "\"int __fastcall check(const char *key, int len)\"");
  qstring before;
  print_type(&before, pfn->start_ea, PRTYPE_1LINE);
  if ( !apply_tinfo(pfn->start_ea, tif, TINFO_DEFINITE) )
    fail("ida_rejected", "IDA could not apply the prototype to " + hexea(pfn->start_ea));
  qstring after;
  print_type(&after, pfn->start_ea, PRTYPE_1LINE);
  msg("[idamcp] set prototype of %s: %s\n", hexea(pfn->start_ea).c_str(), after.c_str());
  Value o = Value::object();
  o.set("function", func_ref(pfn->start_ea));
  o.set("old_declaration", to_std(before));
  o.set("declaration", to_std(after));
  return o;
}

Value h_list_types(Call &c)
{
  const int64_t offset = p_int(c, "offset", 0, 0, INT32_MAX);
  const int64_t limit = p_int(c, "limit", 100, 1, kMaxPage);
  const std::string filter = lower(p_str(c, "filter", false, kMaxNameLen));
  const std::string kind = p_str(c, "kind", false, 16, "all");
  if ( kind != "all" && kind != "struct" && kind != "union" && kind != "enum" && kind != "typedef"
    && kind != "function" )
    fail("invalid_params", "kind must be one of: all, struct, union, enum, typedef, function");
  const uint32 lim = get_ordinal_limit(get_idati());
  Value items = Value::array();
  int64_t idx = 0;  // index among matching types (pagination is over matches)
  bool more = false;
  bool truncated = false;
  for ( uint32 ord = 1; lim != uint32(-1) && ord < lim; ord++ )
  {
    if ( (ord & 0xFF) == 0 && c.expired() )
    {
      truncated = true;
      break;
    }
    const char *nm = get_numbered_type_name(get_idati(), ord);
    if ( nm == nullptr || *nm == '\0' )
      continue;
    const std::string name = nm;
    if ( !filter.empty() && !icontains(name, filter) )
      continue;
    tinfo_t tif;
    if ( !tif.get_numbered_type(get_idati(), ord) )
      continue;
    const char *k = kind_of(tif);
    if ( kind != "all" && kind != k && !(kind == "typedef" && tif.is_typedef()) )
      continue;
    if ( idx++ < offset )
      continue;
    if ( static_cast<int64_t>(items.as_array().size()) >= limit )
    {
      more = true;
      break;
    }
    Value o = Value::object();
    o.set("ordinal", static_cast<int64_t>(ord));
    o.set("name", name);
    o.set("kind", k);
    o.set("size", static_cast<int64_t>(tif.get_size()));
    if ( tif.is_udt() )
      o.set("member_count", static_cast<int64_t>(tif.get_udt_nmembers()));
    items.push(std::move(o));
  }
  return page(std::move(items), offset, more ? offset + limit : -1, -1, truncated);
}

Value h_get_type(Call &c)
{
  const std::string name = p_str(c, "name", true, kMaxNameLen);
  const int64_t limit = p_int(c, "max_members", 500, 1, kMaxMembers);
  tinfo_t tif;
  if ( !load_named(name, &tif) )
    fail("not_found", "no local type named '" + name + "' (see ida_list_types)");
  return describe_named(tif, name, limit);
}

Value h_declare_type(Call &c)
{
  const std::string decl = p_str(c, "declaration", true, kMaxDecl);
  const bool replace = p_bool(c, "replace", false);
  qstring name;
  tinfo_t tif = parse_one(decl, &name, PT_TYP);
  if ( name.empty() )
    fail("invalid_params", "the declaration must name the type, e.g. \"struct packet { int len; char data[16]; }\"");
  tinfo_t existing;
  const bool exists = load_named(to_std(name), &existing);
  if ( exists && !replace )
    fail("already_exists", "a type named '" + to_std(name) + "' already exists; pass replace=true to redefine it");
  const tinfo_code_t code = tif.set_named_type(get_idati(), name.c_str(), exists ? NTF_REPLACE : 0);
  if ( code != TERR_OK )
    fail("ida_rejected", std::string("IDA could not save the type: ") + tinfo_errstr(code));
  msg("[idamcp] %s type %s\n", exists ? "replaced" : "created", name.c_str());
  tinfo_t saved;
  if ( !load_named(to_std(name), &saved) )
    fail("ida_rejected", "the type was saved but cannot be read back");
  Value o = describe_named(saved, to_std(name), 500);
  o.set("replaced", exists);
  return o;
}

Value h_set_data_type(Call &c)
{
  const ea_t ea = p_ea(c, "address");
  const std::string decl = p_str(c, "declaration", true, kMaxDecl);
  qstring name;
  tinfo_t tif = parse_one(decl, &name);
  if ( tif.is_func() )
    fail("invalid_params", "this is a function type; use ida_set_function_type for functions");
  if ( get_func_start(ea) != BADADDR && is_code(get_flags(ea)) )
    fail("invalid_params", hexea(ea) + " is code inside a function; data types apply to data addresses");
  const size_t sz = tif.get_size();
  if ( sz == BADSIZE || sz == 0 )
    fail("invalid_params", "type has no fixed size (incomplete or void)");
  for ( ea_t a = ea; a < ea + sz; a++ )
    if ( !is_mapped(a) )
      fail("invalid_address", "the type (" + std::to_string(sz) + " bytes) would extend past mapped memory at "
                              + hexea(a));
  qstring before;
  print_type(&before, ea, PRTYPE_1LINE);
  if ( !apply_tinfo(ea, tif, TINFO_DEFINITE) )
    fail("ida_rejected", "IDA could not apply the type at " + hexea(ea)
                         + " (overlapping code or items? undefine them first with ida_undefine)");
  qstring after;
  print_type(&after, ea, PRTYPE_1LINE);
  msg("[idamcp] set type at %s: %s\n", hexea(ea).c_str(), after.c_str());
  Value o = Value::object();
  o.set("address", hexea(ea));
  o.set("size", static_cast<int64_t>(sz));
  o.set("old_type", to_std(before));
  o.set("type", to_std(after));
  return o;
}

const MethodDef kTypeMethods[] = {
  {"get_function_type", h_get_function_type, false},
  {"set_function_type", h_set_function_type, true},
  {"list_types", h_list_types, false},
  {"get_type", h_get_type, false},
  {"declare_type", h_declare_type, true},
  {"set_data_type", h_set_data_type, true},
};

}  // namespace

MethodTable types_methods() { return {kTypeMethods, qnumber(kTypeMethods)}; }

}  // namespace idamcp
