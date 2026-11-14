// Group B: stack frames and stack variables, as stored in the IDA database.
// In IDA 9 a function frame is a UDT tinfo (get_func_frame_ea); members are
// read with get_udt_details() and renamed with tinfo_t::rename_udm(). These are
// database stack members, NOT Hex-Rays decompiler local variables.
#include <cctype>
#include <string>

#include <ida.hpp>
#include <idp.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>

#include "common.hpp"

namespace idamcp {
namespace {

using namespace detail;

constexpr int64_t kMaxFrameMembers = 2000;

struct FrameParts
{
  range_t args, retaddr, savregs, lvars;
  bool ok = false;
};

FrameParts frame_parts(ea_t func_ea)
{
  FrameParts p;
  p.ok = get_frame_part_ea(&p.args, func_ea, FPC_ARGS)
      && get_frame_part_ea(&p.retaddr, func_ea, FPC_RETADDR)
      && get_frame_part_ea(&p.savregs, func_ea, FPC_SAVREGS)
      && get_frame_part_ea(&p.lvars, func_ea, FPC_LVARS);
  return p;
}

const char *member_kind(const FrameParts &p, uint64 off, const qstring &name)
{
  if ( name == FRAME_UDM_NAME_R ) return "return_address";
  if ( name == FRAME_UDM_NAME_S ) return "saved_registers";
  if ( !p.ok ) return "unknown";
  if ( p.args.contains(off) ) return "argument";
  if ( p.lvars.contains(off) ) return "local";
  if ( p.retaddr.contains(off) ) return "return_address";
  if ( p.savregs.contains(off) ) return "saved_registers";
  return "unknown";
}

Value range_json(const range_t &r)
{
  Value o = Value::object();
  o.set("start", static_cast<int64_t>(r.start_ea));
  o.set("end", static_cast<int64_t>(r.end_ea));
  o.set("size", static_cast<int64_t>(r.end_ea - r.start_ea));
  return o;
}

tinfo_t load_frame(ea_t func_ea)
{
  tinfo_t frame;
  if ( !get_func_frame_ea(&frame, func_ea) )
    fail("no_frame", "function at " + hexea(func_ea) + " has no stack frame in the database "
                     "(leaf function without locals, or frame analysis did not run)");
  return frame;
}

Value h_get_stack_frame(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const ea_t fea = pfn->start_ea;
  const int64_t limit = p_int(c, "max_members", 500, 1, kMaxFrameMembers);
  Value o = Value::object();
  o.set("function", func_ref(fea));
  o.set("source", "ida_database_frame");  // not decompiler lvars
  o.set("frame_size", static_cast<int64_t>(get_frame_size_ea(fea)));
  o.set("locals_size", static_cast<int64_t>(pfn->frsize));
  o.set("saved_registers_size", static_cast<int64_t>(pfn->frregs));
  o.set("arguments_size", static_cast<int64_t>(pfn->argsize));
  o.set("return_address_size", static_cast<int64_t>(get_frame_retsize_ea(fea)));
  o.set("frame_pointer_delta", static_cast<int64_t>(pfn->fpd));
  const FrameParts parts = frame_parts(fea);
  if ( parts.ok )
  {
    Value layout = Value::object();
    layout.set("locals", range_json(parts.lvars));
    layout.set("saved_registers", range_json(parts.savregs));
    layout.set("return_address", range_json(parts.retaddr));
    layout.set("arguments", range_json(parts.args));
    o.set("layout", std::move(layout));
  }
  tinfo_t frame;
  if ( !get_func_frame_ea(&frame, fea) )
  {
    o.set("members", Value::array());
    o.set("note", "no frame type in the database for this function");
    return o;
  }
  udt_type_data_t udt;
  frame.get_udt_details(&udt);
  Value members = Value::array();
  bool trunc = false;
  for ( size_t i = 0; i < udt.size(); i++ )
  {
    if ( static_cast<int64_t>(members.as_array().size()) >= limit ) { trunc = true; break; }
    const udm_t &m = udt[i];
    if ( m.is_gap() )
      continue;
    const uint64 off = m.offset / 8;
    Value mv = Value::object();
    mv.set("index", static_cast<int64_t>(i));
    mv.set("name", to_std(m.name));
    mv.set("kind", member_kind(parts, off, m.name));
    mv.set("frame_offset", static_cast<int64_t>(off));
    mv.set("fp_offset", static_cast<int64_t>(soff_to_fpoff_ea(fea, off)));
    mv.set("size", static_cast<int64_t>(m.size / 8));
    qstring ts;
    m.type.print(&ts);
    mv.set("type", to_std(ts));
    if ( !m.cmt.empty() ) mv.set("comment", to_std(m.cmt));
    members.push(std::move(mv));
  }
  o.set("members", std::move(members));
  o.set("members_truncated", trunc);
  return o;
}

Value h_rename_stack_variable(Call &c)
{
  func_t *pfn = p_func(c, "address");
  const ea_t fea = pfn->start_ea;
  const std::string new_name = p_str(c, "new_name", true, kMaxNameLen);
  const std::string old_sel = p_str(c, "name", false, kMaxNameLen);
  const int64_t off_sel = p_int(c, "frame_offset", -1, -1, INT32_MAX);
  if ( old_sel.empty() == (off_sel < 0) )
    fail("invalid_params", "pass exactly one of 'name' (current member name) or 'frame_offset'");
  if ( new_name.empty() )
    fail("invalid_params", "new_name must not be empty");
  for ( unsigned char ch : new_name )
    if ( !(std::isalnum(ch) || ch == '_' || ch == '$' || ch == '@' || ch == '?') )
      fail("invalid_params", "stack variable names may contain only letters, digits, _ $ @ ?");
  tinfo_t frame = load_frame(fea);
  udm_t udm;
  int idx;
  if ( !old_sel.empty() )
  {
    udm.name = old_sel.c_str();
    idx = frame.find_udm(&udm, STRMEM_NAME);
  }
  else
  {
    udm.offset = static_cast<uint64>(off_sel) * 8;
    idx = frame.find_udm(&udm, STRMEM_OFFSET);
  }
  if ( idx < 0 )
    fail("not_found", "no stack member " + (old_sel.empty() ? "at frame offset " + std::to_string(off_sel)
                                                             : "named '" + old_sel + "'")
                      + " in " + func_name(fea) + " (see ida_get_stack_frame)");
  if ( udm.name == FRAME_UDM_NAME_R || udm.name == FRAME_UDM_NAME_S || is_special_frame_member(frame.get_udm_tid(idx)) )
    fail("invalid_params", "'" + to_std(udm.name) + "' is a reserved frame slot and cannot be renamed");
  udm_t clash;
  clash.name = new_name.c_str();
  if ( frame.find_udm(&clash, STRMEM_NAME) >= 0 && clash.name != udm.name )
    fail("name_in_use", "the frame already has a member named '" + new_name + "'");
  const std::string old_name = to_std(udm.name);
  const tinfo_code_t code = frame.rename_udm(idx, new_name.c_str());
  if ( code != TERR_OK )
    fail("ida_rejected", std::string("IDA could not rename the stack member: ") + tinfo_errstr(code));
  msg("[idamcp] renamed stack member in %s: '%s' -> '%s'\n", hexea(fea).c_str(), old_name.c_str(),
      new_name.c_str());
  Value o = Value::object();
  o.set("function", func_ref(fea));
  o.set("frame_offset", static_cast<int64_t>(udm.offset / 8));
  o.set("old_name", old_name);
  o.set("new_name", new_name);
  return o;
}

const MethodDef kFrameMethods[] = {
  {"get_stack_frame", h_get_stack_frame, false},
  {"rename_stack_variable", h_rename_stack_variable, true},
};

}  // namespace

MethodTable frame_methods() { return {kFrameMethods, qnumber(kFrameMethods)}; }

}  // namespace idamcp
