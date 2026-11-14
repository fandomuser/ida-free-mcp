// Group C: cursor, selection, navigation, bookmarks (UI APIs from kernwin.hpp / moves.hpp).
// All handlers run on IDA's main thread via execute_sync, which is where UI calls belong.
#include <string>

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <moves.hpp>
#include <segment.hpp>

#include "common.hpp"

namespace idamcp {
namespace {

using namespace detail;

constexpr size_t kMaxBookmarkDesc = 1024;

Value location(ea_t ea)
{
  Value o = Value::object();
  o.set("address", hexea(ea));
  o.set("function", func_ref(ea));
  const std::string nm = ea_name(ea);
  if ( !nm.empty() )
    o.set("name", nm);
  qstring seg;
  get_segment_name(&seg, ea);
  o.set("segment", to_std(seg));
  return o;
}

// The disassembly view that owns bookmarks: the current viewer if it is a
// disassembly view, otherwise the first "IDA View-*".
TWidget *disasm_view()
{
  TWidget *w = get_current_viewer();
  if ( w != nullptr && get_widget_type(w) == BWN_DISASM )
    return w;
  for ( char c = 'A'; c <= 'Z'; c++ )
  {
    char title[32];
    qsnprintf(title, sizeof(title), "IDA View-%c", c);
    if ( TWidget *v = find_widget(title) )
      return v;
  }
  return nullptr;
}

Value h_get_cursor(Call &)
{
  const ea_t ea = get_screen_ea();
  Value o = Value::object();
  TWidget *w = get_current_widget();
  qstring title;
  if ( w != nullptr && get_widget_title(&title, w) )
    o.set("widget", to_std(title));
  o.set("idb_path", get_path(PATH_TYPE_IDB));
  if ( ea == BADADDR || !is_mapped(ea) )
  {
    o.set("address", Value());
    o.set("note", "no address under the cursor (focus a disassembly or hex view in IDA)");
    return o;
  }
  Value loc = location(ea);
  for ( const auto &kv : loc.as_object() )
    o.set(kv.first, kv.second);
  qstring line;
  generate_disasm_line(&line, get_item_head(ea), GENDSM_REMOVE_TAGS);
  o.set("line", to_std(line));
  return o;
}

Value h_get_selection(Call &)
{
  ea_t a = BADADDR;
  ea_t b = BADADDR;
  Value o = Value::object();
  if ( !read_range_selection(nullptr, &a, &b) || a == BADADDR || b == BADADDR || b <= a )
  {
    o.set("has_selection", false);
    o.set("cursor", get_screen_ea() == BADADDR ? Value() : Value(hexea(get_screen_ea())));
    return o;
  }
  o.set("has_selection", true);
  o.set("start", hexea(a));
  o.set("end", hexea(b));
  o.set("size", static_cast<int64_t>(b - a));
  o.set("start_function", func_ref(a));
  return o;
}

Value h_jump_to(Call &c)
{
  const ea_t ea = p_ea(c, "address");
  if ( !jumpto(ea, -1, UIJMP_ACTIVATE) )
    fail("ida_rejected", "IDA could not navigate to " + hexea(ea) + " (no disassembly view open?)");
  Value o = location(ea);
  o.set("navigated", true);
  return o;
}

Value h_list_bookmarks(Call &c)
{
  const int64_t limit = p_int(c, "limit", 200, 1, MAX_MARK_SLOT);
  TWidget *w = disasm_view();
  if ( w == nullptr )
    fail("no_view", "no disassembly view is open in IDA");
  void *ud = get_viewer_user_data(w);
  idaplace_t probe(inf_get_min_ea(), 0);
  const renderer_info_t rinfo(TCCRT_FLAT, 0, 0);
  const lochist_entry_t key(&probe, rinfo);
  const uint32 total = bookmarks_t::size(key, ud);
  Value items = Value::array();
  for ( uint32 slot = 0; slot < MAX_MARK_SLOT && items.as_array().size() < total; slot++ )
  {
    if ( static_cast<int64_t>(items.as_array().size()) >= limit )
      break;
    idaplace_t pl(inf_get_min_ea(), 0);
    lochist_entry_t out(&pl, rinfo);
    qstring desc;
    uint32 idx = slot;
    if ( !bookmarks_t::get(&out, &desc, &idx, ud) || out.place() == nullptr )
      continue;
    const ea_t ea = static_cast<idaplace_t *>(out.place())->ea;
    Value b = location(ea);
    b.set("slot", static_cast<int64_t>(idx));
    b.set("description", to_std(desc));
    items.push(std::move(b));
  }
  Value o = Value::object();
  o.set("bookmarks", std::move(items));
  o.set("total", static_cast<int64_t>(total));
  return o;
}

Value h_add_bookmark(Call &c)
{
  const ea_t ea = p_ea(c, "address");
  const std::string desc = p_str(c, "description", true, kMaxBookmarkDesc);
  if ( desc.empty() )
    fail("invalid_params", "description must not be empty");
  TWidget *w = disasm_view();
  if ( w == nullptr )
    fail("no_view", "no disassembly view is open in IDA");
  void *ud = get_viewer_user_data(w);
  const renderer_info_t rinfo(TCCRT_FLAT, 0, 0);
  // First free slot (never let IDA prompt for one).
  uint32 slot = BOOKMARKS_BAD_INDEX;
  for ( uint32 s = 0; s < MAX_MARK_SLOT; s++ )
  {
    idaplace_t pl(inf_get_min_ea(), 0);
    lochist_entry_t probe(&pl, rinfo);
    qstring d;
    uint32 idx = s;
    if ( !bookmarks_t::get(&probe, &d, &idx, ud) )
    {
      slot = s;
      break;
    }
  }
  if ( slot == BOOKMARKS_BAD_INDEX )
    fail("ida_rejected", "all bookmark slots are in use");
  idaplace_t place(get_item_head(ea), 0);
  const lochist_entry_t entry(&place, rinfo);
  const uint32 used = bookmarks_t::mark(entry, slot, nullptr, desc.c_str(), ud);
  if ( used == BOOKMARKS_BAD_INDEX )
    fail("ida_rejected", "IDA could not create the bookmark");
  msg("[idamcp] bookmark %u at %s: %s\n", used, hexea(get_item_head(ea)).c_str(), desc.c_str());
  Value o = location(get_item_head(ea));
  o.set("slot", static_cast<int64_t>(used));
  o.set("description", desc);
  return o;
}

Value h_delete_bookmark(Call &c)
{
  const int64_t slot = p_int(c, "slot", -1, 0, MAX_MARK_SLOT - 1);
  if ( slot < 0 )
    fail("invalid_params", "missing required parameter 'slot' (see ida_list_bookmarks)");
  TWidget *w = disasm_view();
  if ( w == nullptr )
    fail("no_view", "no disassembly view is open in IDA");
  void *ud = get_viewer_user_data(w);
  const renderer_info_t rinfo(TCCRT_FLAT, 0, 0);
  idaplace_t pl(inf_get_min_ea(), 0);
  lochist_entry_t e(&pl, rinfo);
  qstring desc;
  uint32 idx = static_cast<uint32>(slot);
  if ( !bookmarks_t::get(&e, &desc, &idx, ud) )
    fail("not_found", "no bookmark in slot " + std::to_string(slot));
  if ( !bookmarks_t::erase(e, static_cast<uint32>(slot), ud) )
    fail("ida_rejected", "IDA could not delete bookmark " + std::to_string(slot));
  msg("[idamcp] deleted bookmark %lld\n", static_cast<long long>(slot));
  Value o = Value::object();
  o.set("slot", slot);
  o.set("deleted", true);
  o.set("description", to_std(desc));
  return o;
}

const MethodDef kUiMethods[] = {
  {"get_cursor", h_get_cursor, false},
  {"get_selection", h_get_selection, false},
  {"jump_to", h_jump_to, false},
  {"list_bookmarks", h_list_bookmarks, false},
  {"add_bookmark", h_add_bookmark, true},
  {"delete_bookmark", h_delete_bookmark, true},
};

}  // namespace

MethodTable ui_methods() { return {kUiMethods, qnumber(kUiMethods)}; }

}  // namespace idamcp
