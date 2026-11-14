// Internal helpers shared by the bridge handler modules. Everything here runs on
// IDA's main thread (inside execute_sync) unless stated otherwise.
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>

#include <ida.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <range.hpp>
#include <ua.hpp>

#include "handlers.hpp"
#include "json.hpp"

namespace idamcp::detail {

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

[[noreturn]] void fail(const char *code, const std::string &msg);
std::string hexea(ea_t ea);
std::string to_std(const qstring &q);
std::string lower(std::string s);

// -------- parameter access & validation
const Value *param(const Call &c, const char *key);
std::string p_str(const Call &c, const char *key, bool required, size_t max_len,
                  const std::string &def = std::string());
int64_t p_int(const Call &c, const char *key, int64_t def, int64_t lo, int64_t hi);
bool p_bool(const Call &c, const char *key, bool def);
bool parse_hex_ea(const std::string &s, ea_t *out);
// Address parameter: "0x..." hex or a symbol name; must be mapped.
ea_t p_ea(const Call &c, const char *key, bool required = true, ea_t def = BADADDR);
func_t *p_func(const Call &c, const char *key);

// -------- formatting
std::string ea_name(ea_t ea);
std::string func_name(ea_t ea);
Value func_ref(ea_t any_ea);
Value func_flags(uint64 f);
std::string bytes_hex(ea_t ea, size_t n);
Value disasm_line(ea_t ea);
bool icontains(const std::string &hay, const std::string &needle_lower);
Value page(Value items, int64_t offset, int64_t next_offset, int64_t total, bool truncated);
const char *xref_type_name(uchar t, bool iscode);
int xref_flags_for(const std::string &kind, bool include_flow);

// -------- instruction decoding (search.cpp)
const char *optype_name(optype_t t);
std::string reg_name(int reg, size_t width);
bool decode_at(ea_t ea, insn_t *insn);           // true if ea is a decodable instruction
Value decode_json(ea_t ea, const insn_t &insn);  // structured operands + control flow

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

}  // namespace idamcp::detail

namespace idamcp {

// Method tables provided by each handler module (see handlers.cpp for the registry).
struct MethodTable
{
  const MethodDef *defs;
  size_t count;
};

MethodTable core_methods();      // handlers.cpp: original 24 methods
MethodTable types_methods();     // types.cpp: prototypes, local types, structs, enums
MethodTable frame_methods();     // frames.cpp: stack frames and variables
MethodTable ui_methods();        // ui.cpp: cursor, selection, navigation, bookmarks
MethodTable edit_methods();      // edit.cpp: code/data definition, undefine, reanalysis
MethodTable search_methods();    // search.cpp: immediate/mnemonic/text/operand/pointer search, decoding
MethodTable analysis_methods();  // analysis.cpp: function analysis, constants, crypto, fingerprints

}  // namespace idamcp
