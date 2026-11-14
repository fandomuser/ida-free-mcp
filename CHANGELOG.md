# Changelog

## 1.1.0

30 new MCP tools (58 total), 6 MCP prompts and 4 MCP resources. Existing tools and
behaviour are unchanged: MCP is still turned ON/OFF per IDA window via Edit > Plugins > idamcp,
reads and writes are available together while ON, every database-specific tool accepts
`database`, and ambiguous writes are refused.

### Added
- **Types** (`types.cpp`): `ida_get_function_type`, `ida_set_function_type`, `ida_list_types`,
  `ida_get_type`, `ida_declare_type` (create or redefine structs/unions/enums/typedefs from C),
  `ida_set_data_type`.
- **Stack frames** (`frames.cpp`): `ida_get_stack_frame` (layout + members with frame/FP offsets,
  sizes, types, kinds), `ida_rename_stack_variable`. These are IDA database stack members, not
  decompiler locals.
- **Cursor and navigation** (`ui.cpp`): `ida_get_cursor`, `ida_get_selection`, `ida_jump_to`,
  `ida_list_bookmarks`, `ida_add_bookmark`, `ida_delete_bookmark`.
- **Code/data editing** (`edit.cpp`): `ida_get_item_info`, `ida_define_code`, `ida_define_data`,
  `ida_undefine` (refuses function code unless allowed), `ida_reanalyze_range`. Ranges are
  validated and capped; every change is logged in IDA's Output window.
- **Search and decoding** (`search.cpp`): `ida_decode_instruction` (operands from IDA's decoder),
  `ida_search_immediate`, `ida_search_instructions` (mnemonic/operand-type/register/immediate/target
  filters), `ida_search_disassembly`, `ida_search_pointers`. All resumable with `next_start`.
- **Function intelligence** (`analysis.cpp`): `ida_analyze_function` (brief/standard/deep),
  `ida_get_function_constants`, `ida_find_crypto_constants` (known tables and constants; results are
  candidates).
- **Comparison**: `ida_compare_databases` (name, exact-byte hash, normalized-instruction hash, then
  scored similarity), `ida_find_similar_functions`.
- **Export**: `ida_export_analysis` writes a bounded JSON export to an explicit path.
- **Prompts**: `triage_binary`, `investigate_function`, `identify_crypto`, `reconstruct_structure`,
  `compare_versions`, `explore_call_graph`.
- **Resources**: `idamcp://databases`, `idamcp://{database}/metadata`,
  `idamcp://{database}/functions`, `idamcp://{database}/function/{address}`.

### Changed
- Plugin handlers are split into one module per feature group with a shared helper library
  (`common.{hpp,cpp}`) and a method-table registry.
- Test tooling: `scripts/run_live_tests.ps1 -LargeBinary <path>` adds pagination, deadline and
  shutdown-under-load tests; `scripts/close_ida.ps1` closes a test IDA by its main window title.

### Fixed
- 32-bit immediates are reported masked to their operand size (IDA stores them sign-extended).

### Known limitations
- Hex-Rays pseudocode is still unavailable on IDA Free (the cloud decompiler's API is not exposed
  to plugins); `ida_decompile` works on IDA Home/Educational/Pro.
- `o_phrase`/`o_displ` operand decoding reports the base register and displacement; index/scale
  encodings are processor-specific and only appear in the operand text.

## 1.0.0
- Initial release: 28 tools, manual per-window ON/OFF, multi-database routing, release workflow.
