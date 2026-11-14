# Expansion work log (v1.1)

Goal: add feature groups A–K (types, frames, UI/navigation, code/data editing, advanced search,
instruction decoding, function analysis, multi-database comparison, crypto/constants, export,
MCP prompts/resources) while preserving the v1.0 behaviour (manual ON/OFF, unified read/write,
multi-database `database` routing, ambiguous-write refusal, localhost + token, no code execution).

## Architecture decisions
- `plugin/src/common.{hpp,cpp}`: shared main-thread helpers (param validation, address parsing,
  formatting) extracted from handlers.cpp (namespace `idamcp::detail`).
- One file per feature group, each exporting a `MethodTable <group>_methods()`; handlers.cpp
  keeps the registry (`find_method` / `describe_methods` iterate all tables).
  - types.cpp (A), frames.cpp (B), ui.cpp (C), edit.cpp (D), search.cpp (E+F),
    analysis.cpp (G+I + per-function fingerprints for H).
- H (compare), J (export), K (prompts/resources) live in the Python server: they are composed from
  bridge calls so IDA's UI thread is never held for a whole-database job.
- Every write handler logs to IDA's Output window (`[idamcp] ...`) and the bridge log.

## Status
- [x] Refactor + registry (builds, 172 C++ checks pass)
- [x] A types.cpp: get/set_function_type, list_types, get_type, declare_type, set_data_type (compiles)
- [x] B frames.cpp: get_stack_frame, rename_stack_variable (compiles)
- [x] C ui.cpp, D edit.cpp, E/F search.cpp, G/I analysis.cpp (live-tested)
- [x] Python tools for all groups (tools_ext.py) + H/J/K (compare.py, workflows.py): 58 tools, 6 prompts, 4 resources
- [x] Unit tests (37) + live tests: test_live_v11.py, test_live_v11_multi.py, test_live_large.py
- [x] README, CHANGELOG, version 1.1.0
- [x] Committed locally; push + tag v1.1.0 awaiting approval

## Lessons
- tinfo_t::get_named_type() succeeds for unknown names; check get_type_ordinal() > 0 first.
- op_t::value holds 32-bit immediates sign-extended; mask with get_dtype_size (imm_value()).
- IDA asks "Load PDB file" for binaries with debug info; tests answer No (no symbol-server access).
- Process.MainWindowHandle may point at a leftover popup; close IDA via the "IDA - *" window.

## Verified API notes (IDA SDK 9.5 headers)
- Frames are tinfo UDTs: get_func_frame_ea, get_frame_part_ea(FPC_*), soff_to_fpoff_ea, rename_udm.
- Bookmarks: bookmarks_t::{mark,get,get_desc,size,erase} with lochist_entry_t(idaplace_t, renderer_info_t)
  and the disassembly view's get_viewer_user_data().
- IDA Free: decompiler API unavailable (see README "Decompiler").
