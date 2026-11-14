"""Feature groups H (comparison), J (export) and K (prompts/resources).

These compose existing bridge methods in the MCP server; the IDA plugin is only asked
for short, paged, read-only calls.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path
from typing import Annotated, Any, Awaitable, Callable, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__
from .compare import HEURISTIC_NOTE, compare, fetch_fingerprints, rank_similar
from .server import READ_ONLY, Address, Database, _optional_hex, normalize_address

Call = Callable[..., Awaitable[Any]]

FINGERPRINT_TIMEOUT_MS = 60_000


def _hex_to_int(s: str | None) -> int | None:
    return None if s is None else int(s, 16)


def register_workflows(mcp: MCPServer, call: Call, bridge: Any) -> None:
    # ============================================================ H. comparison
    @mcp.tool(title="Compare two databases", annotations=READ_ONLY)
    async def ida_compare_databases(
        database_a: Annotated[str, Field(min_length=1, max_length=1024, description="Older/base database (name or pid).")],
        database_b: Annotated[str, Field(min_length=1, max_length=1024, description="Newer database (name or pid).")],
        min_score: Annotated[float, Field(ge=0.5, le=1.0, description="Minimum score for heuristic matches.")] = 0.75,
        max_functions: Annotated[int, Field(ge=1, le=20000)] = 5000,
        include_identical: Annotated[bool, Field(description="List identical pairs too (else only counted).")] = False,
        max_report: Annotated[int, Field(ge=1, le=2000, description="Max entries per report list.")] = 200,
    ) -> dict[str, Any]:
        """Diffs two open databases (e.g. two versions of a binary): matched, modified, added and
        removed functions. Matching uses names, exact byte hashes, normalized instruction hashes,
        then heuristic similarity with a confidence score. Read-only."""
        if database_a == database_b:
            raise ToolError("database_a and database_b must be different databases")
        fa, trunc_a = await fetch_fingerprints(call, database_a, max_functions, FINGERPRINT_TIMEOUT_MS)
        fb, trunc_b = await fetch_fingerprints(call, database_b, max_functions, FINGERPRINT_TIMEOUT_MS)
        result = compare(fa, fb, min_score=min_score)
        pairs = result["pairs"]
        counts = {
            "functions_a": len(fa), "functions_b": len(fb),
            "identical": sum(p["status"] == "identical" for p in pairs),
            "same_structure": sum(p["status"] == "same_structure" for p in pairs),
            "modified": sum(p["status"] == "modified" for p in pairs),
            "added": len(result["added"]), "removed": len(result["removed"]),
            "matched_by": {m: sum(p["method"] == m for p in pairs)
                           for m in ("name", "exact_bytes", "normalized", "similarity")},
        }
        changed = [p for p in pairs if p["status"] != "identical"]
        changed.sort(key=lambda p: (p["status"] != "modified", p["confidence"]))
        out: dict[str, Any] = {
            "database_a": database_a, "database_b": database_b, "summary": counts,
            "changed": changed[:max_report], "added": result["added"][:max_report],
            "removed": result["removed"][:max_report],
            "truncated": {"function_limit_a": trunc_a, "function_limit_b": trunc_b,
                          "changed": len(changed) > max_report, "added": len(result["added"]) > max_report,
                          "removed": len(result["removed"]) > max_report},
            "note": HEURISTIC_NOTE,
        }
        if include_identical:
            out["identical"] = [p for p in pairs if p["status"] == "identical"][:max_report]
        return out

    @mcp.tool(title="Find similar functions", annotations=READ_ONLY)
    async def ida_find_similar_functions(
        address: Address,
        database: Database = None,
        target_database: Annotated[str | None, Field(max_length=1024, description="Where to search (default: the "
                                                                                  "same database).")] = None,
        top: Annotated[int, Field(ge=1, le=100)] = 10,
        min_score: Annotated[float, Field(ge=0.0, le=1.0)] = 0.6,
        max_functions: Annotated[int, Field(ge=1, le=20000)] = 5000,
    ) -> dict[str, Any]:
        """Ranks functions similar to the one at `address`, in the same or another open database
        (scores are heuristic; `exact_match`/`same_structure` flag hash-identical bodies)."""
        src_page = await call(database, "function_fingerprints", timeout_ms=FINGERPRINT_TIMEOUT_MS,
                              address=normalize_address(address))
        if not src_page["items"]:
            raise ToolError("could not fingerprint the source function")
        src = src_page["items"][0]
        same = target_database is None
        cands, trunc = await fetch_fingerprints(call, database if same else target_database, max_functions,
                                                FINGERPRINT_TIMEOUT_MS)
        if same:
            cands = [c for c in cands if c["address"] != src["address"]]
        return {"function": {k: src[k] for k in ("address", "name", "size", "instructions")},
                "searched_database": target_database or database or "(default)",
                "candidates_scanned": len(cands), "truncated": trunc,
                "matches": rank_similar(src, cands, top, min_score), "note": HEURISTIC_NOTE}

    # ============================================================ J. export
    @mcp.tool(title="Export analysis to JSON",
              annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False,
                                          open_world_hint=False))
    async def ida_export_analysis(
        output_path: Annotated[str, Field(min_length=1, max_length=1024,
                                          description="Absolute path of the .json file to create.")],
        include: Annotated[list[Literal["functions", "summaries", "names", "types", "comments", "xrefs", "cfg"]],
                           Field(min_length=1, max_length=7)] = ["functions", "summaries", "names", "types"],
        name_filter: Annotated[str | None, Field(max_length=256, description="Substring filter on function names.")] = None,
        start: Annotated[str | None, Field(max_length=32)] = None,
        end: Annotated[str | None, Field(max_length=32)] = None,
        segments: Annotated[list[str] | None, Field(max_length=64, description='Only these segments, e.g. [".text"].')] = None,
        max_functions: Annotated[int, Field(ge=1, le=5000)] = 500,
        overwrite: bool = False,
        database: Database = None,
    ) -> dict[str, Any]:
        """Writes a bounded JSON export of the analysis (functions, per-function summaries, names,
        local types, comments, cross-references, optional CFGs) to an explicit file path. Filter by
        function name, address range and segments. Never overwrites unless overwrite=true."""
        p = Path(output_path)
        if not p.is_absolute() or p.suffix.lower() != ".json":
            raise ToolError("output_path must be an absolute path ending in .json")
        if not p.parent.is_dir():
            raise ToolError(f"directory does not exist: {p.parent}")
        if p.exists() and not overwrite:
            raise ToolError(f"{p} already exists; pass overwrite=true to replace it")
        lo, hi = _hex_to_int(_optional_hex(start, "start")), _hex_to_int(_optional_hex(end, "end"))

        seg_ranges: list[tuple[int, int]] = []
        if segments:
            segs = (await call(database, "list_segments", limit=1000))["items"]
            wanted = set(segments)
            seg_ranges = [(int(s["start"], 16), int(s["end"], 16)) for s in segs if s["name"] in wanted]
            if not seg_ranges:
                raise ToolError(f"none of the segments {sorted(wanted)} exist")

        def in_scope(addr: str) -> bool:
            a = int(addr, 16)
            if lo is not None and a < lo:
                return False
            if hi is not None and a >= hi:
                return False
            return not seg_ranges or any(s <= a < e for s, e in seg_ranges)

        export: dict[str, Any] = {
            "format": "idamcp-export", "format_version": 1, "generated_by": f"idamcp-server {__version__}",
            "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "options": {"include": include, "name_filter": name_filter, "start": start, "end": end,
                        "segments": segments, "max_functions": max_functions},
            "metadata": await call(database, "get_metadata"),
        }
        truncated: dict[str, bool] = {}

        funcs: list[dict[str, Any]] = []
        offset = 0
        while len(funcs) < max_functions:
            page = await call(database, "list_functions", offset=offset, limit=1000, filter=name_filter)
            funcs += [f for f in page["items"] if in_scope(f["address"])]
            if page.get("next_offset") is None:
                break
            offset = page["next_offset"]
        truncated["functions"] = len(funcs) > max_functions
        funcs = funcs[:max_functions]

        if "functions" in include or "summaries" in include or "xrefs" in include or "cfg" in include \
                or "comments" in include:
            for f in funcs:
                a = f["address"]
                if "summaries" in include:
                    s = await call(database, "analyze_function", timeout_ms=60_000, address=a, detail="brief")
                    f["summary"] = {k: s.get(k) for k in ("prototype", "calling_convention", "instruction_count",
                                                          "control_flow", "callees", "callers", "imports",
                                                          "strings")}
                if "xrefs" in include:
                    x = await call(database, "get_xrefs_to", address=a, limit=200)
                    f["xrefs_to"] = x["items"]
                if "comments" in include:
                    f["comments"] = (await call(database, "get_comments", address=a, limit=500))["comments"]
                if "cfg" in include:
                    g = await call(database, "get_flowchart", address=a, max_blocks=1000)
                    f["cfg"] = {"blocks": g["blocks"], "edges": g["edges"]}
            export["functions"] = funcs

        if "names" in include:
            names: list[dict[str, Any]] = []
            offset = 0
            while len(names) < 50_000:
                page = await call(database, "get_names", offset=offset, limit=1000)
                names += [n for n in page["items"] if in_scope(n["address"])]
                if page.get("next_offset") is None:
                    break
                offset = page["next_offset"]
            truncated["names"] = len(names) >= 50_000
            export["names"] = names[:50_000]

        if "types" in include:
            types: list[dict[str, Any]] = []
            offset = 0
            while len(types) < 2000:
                page = await call(database, "list_types", offset=offset, limit=500)
                for t in page["items"]:
                    if len(types) >= 2000:
                        break
                    types.append(await call(database, "get_type", name=t["name"]))
                if page.get("next_offset") is None:
                    break
                offset = page["next_offset"]
            truncated["types"] = len(types) >= 2000
            export["types"] = types

        export["truncated"] = truncated
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(export, indent=1, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)
        return {"output_path": str(p), "bytes": p.stat().st_size,
                "counts": {k: len(export[k]) for k in ("functions", "names", "types") if k in export},
                "truncated": truncated}

    # ============================================================ K. prompts
    @mcp.prompt(title="Binary triage")
    def triage_binary(database: str = "") -> str:
        """First-pass triage of an open binary: what it is, what it does, where to look next."""
        db = f' (pass database="{database}" to every tool)' if database else ""
        return (
            f"Triage the binary open in IDA{db} using the idamcp tools.\n"
            "1. ida_status and ida_get_metadata: format, architecture, entry point, compiler, size.\n"
            "2. ida_list_segments: note unusual sections or writable+executable segments.\n"
            "3. ida_get_imports (grouped by module) and ida_get_exports: infer capabilities "
            "(network, crypto, process/registry, file I/O, anti-debug).\n"
            "4. ida_search_strings for URLs, paths, registry keys, commands and error messages.\n"
            "5. ida_find_crypto_constants for crypto/hash/checksum candidates.\n"
            "6. ida_analyze_function (detail=brief) on the entry point and the 5 most interesting functions "
            "found above.\n"
            "Report: purpose, notable capabilities with evidence addresses, suspicious indicators, and a ranked "
            "list of functions to investigate next. Mark inferences as such."
        )

    @mcp.prompt(title="Investigate a function")
    def investigate_function(address: str, database: str = "") -> str:
        """Deep-dive one function: behaviour, inputs/outputs, and suggested names/types."""
        db = f', database="{database}"' if database else ""
        return (
            f"Investigate the function at {address} in IDA.\n"
            f"1. ida_analyze_function(address=\"{address}\", detail=\"deep\"{db}).\n"
            f"2. ida_get_disassembly(address=\"{address}\"{db}) and ida_get_control_flow_graph for structure.\n"
            "3. ida_get_function_type and ida_get_stack_frame for arguments and locals.\n"
            "4. For each callee and referenced string/global that matters, follow it (ida_get_xrefs_to, "
            "ida_analyze_function brief).\n"
            "Explain what the function does step by step with addresses, its inputs/outputs and side effects. "
            "Then propose a function name, a prototype and stack-variable names. Ask before applying them "
            "(ida_rename_function, ida_set_function_type, ida_rename_stack_variable)."
        )

    @mcp.prompt(title="Identify crypto routines")
    def identify_crypto(database: str = "") -> str:
        """Find and characterise cryptographic, hashing, checksum and encoding routines."""
        db = f' (database="{database}")' if database else ""
        return (
            f"Find cryptographic and encoding routines in the binary{db}.\n"
            "1. ida_find_crypto_constants: known tables and constants, grouped per function.\n"
            "2. ida_search_instructions for rotate (rol/ror) and xor-heavy code; ida_analyze_function "
            "(detail=standard) on each candidate and read its crypto_heuristic.\n"
            "3. ida_get_function_constants and ida_decode_instruction to confirm round constants, key sizes "
            "and loop structure.\n"
            "For each candidate give: address, likely algorithm, evidence, confidence, and the callers that "
            "supply keys/data. Treat every identification as a candidate unless the evidence is conclusive."
        )

    @mcp.prompt(title="Reconstruct a data structure")
    def reconstruct_structure(address: str, database: str = "") -> str:
        """Infer a struct layout from how code accesses memory, then declare and apply it."""
        db = f', database="{database}"' if database else ""
        return (
            f"Reconstruct the data structure used at {address}.\n"
            f"1. ida_get_xrefs_to(address=\"{address}\"{db}) and the functions that use it.\n"
            "2. In those functions, ida_search_instructions with register/operand filters and "
            "ida_decode_instruction to collect displacement offsets and access sizes.\n"
            "3. Build a C struct (offset, size, inferred type, purpose per field; use padding for unknowns).\n"
            "4. Show the declaration and ask before applying: ida_declare_type, then ida_set_data_type or "
            "ida_set_function_type for functions taking a pointer to it."
        )

    @mcp.prompt(title="Compare two versions")
    def compare_versions(database_a: str, database_b: str) -> str:
        """Patch/version diff of two binaries open in two IDA windows."""
        return (
            f"Compare {database_a} (old) with {database_b} (new).\n"
            f"1. ida_compare_databases(database_a=\"{database_a}\", database_b=\"{database_b}\").\n"
            "2. For each modified function (lowest confidence first), ida_get_disassembly on both sides and "
            "explain the change; check whether it is security relevant (bounds checks, length handling, "
            "authentication, crypto).\n"
            "3. Summarise added/removed functionality.\n"
            "State that heuristic matches are not proof of equivalence."
        )

    @mcp.prompt(title="Explore the call graph")
    def explore_call_graph(address: str, depth: str = "2", database: str = "") -> str:
        """Map callers and callees around a function to a given depth."""
        db = f', database="{database}"' if database else ""
        return (
            f"Map the call graph around {address} to depth {depth}.\n"
            f"Use ida_get_callees and ida_get_callers(address=..., {db.lstrip(', ')}) breadth-first, and "
            "ida_analyze_function (detail=brief) for each node. Present it as an indented tree with addresses, "
            "names, imports reached and a one-line role per function. Stop expanding library/thunk functions."
        )

    # ============================================================ K. resources
    @mcp.resource("idamcp://databases", mime_type="application/json")
    async def databases_resource() -> str:
        """Databases with MCP turned on (name, pid, paths)."""
        return json.dumps([i.describe() for i in bridge.instances()], indent=1)

    @mcp.resource("idamcp://{database}/metadata", mime_type="application/json")
    async def metadata_resource(database: str) -> str:
        """Metadata of one database (file, hashes, architecture, counts)."""
        return json.dumps(await call(database, "get_metadata"), indent=1)

    @mcp.resource("idamcp://{database}/functions", mime_type="application/json")
    async def functions_resource(database: str) -> str:
        """First 1000 functions of one database (address, name, size)."""
        return json.dumps(await call(database, "list_functions", limit=1000), indent=1)

    @mcp.resource("idamcp://{database}/function/{address}", mime_type="application/json")
    async def function_resource(database: str, address: str) -> str:
        """Brief analysis of one function (address in hex)."""
        return json.dumps(await call(database, "analyze_function", timeout_ms=60_000,
                                     address=normalize_address(address), detail="brief"), indent=1)
