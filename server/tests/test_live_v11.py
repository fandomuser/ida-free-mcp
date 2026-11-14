"""Live tests for the v1.1 feature groups against tests/fixtures/sample.exe in IDA Free 9.5.
The database is a disposable copy (scripts/run_live_tests.ps1); every change is reverted
where practical and the database is closed without saving."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from idamcp_server.bridge import BridgeManager, discover
from idamcp_server.server import create_server

pytestmark = [pytest.mark.live, pytest.mark.anyio]


def _fixture_pid() -> int | None:
    try:
        return next((i.pid for i in discover() if i.name.lower() == "sample.exe"), None)
    except Exception:
        return None


PID = _fixture_pid()
if PID is None:
    pytest.skip("needs tests/fixtures/sample.exe open in IDA with MCP on", allow_module_level=True)
DB = str(PID)


@pytest.fixture
async def c():
    mgr = BridgeManager(default_timeout_ms=30000)
    async with Client(create_server(mgr), raise_exceptions=True) as client:
        yield client


async def call(c: Client, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    r = await c.call_tool(name, {**(args or {}), "database": DB})
    assert not r.is_error, (name, r.content[0].text)
    return r.structured_content


async def err(c: Client, name: str, args: dict[str, Any]) -> str:
    r = await c.call_tool(name, {**args, "database": DB})
    assert r.is_error, (name, r.structured_content)
    return r.content[0].text


async def main_addr(c: Client) -> str:
    r = await call(c, "ida_get_callers", {"address": "idamcp_checksum"})
    return r["callers"][0]["function"]["address"]


# ------------------------------------------------------------------ A. types
async def test_types_roundtrip(c):
    await call(c, "ida_set_function_type", {"address": "idamcp_add", "declaration": "int __fastcall idamcp_add(int a, int b)"})
    ft = await call(c, "ida_get_function_type", {"address": "idamcp_add"})
    assert ft["has_type"] and ft["calling_convention"] == "fastcall"
    assert [a["name"] for a in ft["arguments"]] == ["a", "b"] and ft["arguments"][0]["location"] == "ecx"
    assert "not a function prototype" in await err(c, "ida_set_function_type", {"address": "idamcp_add", "declaration": "int x"})

    r = await call(c, "ida_declare_type", {"declaration": "struct live_pkt { int len; unsigned char data[12]; void *next; }"})
    assert r["kind"] == "struct" and r["size"] == 24
    assert [(m["name"], m["offset"], m["size"]) for m in r["members"]] == [("len", 0, 4), ("data", 4, 12), ("next", 16, 8)]
    assert "already_exists" in await err(c, "ida_declare_type", {"declaration": "struct live_pkt { int a; }"})
    r = await call(c, "ida_declare_type", {"declaration": "struct live_pkt { int len; short flags; }", "replace": True})
    assert r["replaced"] and [m["name"] for m in r["members"]] == ["len", "flags"]
    await call(c, "ida_declare_type", {"declaration": "enum live_color { RED = 1, BLUE = 0x10 }"})
    e = await call(c, "ida_get_type", {"name": "live_color"})
    assert e["kind"] == "enum" and {m["name"]: m["value"] for m in e["members"]} == {"RED": 1, "BLUE": 16}
    lst = await call(c, "ida_list_types", {"filter": "live_"})
    assert {t["name"] for t in lst["items"]} == {"live_pkt", "live_color"}
    assert "not_found" in await err(c, "ida_get_type", {"name": "no_such_type_xyz"})
    assert "parse_error" in await err(c, "ida_declare_type", {"declaration": "struct { garbage"})


async def test_set_data_type(c):
    hit = (await call(c, "ida_search_bytes", {"pattern": "DE AD BE EF 13 37 C0 DE"}))["matches"][0]["address"]
    r = await call(c, "ida_set_data_type", {"address": hit, "declaration": "unsigned char magic[8]"})
    assert r["size"] == 8 and "[8]" in r["type"]
    info = await call(c, "ida_get_item_info", {"address": hit})
    assert info["class"] == "data" and info["element_count"] == 8
    await call(c, "ida_undefine", {"address": hit, "size": 8})


# ------------------------------------------------------------------ B. frames
async def test_stack_frame_and_rename(c):
    m = await main_addr(c)
    fr = await call(c, "ida_get_stack_frame", {"address": m})
    assert fr["source"] == "ida_database_frame" and fr["frame_size"] > 0
    kinds = {x["kind"] for x in fr["members"]}
    assert "local" in kinds
    assert fr["layout"]["return_address"]["size"] == 8
    loc = next(x for x in fr["members"] if x["kind"] == "local")
    r = await call(c, "ida_rename_stack_variable", {"address": m, "name": loc["name"], "new_name": "live_local"})
    assert r["old_name"] == loc["name"]
    again = await call(c, "ida_get_stack_frame", {"address": m})
    assert any(x["name"] == "live_local" for x in again["members"])
    await call(c, "ida_rename_stack_variable", {"address": m, "frame_offset": loc["frame_offset"], "new_name": loc["name"]})
    assert "reserved" in await err(c, "ida_rename_stack_variable",
                                   {"address": m, "name": "__return_address", "new_name": "x"})


# ------------------------------------------------------------------ C. cursor / navigation
async def test_navigation_cursor_bookmarks(c):
    j = await call(c, "ida_jump_to", {"address": "idamcp_classify"})
    assert j["navigated"]
    cur = await call(c, "ida_get_cursor")
    assert cur["function"]["name"] == "idamcp_classify" and cur["address"] == j["address"]
    sel = await call(c, "ida_get_selection")
    assert sel["has_selection"] is False and sel["cursor"] == j["address"]
    b = await call(c, "ida_add_bookmark", {"address": "idamcp_classify", "description": "live bookmark"})
    lst = await call(c, "ida_list_bookmarks")
    assert any(x["slot"] == b["slot"] and x["description"] == "live bookmark" for x in lst["bookmarks"])
    await call(c, "ida_delete_bookmark", {"slot": b["slot"]})
    lst = await call(c, "ida_list_bookmarks")
    assert all(x["slot"] != b["slot"] for x in lst["bookmarks"])


# ------------------------------------------------------------------ D. code / data
async def test_code_and_data_editing(c):
    hit = (await call(c, "ida_search_bytes", {"pattern": "DE AD BE EF 13 37 C0 DE"}))["matches"][0]["address"]
    await call(c, "ida_undefine", {"address": hit, "size": 8})
    d = await call(c, "ida_define_data", {"address": hit, "type": "dword", "count": 2})
    assert d["item"]["data_type"] == "dword" and d["item"]["element_count"] == 2
    await call(c, "ida_undefine", {"address": hit, "size": 8})
    assert (await call(c, "ida_get_item_info", {"address": hit}))["class"] == "unknown"
    msg = await err(c, "ida_undefine", {"address": "idamcp_add", "size": 4})
    assert "allow_function_code" in msg
    r = await call(c, "ida_define_code", {"address": "idamcp_add"})
    assert r["already_code"] is True
    s = (await call(c, "ida_search_strings", {"query": "fixture banner"}))["items"][0]["address"]
    info = await call(c, "ida_get_item_info", {"address": s})
    assert info["data_type"] == "string"
    r = await call(c, "ida_reanalyze_range", {"start": "0x140001000", "end": "0x140001200"})
    assert r["scheduled"]
    assert "not fully mapped" in await err(c, "ida_define_data", {"address": "0x140025FFE", "type": "qword", "count": 4})


# ------------------------------------------------------------------ E/F. search & decode
async def test_decode_instruction_structured(c):
    d = await call(c, "ida_decode_instruction", {"address": "idamcp_classify", "count": 4})
    first = d["instructions"][0]
    assert first["mnemonic"] == "mov" and first["operands"][1] == {
        "index": 1, "type": "register", "size": 4, "text": "ecx", "register": "ecx"}
    assert first["operands"][0]["type"] == "displacement" and first["operands"][0]["base_register"] == "rsp"
    assert any(i["control_flow"] == "conditional_jump" for i in d["instructions"])
    m = await main_addr(c)
    callees = await call(c, "ida_get_callees", {"address": m})
    site = next(x for x in callees["callees"] if x["name"] == "idamcp_add")["call_sites"][0]
    call_insn = await call(c, "ida_decode_instruction", {"address": site})
    assert call_insn["control_flow"] == "call"
    assert call_insn["operands"][0]["type"] == "near_code" and call_insn["operands"][0]["target_name"] == "idamcp_add"


async def test_searches(c):
    r = await call(c, "ida_search_immediate", {"value": "0x811C9DC5"})
    assert [x["function"]["name"] for x in r["matches"]] == ["idamcp_checksum"]
    r = await call(c, "ida_search_instructions", {"mnemonic": "imul", "immediate": "0x1000193"})
    assert len(r["matches"]) == 1
    r = await call(c, "ida_search_instructions", {"register": "rsp", "operand_type": "displacement",
                                                   "functions_only": True, "max_results": 5})
    assert len(r["matches"]) == 5 and r["next_start"]
    r2 = await call(c, "ida_search_instructions", {"register": "rsp", "operand_type": "displacement",
                                                    "functions_only": True, "max_results": 5,
                                                    "start": r["next_start"]})
    assert r2["matches"][0]["address"] == r["next_start"]
    r = await call(c, "ida_search_disassembly", {"text": "811C9DC5"})
    assert len(r["matches"]) == 1
    r = await call(c, "ida_search_pointers", {"target": "idamcp_add"})
    assert r["recognized_references"], r
    assert "at least one filter" in await err(c, "ida_search_instructions", {})


# ------------------------------------------------------------------ G/I. analysis + crypto
async def test_analyze_function_levels(c):
    brief = await call(c, "ida_analyze_function", {"address": "idamcp_checksum", "detail": "brief"})
    assert brief["control_flow"]["loops_back_edges"] >= 1 and "constants" not in brief
    std = await call(c, "ida_analyze_function", {"address": "idamcp_checksum", "detail": "standard"})
    assert any(k.get("known", "").startswith("FNV-1a 32") for k in std["constants"])
    assert std["crypto_heuristic"]["is_candidate"] and "FNV-1a 32" in std["crypto_heuristic"]["algorithm_candidates"]
    m = await main_addr(c)
    deep = await call(c, "ida_analyze_function", {"address": m, "detail": "deep"})
    assert {x["name"] for x in deep["callees"]} >= {"idamcp_checksum", "idamcp_add", "idamcp_classify"}
    assert any(x["is_import"] for x in deep["callees"])
    assert any("IDAMCP_MARKER" in s.get("text", "") for s in deep["strings"])
    assert deep["control_flow"]["blocks"] and deep["mnemonic_histogram"]


async def test_constants_and_crypto(c):
    k = await call(c, "ida_get_function_constants", {"address": "idamcp_checksum"})
    assert k["constants"][0]["value"] == "0x811C9DC5" and k["constants"][0]["known_algorithm_candidate"] == "FNV-1a 32"
    cr = await call(c, "ida_find_crypto_constants")
    algos = {x["algorithm_candidate"] for x in cr["immediate_matches"]}
    assert "FNV-1a 32" in algos and "FNV-1/FNV-1a 32" in algos
    assert "candidates only" in cr["note"]


# ------------------------------------------------------------------ H. similarity (single database)
async def test_find_similar_functions(c):
    r = await call(c, "ida_find_similar_functions", {"address": "idamcp_add", "top": 5, "min_score": 0.0})
    assert r["function"]["name"] == "idamcp_add" and len(r["matches"]) == 5
    assert all(m["function"]["address"] != r["function"]["address"] for m in r["matches"])
    assert r["matches"][0]["score"] >= r["matches"][-1]["score"]
    assert "does not prove" in r["note"]


# ------------------------------------------------------------------ J. export
async def test_export(c, tmp_path: Path):
    out = tmp_path / "export.json"
    r = await call(c, "ida_export_analysis", {
        "output_path": str(out), "include": ["functions", "summaries", "names", "types", "comments", "xrefs", "cfg"],
        "name_filter": "idamcp_", "max_functions": 10})
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["format"] == "idamcp-export" and data["metadata"]["file_name"] == "sample.exe"
    names = {f["name"] for f in data["functions"]}
    assert {"idamcp_add", "idamcp_checksum", "idamcp_classify"} <= names
    f = next(f for f in data["functions"] if f["name"] == "idamcp_checksum")
    assert f["summary"]["control_flow"] and f["cfg"]["blocks"] and "xrefs_to" in f
    assert data["types"] and data["names"]
    assert r["bytes"] == out.stat().st_size
    assert "overwrite" in await err(c, "ida_export_analysis", {"output_path": str(out)})
    seg = tmp_path / "seg.json"
    await call(c, "ida_export_analysis", {"output_path": str(seg), "include": ["functions"], "segments": [".text"],
                                          "max_functions": 3})
    assert len(json.loads(seg.read_text(encoding="utf-8"))["functions"]) == 3


# ------------------------------------------------------------------ K. resources
async def test_resources(c):
    dbs = json.loads((await c.read_resource("idamcp://databases")).contents[0].text)
    assert any(d["pid"] == PID for d in dbs)
    md = json.loads((await c.read_resource(f"idamcp://{DB}/metadata")).contents[0].text)
    assert md["file_name"] == "sample.exe"
    fn = json.loads((await c.read_resource(f"idamcp://{DB}/function/0x140001050")).contents[0].text)
    assert fn["name"] == "idamcp_checksum"
