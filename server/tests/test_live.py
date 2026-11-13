"""Live integration tests: a real IDA Free 9.5 instance with the idamcp plugin must be
running with tests/fixtures/sample.exe loaded (see scripts/run_live_tests.ps1).

Run:  uv run pytest -m live   (MCP must be turned on in that IDA window)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import Client, StdioServerParameters

from idamcp_server.bridge import BridgeManager, discover
from idamcp_server.server import create_server

pytestmark = [pytest.mark.live, pytest.mark.anyio]


def _fixture_loaded() -> bool:
    try:
        return any(i.input_file.lower().endswith("sample.exe") for i in discover())
    except Exception:
        return False


if not _fixture_loaded():
    pytest.skip("no IDA instance with tests/fixtures/sample.exe loaded", allow_module_level=True)


def _select_fixture(mgr: BridgeManager) -> None:
    for inst in discover():
        if inst.input_file.lower().endswith("sample.exe"):
            mgr.select(str(inst.pid))
            return


@pytest.fixture
async def client():
    mgr = BridgeManager(default_timeout_ms=20000)
    _select_fixture(mgr)
    async with Client(create_server(mgr), raise_exceptions=True) as c:
        yield c


async def call(c: Client, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    r = await c.call_tool(name, args or {})
    assert not r.is_error, r.content[0].text if r.content else r
    return r.structured_content


async def fn_addr(c: Client, name: str) -> str:
    r = await call(c, "ida_list_functions", {"filter": name, "limit": 10})
    hits = [f for f in r["items"] if f["name"] == name]
    assert hits, f"{name} not found"
    return hits[0]["address"]


async def main_addr(c: Client) -> str:
    """IDA does not auto-name main in this static-CRT fixture: it is the sole caller of idamcp_checksum."""
    r = await call(c, "ida_get_callers", {"address": "idamcp_checksum"})
    assert len(r["callers"]) == 1
    return r["callers"][0]["function"]["address"]


async def test_status_and_metadata(client):
    st = await call(client, "ida_status")
    assert st["connected"] is True
    db = next(d for d in st["databases"] if d["database"].lower() == "sample.exe")
    assert db["connected"] and isinstance(db["capabilities"]["decompiler"], bool)
    md = await call(client, "ida_get_metadata")
    assert md["file_name"] == "sample.exe"
    assert md["bitness"] == 64
    assert md["processor"] == "metapc"
    assert "PE" in md["file_type"]
    assert len(md["sha256"]) == 64


async def test_segments(client):
    r = await call(client, "ida_list_segments")
    names = {s["name"] for s in r["items"]}
    assert ".text" in names
    text = next(s for s in r["items"] if s["name"] == ".text")
    assert "x" in text["permissions"]


async def test_function_enumeration_and_pagination(client):
    first = await call(client, "ida_list_functions", {"limit": 50})
    assert first["total"] > 50
    assert first["next_offset"] == 50
    second = await call(client, "ida_list_functions", {"offset": 50, "limit": 50})
    a = {f["address"] for f in first["items"]}
    b = {f["address"] for f in second["items"]}
    assert a.isdisjoint(b)
    names = {f["name"] for f in (await call(client, "ida_list_functions", {"filter": "idamcp_"}))["items"]}
    assert {"idamcp_add", "idamcp_checksum", "idamcp_classify"} <= names


async def test_get_function_by_name_and_address(client):
    addr = await fn_addr(client, "idamcp_classify")
    by_addr = await call(client, "ida_get_function", {"address": addr})
    by_name = await call(client, "ida_get_function", {"address": "idamcp_classify"})
    assert by_addr == by_name
    assert by_addr["name"] == "idamcp_classify"
    assert by_addr["instruction_count"] > 5


async def test_disassembly(client):
    addr = await fn_addr(client, "idamcp_add")
    r = await call(client, "ida_get_disassembly", {"address": addr})
    assert r["function"]["name"] == "idamcp_add"
    texts = [l["text"] for l in r["lines"]]
    assert any("add" in t for t in texts), texts
    assert any(t.startswith("retn") or "ret" in t for t in texts), texts
    assert r["lines"][0]["address"] == addr
    assert r["lines"][0]["label"] == "idamcp_add"
    # pagination within a function
    page1 = await call(client, "ida_get_disassembly", {"address": "idamcp_checksum", "max_lines": 3})
    assert len(page1["lines"]) == 3 and page1["next_address"]
    page2 = await call(client, "ida_get_disassembly", {"address": "idamcp_checksum", "max_lines": 3,
                                                       "start_from": page1["next_address"]})
    assert page2["lines"][0]["address"] == page1["next_address"]
    # linear mode
    lin = await call(client, "ida_get_disassembly", {"address": addr, "mode": "linear", "max_lines": 5})
    assert len(lin["lines"]) == 5


async def test_bytes(client):
    r = await call(client, "ida_search_bytes", {"pattern": "DE AD BE EF 13 37 C0 DE"})
    assert len(r["matches"]) == 1
    hit = r["matches"][0]["address"]
    b = await call(client, "ida_get_bytes", {"address": hit, "size": 8})
    assert b["hex"] == "deadbeef1337c0de"
    assert b["loaded_bytes"] == 8
    wild = await call(client, "ida_search_bytes", {"pattern": "DE AD ?? EF"})
    assert hit in {m["address"] for m in wild["matches"]}


async def test_strings(client):
    r = await call(client, "ida_search_strings", {"query": "IDAMCP_MARKER"})
    texts = {s["text"] for s in r["items"]}
    assert "IDAMCP_MARKER: secret-string-42" in texts
    assert "IDAMCP_MARKER: fixture banner v1" in texts
    exact = await call(client, "ida_search_strings", {"query": "IDAMCP_MARKER: secret-string-42", "match": "exact"})
    assert len(exact["items"]) == 1
    listing = await call(client, "ida_get_strings", {"limit": 20})
    assert listing["total"] >= 2


async def test_string_xrefs(client):
    r = await call(client, "ida_search_strings", {"query": "secret-string-42"})
    s_addr = r["items"][0]["address"]
    x = await call(client, "ida_get_xrefs_to", {"address": s_addr})
    main = await main_addr(client)
    assert any(i["from_function"] and i["from_function"]["address"] == main for i in x["items"]), x


async def test_imports_exports_entrypoints(client):
    imp = await call(client, "ida_get_imports", {"filter": "kernel32", "limit": 1000})
    names = {i["name"] for i in imp["items"]}
    assert {"GetTickCount", "OutputDebugStringA"} <= names
    exp = await call(client, "ida_get_exports")
    assert {e["name"] for e in exp["items"]} == {"idamcp_add", "idamcp_checksum", "idamcp_classify"}
    ent = await call(client, "ida_get_entrypoints")
    assert any(e["is_program_entry"] for e in ent["items"])


async def test_call_graph(client):
    checksum = await fn_addr(client, "idamcp_checksum")
    callers = await call(client, "ida_get_callers", {"address": checksum})
    assert len(callers["callers"]) == 1 and len(callers["callers"][0]["call_sites"]) == 1
    main = callers["callers"][0]["function"]["address"]
    callees = await call(client, "ida_get_callees", {"address": main})
    names = {c["name"] for c in callees["callees"]}
    assert {"idamcp_checksum", "idamcp_add", "idamcp_classify"} <= names
    assert any("GetTickCount" in n for n in names), names
    # idamcp_mix is `static`, so without a PDB IDA names it sub_XXXX: assert the edge structurally.
    sub = await call(client, "ida_get_callees", {"address": checksum})
    assert len(sub["callees"]) == 1 and sub["callees"][0]["kind"] == "call"
    mix = sub["callees"][0]["function"]["address"]
    back = await call(client, "ida_get_callers", {"address": mix})
    assert [c["function"]["address"] for c in back["callers"]] == [checksum]


async def test_xrefs_from(client):
    main = await main_addr(client)
    callees = await call(client, "ida_get_callees", {"address": main})
    site = next(c for c in callees["callees"] if c["name"] == "idamcp_add")["call_sites"][0]
    x = await call(client, "ida_get_xrefs_from", {"address": site, "kind": "code"})
    assert any(i["type"] == "call" and i["to_name"] == "idamcp_add" for i in x["items"]), x


async def test_basic_blocks_and_cfg(client):
    bb = await call(client, "ida_get_basic_blocks", {"address": "idamcp_classify"})
    assert bb["block_count"] >= 5
    assert "edges" not in bb
    assert any(b["type"] == "return" for b in bb["blocks"])
    cfg = await call(client, "ida_get_control_flow_graph", {"address": "idamcp_classify",
                                                            "include_instructions": True})
    assert len(cfg["edges"]) >= cfg["block_count"] - 1
    ids = {b["id"] for b in cfg["blocks"]}
    assert all(e["from"] in ids and e["to"] in ids for e in cfg["edges"])
    assert all(b["instructions"] for b in cfg["blocks"])


async def test_names_and_comments(client):
    n = await call(client, "ida_get_names", {"filter": "idamcp_", "limit": 100})
    kinds = {i["name"]: i["kind"] for i in n["items"]}
    assert kinds.get("idamcp_add") == "function"
    main = await main_addr(client)
    c = await call(client, "ida_get_comments", {"address": main})
    assert c["function"]["address"] == main
    assert isinstance(c["comments"], list)


async def test_errors_are_actionable(client):
    r = await client.call_tool("ida_get_function", {"address": "no_such_symbol_xyz"})
    assert r.is_error and "[not_found]" in r.content[0].text
    r = await client.call_tool("ida_get_function", {"address": "0x10"})
    assert r.is_error and "[invalid_address]" in r.content[0].text
    # Must fail fast with a validation error; IDA's own parser would open a modal question here.
    for bad in ("ZZ", "48 8B GG", '"unterminated', "48;8B"):
        r = await client.call_tool("ida_search_bytes", {"pattern": bad})
        assert r.is_error and "[invalid_params]" in r.content[0].text, (bad, r.content[0].text)
    # The quoted-string form works.
    r = await call(client, "ida_search_bytes", {"pattern": '"secret-string-42"'})
    assert len(r["matches"]) == 1


async def test_stdio_end_to_end():
    """Launch the real server over stdio, exactly as Claude Code does."""
    params = StdioServerParameters(command=sys.executable, args=["-m", "idamcp_server"],
                                   env={**os.environ, "IDAMCP_LOG_LEVEL": "WARNING"},
                                   cwd=str(Path(__file__).parent.parent))
    async with Client(params) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        assert "ida_list_functions" in tools and "ida_rename_function" in tools and len(tools) == 28
        r = await c.call_tool("ida_status", {})
        assert not r.is_error and r.structured_content["connected"] is True


async def test_live_writes(client):
    """Writes are available whenever MCP is on. Restores everything it changes."""
    add = await fn_addr(client, "idamcp_add")
    try:
        r = await call(client, "ida_rename_function", {"address": add, "new_name": "idamcp_add_renamed"})
        assert r["old_name"] == "idamcp_add" and r["new_name"] == "idamcp_add_renamed"
        assert (await call(client, "ida_get_function", {"address": add}))["name"] == "idamcp_add_renamed"
        clash = await client.call_tool("ida_rename_function", {"address": add, "new_name": "idamcp_checksum"})
        assert clash.is_error and "[name_in_use]" in clash.content[0].text
    finally:
        await call(client, "ida_rename_function", {"address": add, "new_name": "idamcp_add"})

    await call(client, "ida_set_comment", {"address": add, "comment": "adds two ints"})
    cm = await call(client, "ida_get_comments", {"address": add})
    assert any(x.get("comment") == "adds two ints" for x in cm["comments"])
    await call(client, "ida_set_comment", {"address": add, "comment": ""})

    await call(client, "ida_set_function_comment", {"address": add, "comment": "fn comment", "repeatable": True})
    assert (await call(client, "ida_get_function", {"address": add}))["repeatable_comment"] == "fn comment"
    await call(client, "ida_set_function_comment", {"address": add, "comment": "", "repeatable": True})

    exists = await client.call_tool("ida_create_function", {"address": add})
    assert exists.is_error and "[already_exists]" in exists.content[0].text

    sym = await call(client, "ida_search_strings", {"query": "secret-string-42"})
    s_addr = sym["items"][0]["address"]
    r = await call(client, "ida_rename_symbol", {"address": s_addr, "new_name": "g_secret_str"})
    assert r["new_name"] == "g_secret_str"
    await call(client, "ida_rename_symbol", {"address": s_addr, "new_name": r["old_name"] or ""})


async def test_decompile_matches_capability(client):
    """IDA Free: the cloud decompiler refuses plugin access -> clear error. Home/Pro: pseudocode."""
    st = await call(client, "ida_status")
    db = next(d for d in st["databases"] if d["database"].lower() == "sample.exe")
    r = await client.call_tool("ida_decompile", {"address": "idamcp_classify"})
    if db["capabilities"]["decompiler"]:
        assert not r.is_error, r.content[0].text
        text = "\n".join(r.structured_content["lines"])
        assert '"negative"' in text and '"large"' in text
    else:
        assert r.is_error and "[decompiler_unavailable]" in r.content[0].text
        assert "IDA Home" in r.content[0].text
