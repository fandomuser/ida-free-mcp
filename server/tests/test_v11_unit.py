"""Unit tests for the v1.1 feature groups (no IDA needed)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from idamcp_server import compare as cmp
from idamcp_server.server import create_server
from idamcp_server.tools_ext import _imm

from test_server_unit import FakeBridge, FakeInstance


def fp(addr: str, name: str, *, named: bool = True, exact: str = "e", norm: str = "n", insns: int = 20,
       mn: dict[str, int] | None = None, blocks: int = 3, edges: int = 3, callees=(), strings=()) -> dict[str, Any]:
    return {"address": addr, "name": name, "named": named, "size": insns * 3, "instructions": insns,
            "blocks": blocks, "edges": edges, "exact_hash": exact, "normalized_hash": norm,
            "mnemonics": mn or {"mov": insns - 2, "ret": 1, "call": 1}, "callees": list(callees),
            "strings": list(strings)}


# ------------------------------------------------------------------ compare
def test_compare_stages_and_statuses():
    a = [
        fp("0x1000", "main", exact="A1", norm="N1"),
        fp("0x2000", "sub_2000", named=False, exact="SAME", norm="N2"),
        fp("0x3000", "sub_3000", named=False, exact="X", norm="NORM3"),
        fp("0x4000", "sub_4000", named=False, exact="old4", norm="old4n", insns=40,
           mn={"mov": 20, "xor": 10, "rol": 5, "ret": 1}, callees=["memcpy"], strings=["key"]),
        fp("0x5000", "gone", exact="G", norm="GN", insns=5, mn={"nop": 5}),
    ]
    b = [
        fp("0x1100", "main", exact="A2", norm="N1b"),                # renamed? no: same name, changed body
        fp("0x2100", "sub_2100", named=False, exact="SAME", norm="N2"),   # moved, identical bytes
        fp("0x3100", "sub_3100", named=False, exact="Y", norm="NORM3"),   # same structure, relocated
        fp("0x4100", "sub_4100", named=False, exact="new4", norm="new4n", insns=42,
           mn={"mov": 21, "xor": 10, "rol": 5, "ret": 1}, callees=["memcpy"], strings=["key"]),
        fp("0x6000", "brand_new", exact="B", norm="BN", insns=200, mn={"push": 100, "pop": 100}),
    ]
    r = cmp.compare(a, b, min_score=0.75)
    by_a = {p["a"]["address"]: p for p in r["pairs"]}
    assert by_a["0x1000"]["method"] == "name" and by_a["0x1000"]["status"] == "modified"
    assert by_a["0x2000"]["method"] == "exact_bytes" and by_a["0x2000"]["status"] == "identical"
    assert by_a["0x3000"]["method"] == "normalized" and by_a["0x3000"]["status"] == "same_structure"
    assert by_a["0x4000"]["method"] == "similarity" and 0.75 <= by_a["0x4000"]["confidence"] < 1.0
    assert "signals" in by_a["0x4000"]
    assert [f["address"] for f in r["removed"]] == ["0x5000"]
    assert [f["address"] for f in r["added"]] == ["0x6000"]


def test_ambiguous_hashes_are_not_matched_blindly():
    # Two identical stubs on each side: hash is not unique, so stage 2 must not pair them arbitrarily.
    a = [fp("0x1", "s1", named=False, exact="DUP", norm="DUPN"), fp("0x2", "s2", named=False, exact="DUP", norm="DUPN")]
    b = [fp("0x3", "s3", named=False, exact="DUP", norm="DUPN")]
    r = cmp.compare(a, b, min_score=0.99)
    assert all(p["method"] in ("similarity",) for p in r["pairs"])


def test_similarity_bounds_and_rank():
    src = fp("0x1", "f", mn={"xor": 10, "rol": 4, "mov": 6})
    near = fp("0x2", "g", mn={"xor": 9, "rol": 4, "mov": 7})
    far = fp("0x3", "h", mn={"push": 50}, insns=200, blocks=40, edges=60)
    s_near, _ = cmp.similarity(src, near)
    s_far, _ = cmp.similarity(src, far)
    assert 0.0 <= s_far < s_near <= 1.0
    ranked = cmp.rank_similar(src, [far, near], top=5, min_score=0.0)
    assert ranked[0]["function"]["address"] == "0x2"


# ------------------------------------------------------------------ argument normalisation
def test_immediate_normalisation():
    assert _imm(42) == 42
    assert _imm("0xdeadbeef") == "0xDEADBEEF"
    assert _imm("1337h") == "0x1337"
    assert _imm("100") == 100


# ------------------------------------------------------------------ tools via fake bridge
@pytest.mark.anyio
async def test_new_write_tools_respect_ambiguity_guard():
    fb = FakeBridge([FakeInstance(1, "a.exe"), FakeInstance(2, "b.exe")])
    writes = {
        "ida_set_function_type": {"address": "0x10", "declaration": "int f(int)"},
        "ida_declare_type": {"declaration": "struct s { int a; }"},
        "ida_set_data_type": {"address": "0x10", "declaration": "int"},
        "ida_rename_stack_variable": {"address": "0x10", "new_name": "x", "name": "var_8"},
        "ida_jump_to": {"address": "0x10"},
        "ida_add_bookmark": {"address": "0x10", "description": "d"},
        "ida_delete_bookmark": {"slot": 0},
        "ida_define_code": {"address": "0x10"},
        "ida_define_data": {"address": "0x10", "type": "dword"},
        "ida_undefine": {"address": "0x10", "size": 4},
        "ida_reanalyze_range": {"start": "0x10", "end": "0x20"},
    }
    async with Client(create_server(fb), raise_exceptions=True) as c:
        for name, args in writes.items():
            r = await c.call_tool(name, args)
            assert r.is_error and "pass `database`" in r.content[0].text, name
            r = await c.call_tool(name, {**args, "database": "b.exe"})
            assert not r.is_error, (name, r.content[0].text)
    assert all(retry is False for _, _, retry in fb.calls)


@pytest.mark.anyio
async def test_reads_route_and_heavy_timeouts():
    fb = FakeBridge()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        await c.call_tool("ida_analyze_function", {"address": "main", "detail": "deep"})
        await c.call_tool("ida_search_immediate", {"value": "0x67452301"})
        await c.call_tool("ida_search_instructions", {"mnemonic": "rol", "immediate": "10h"})
        r = await c.call_tool("ida_analyze_function", {"address": "main", "detail": "huge"})
        assert r.is_error  # schema rejects unknown detail levels
    assert fb.calls[0] == ("analyze_function", {"address": "main", "detail": "deep"}, True)
    assert fb.timeouts[0] == 60_000
    assert fb.calls[1][1]["value"] == "0x67452301"
    assert fb.calls[2][1] == {"mnemonic": "rol", "immediate": "0x10", "functions_only": False, "max_results": 100}


@pytest.mark.anyio
async def test_export_path_validation(tmp_path: Path):
    fb = FakeBridge()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_export_analysis", {"output_path": "relative.json"})
        assert r.is_error and "absolute" in r.content[0].text
        r = await c.call_tool("ida_export_analysis", {"output_path": str(tmp_path / "x.txt")})
        assert r.is_error and ".json" in r.content[0].text
        r = await c.call_tool("ida_export_analysis", {"output_path": str(tmp_path / "missing" / "x.json")})
        assert r.is_error and "does not exist" in r.content[0].text
        existing = tmp_path / "e.json"
        existing.write_text("{}")
        r = await c.call_tool("ida_export_analysis", {"output_path": str(existing)})
        assert r.is_error and "overwrite" in r.content[0].text
    assert fb.calls == []  # nothing reached IDA


@pytest.mark.anyio
async def test_prompts_render_with_arguments():
    async with Client(create_server(FakeBridge()), raise_exceptions=True) as c:
        names = {p.name for p in (await c.list_prompts()).prompts}
        assert names == {"triage_binary", "investigate_function", "identify_crypto", "reconstruct_structure",
                         "compare_versions", "explore_call_graph"}
        r = await c.get_prompt("investigate_function", {"address": "0x140001000", "database": "a.exe"})
        text = r.messages[0].content.text
        assert "0x140001000" in text and 'database="a.exe"' in text and "Ask before applying" in text
        r = await c.get_prompt("compare_versions", {"database_a": "old.exe", "database_b": "new.exe"})
        assert "not proof" in r.messages[0].content.text


@pytest.mark.anyio
async def test_compare_same_database_rejected():
    async with Client(create_server(FakeBridge()), raise_exceptions=True) as c:
        r = await c.call_tool("ida_compare_databases", {"database_a": "a.exe", "database_b": "a.exe"})
    assert r.is_error and "different" in r.content[0].text
