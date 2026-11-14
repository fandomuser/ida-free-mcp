"""Live comparison tests: sample.exe and sample_b.exe (identical copies) in two IDA windows."""

from __future__ import annotations

from typing import Any

import pytest
from mcp import Client

from idamcp_server.bridge import BridgeManager, discover
from idamcp_server.server import create_server

pytestmark = [pytest.mark.live, pytest.mark.anyio]


def _names() -> set[str]:
    try:
        return {i.name.lower() for i in discover()}
    except Exception:
        return set()


if not {"sample.exe", "sample_b.exe"} <= _names():
    pytest.skip("needs sample.exe and sample_b.exe open (run_live_tests.ps1 -TwoDatabases)", allow_module_level=True)


@pytest.fixture
async def c():
    async with Client(create_server(BridgeManager(default_timeout_ms=60000)), raise_exceptions=True) as client:
        yield client


async def call(c: Client, name: str, args: dict[str, Any]) -> dict[str, Any]:
    r = await c.call_tool(name, args)
    assert not r.is_error, (name, r.content[0].text)
    return r.structured_content


async def test_compare_identical_copies(c):
    r = await call(c, "ida_compare_databases", {"database_a": "sample.exe", "database_b": "sample_b.exe"})
    s = r["summary"]
    assert s["functions_a"] == s["functions_b"] > 500
    assert s["identical"] == s["functions_a"] and s["added"] == s["removed"] == s["modified"] == 0
    assert "not prove" in r["note"]


async def test_compare_falls_back_to_hash_after_rename(c):
    await call(c, "ida_rename_function", {"address": "idamcp_add", "new_name": "renamed_in_b", "database": "sample_b.exe"})
    try:
        r = await call(c, "ida_compare_databases", {"database_a": "sample.exe", "database_b": "sample_b.exe",
                                                    "include_identical": True, "max_report": 2000})
        pair = next(p for p in r["identical"] if p["a"]["name"] == "idamcp_add")
        assert pair["b"]["name"] == "renamed_in_b" and pair["method"] == "exact_bytes"
        assert r["summary"]["added"] == r["summary"]["removed"] == 0
    finally:
        await call(c, "ida_rename_function", {"address": "renamed_in_b", "new_name": "idamcp_add",
                                              "database": "sample_b.exe"})


async def test_find_similar_across_databases(c):
    r = await call(c, "ida_find_similar_functions", {"address": "idamcp_checksum", "database": "sample.exe",
                                                     "target_database": "sample_b.exe", "top": 3})
    best = r["matches"][0]
    assert best["function"]["name"] == "idamcp_checksum" and best["exact_match"] and best["score"] >= 0.95
