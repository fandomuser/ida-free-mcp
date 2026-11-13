"""Live multi-database tests: two IDA Free windows, sample.exe and sample_b.exe (a copy).

Run via:  scripts/run_live_tests.ps1 -TwoDatabases
"""

from __future__ import annotations

import os
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
    pytest.skip("needs sample.exe and sample_b.exe open in two IDA windows", allow_module_level=True)


@pytest.fixture
async def client():
    async with Client(create_server(BridgeManager(default_timeout_ms=20000)), raise_exceptions=True) as c:
        yield c


async def call(c: Client, name: str, args: dict[str, Any]) -> dict[str, Any]:
    r = await c.call_tool(name, args)
    assert not r.is_error, r.content[0].text
    return r.structured_content


async def test_status_lists_both():
    async with Client(create_server(BridgeManager()), raise_exceptions=True) as c:
        st = await call(c, "ida_status", {})
    dbs = {d["database"].lower(): d for d in st["databases"]}
    assert {"sample.exe", "sample_b.exe"} <= set(dbs)
    assert all(dbs[n]["connected"] for n in ("sample.exe", "sample_b.exe"))
    assert sum(1 for d in st["databases"] if d["default"]) == 1


async def test_reads_target_each_database(client):
    a = await call(client, "ida_get_metadata", {"database": "sample.exe"})
    b = await call(client, "ida_get_metadata", {"database": "sample_b.exe"})
    assert a["file_name"] == "sample.exe" and b["file_name"] == "sample_b.exe"
    assert a["idb_path"] != b["idb_path"]
    assert a["sha256"] == b["sha256"]  # same bytes, separate databases
    # By pid, and interleaved calls on both connections.
    pid_b = next(i.pid for i in discover() if i.name.lower() == "sample_b.exe")
    fa = await call(client, "ida_list_functions", {"database": "sample.exe", "filter": "idamcp_"})
    fb = await call(client, "ida_list_functions", {"database": str(pid_b), "filter": "idamcp_"})
    assert [f["name"] for f in fa["items"]] == [f["name"] for f in fb["items"]]


async def test_unknown_database_is_actionable(client):
    r = await client.call_tool("ida_list_functions", {"database": "nope.exe"})
    assert r.is_error
    assert "sample.exe" in r.content[0].text and "sample_b.exe" in r.content[0].text


async def test_writes_are_isolated(client):
    # Without `database`, a write is refused while two databases are open.
    r = await client.call_tool("ida_set_comment", {"address": "idamcp_add", "comment": "x"})
    assert r.is_error and "pass `database`" in r.content[0].text

    try:
        await call(client, "ida_rename_function", {"address": "idamcp_add", "new_name": "only_in_b",
                                                   "database": "sample_b.exe"})
        b = await call(client, "ida_list_functions", {"database": "sample_b.exe", "filter": "only_in_b"})
        a = await call(client, "ida_list_functions", {"database": "sample.exe", "filter": "only_in_b"})
        assert [f["name"] for f in b["items"]] == ["only_in_b"]
        assert a["items"] == []
        still = await call(client, "ida_get_function", {"address": "idamcp_add", "database": "sample.exe"})
        assert still["name"] == "idamcp_add"
    finally:
        await call(client, "ida_rename_function", {"address": "only_in_b", "new_name": "idamcp_add",
                                                   "database": "sample_b.exe"})
