"""Unit tests for the MCP tool layer using an in-memory client and a fake bridge."""

from __future__ import annotations

from typing import Any

import pytest
from mcp import Client

from idamcp_server.bridge import BridgeError, BridgeUnavailable
from idamcp_server.server import create_server, normalize_address

READ_TOOLS = {
    "ida_status", "ida_select_instance", "ida_get_metadata", "ida_list_segments", "ida_list_functions",
    "ida_get_function", "ida_get_disassembly", "ida_get_bytes", "ida_get_strings", "ida_search_strings",
    "ida_get_imports", "ida_get_exports", "ida_get_entrypoints", "ida_get_xrefs_to", "ida_get_xrefs_from",
    "ida_get_callers", "ida_get_callees", "ida_get_basic_blocks", "ida_get_control_flow_graph",
    "ida_search_bytes", "ida_get_names", "ida_get_comments", "ida_decompile",
}
WRITE_TOOLS = {
    "ida_rename_function", "ida_rename_symbol", "ida_set_comment", "ida_set_function_comment",
    "ida_create_function",
}


class FakeInstance:
    def __init__(self, pid: int, name: str = "sample.exe") -> None:
        self.pid = pid
        self.name = name

    def describe(self) -> dict[str, Any]:
        return {"database": self.name, "pid": self.pid}


class FakeBridge:
    def __init__(self, instances: list[FakeInstance] | None = None) -> None:
        self.insts = instances or [FakeInstance(1234)]
        self.databases: list[str | None] = []
        self.timeouts: list[int | None] = []
        self.calls: list[tuple[str, dict[str, Any], bool]] = []
        self.selected_pid: int | None = None
        self.raise_exc: Exception | None = None
        self.result: Any = {"ok": True}
        self.closed = False

    async def call(self, method: str, params: dict[str, Any] | None = None, *, retry: bool = True,
                   timeout_ms: int | None = None, database: str | None = None) -> Any:
        params = {k: v for k, v in (params or {}).items() if v is not None}
        self.calls.append((method, params, retry))
        self.databases.append(database)
        self.timeouts.append(timeout_ms)
        if self.raise_exc:
            raise self.raise_exc
        return dict(self.result) if isinstance(self.result, dict) else self.result

    def instances(self) -> list[Any]:
        return list(self.insts)

    def select(self, database: str) -> Any:
        for i in self.insts:
            if database in (str(i.pid), i.name):
                self.selected_pid = i.pid
                return i
        raise BridgeUnavailable(f"no open IDA database matches '{database}'")

    async def hello(self, database: str | None = None) -> dict[str, Any]:
        return {"pid": 1234, "capabilities": {"decompiler": False, "database_writes": True}}

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.anyio
async def test_all_28_tools_registered():
    async with Client(create_server(FakeBridge()), raise_exceptions=True) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert names == READ_TOOLS | WRITE_TOOLS
    assert len(names) == 28


@pytest.mark.anyio
async def test_annotations():
    async with Client(create_server(FakeBridge()), raise_exceptions=True) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
    for name in WRITE_TOOLS:
        assert tools[name].annotations.read_only_hint is False, name


@pytest.mark.anyio
async def test_address_normalised_and_routed():
    fb = FakeBridge()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_get_function", {"address": "0x1400010c0"})
        assert not r.is_error
        r = await c.call_tool("ida_get_xrefs_to", {"address": "140001050h", "kind": "code"})
        assert not r.is_error
        r = await c.call_tool("ida_get_function", {"address": "main"})
        assert not r.is_error
    assert fb.calls[0] == ("get_function", {"address": "0x1400010C0"}, True)
    assert fb.calls[1][1]["address"] == "0x140001050"
    assert fb.calls[1][1]["kind"] == "code"
    assert fb.calls[2][1]["address"] == "main"


@pytest.mark.anyio
async def test_ambiguous_decimal_address_rejected():
    fb = FakeBridge()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_get_function", {"address": "4096"})
    assert r.is_error
    assert "0x1000" in r.content[0].text
    assert fb.calls == []


@pytest.mark.anyio
async def test_schema_validation_rejects_bad_limit():
    fb = FakeBridge()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_list_functions", {"limit": 5000})
    assert r.is_error
    assert fb.calls == []


@pytest.mark.anyio
async def test_bridge_error_becomes_tool_error():
    fb = FakeBridge()
    fb.raise_exc = BridgeError("not_a_function", "0x10 is not inside a function")
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_get_function", {"address": "0x10"})
    assert r.is_error
    assert "[not_a_function]" in r.content[0].text


@pytest.mark.anyio
async def test_unavailable_becomes_tool_error():
    fb = FakeBridge()
    fb.raise_exc = BridgeUnavailable("No IDA instance with the idamcp plugin is running.")
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_get_metadata", {})
    assert r.is_error
    assert "No IDA instance" in r.content[0].text


@pytest.mark.anyio
async def test_write_calls_never_retry():
    fb = FakeBridge()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_rename_function", {"address": "0x140001030", "new_name": "add_ints"})
        assert not r.is_error
        r = await c.call_tool("ida_set_comment", {"address": "0x140001030", "comment": "hi"})
        assert not r.is_error
    assert fb.calls[0] == ("rename_function", {"address": "0x140001030", "new_name": "add_ints"}, False)
    assert fb.calls[1][2] is False


@pytest.mark.anyio
async def test_basic_blocks_strips_edges_and_structured_output():
    fb = FakeBridge()
    fb.result = {"blocks": [{"id": 0}], "edges": [{"from": 0, "to": 1}], "block_count": 1}
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_get_basic_blocks", {"address": "0x140001000"})
    assert not r.is_error
    assert r.structured_content is not None
    assert "edges" not in r.structured_content
    assert r.structured_content["block_count"] == 1


@pytest.mark.anyio
async def test_search_bytes_rejects_name_as_range():
    fb = FakeBridge()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_search_bytes", {"pattern": "DE AD", "start": "main"})
    assert r.is_error
    assert fb.calls == []


@pytest.mark.anyio
async def test_status_and_select():
    fb = FakeBridge()
    fb.result = {"function_count": 3}
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_status", {})
        assert not r.is_error
        assert r.structured_content["connected"] is True
        db = r.structured_content["databases"][0]
        assert db["database"] == "sample.exe" and db["default"] is True
        assert db["capabilities"]["decompiler"] is False
        r = await c.call_tool("ida_select_instance", {"database": "999"})
        assert r.is_error
        r = await c.call_tool("ida_select_instance", {"database": "sample.exe"})
        assert not r.is_error


def test_normalize_address():
    assert normalize_address(" 0xdeadBEEF ") == "0xDEADBEEF"
    assert normalize_address("401000h") == "0x401000"
    assert normalize_address("sub_401000") == "sub_401000"
    assert normalize_address("?foo@@YAXXZ") == "?foo@@YAXXZ"


def _two_dbs() -> FakeBridge:
    return FakeBridge([FakeInstance(1, "a.exe"), FakeInstance(2, "b.dll")])


@pytest.mark.anyio
async def test_database_parameter_routes_each_call():
    fb = _two_dbs()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert all("database" in t.input_schema["properties"] for n, t in tools.items() if n != "ida_status")
        await c.call_tool("ida_list_functions", {"database": "a.exe"})
        await c.call_tool("ida_list_functions", {"database": "b.dll"})
        await c.call_tool("ida_get_disassembly", {"address": "0x1000", "database": "2"})
        await c.call_tool("ida_get_metadata", {})
    assert fb.databases == ["a.exe", "b.dll", "2", None]


@pytest.mark.anyio
async def test_status_lists_every_database():
    fb = _two_dbs()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_status", {})
    dbs = r.structured_content["databases"]
    assert [d["database"] for d in dbs] == ["a.exe", "b.dll"]
    assert all(d["connected"] for d in dbs)


@pytest.mark.anyio
async def test_write_needs_explicit_database_when_several_open():
    fb = _two_dbs()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_set_comment", {"address": "0x1000", "comment": "x"})
        assert r.is_error and "pass `database`" in r.content[0].text
        assert fb.calls == []
        r = await c.call_tool("ida_set_comment", {"address": "0x1000", "comment": "x", "database": "b.dll"})
        assert not r.is_error
        r = await c.call_tool("ida_get_metadata", {})  # reads without `database` use the default
        assert not r.is_error
        await c.call_tool("ida_select_instance", {"database": "a.exe"})  # explicit default satisfies the guard
        r = await c.call_tool("ida_set_comment", {"address": "0x1000", "comment": "y"})
        assert not r.is_error
    assert [d for d, (m, _, _) in zip(fb.databases, fb.calls) if m == "set_comment"] == ["b.dll", None]


@pytest.mark.anyio
async def test_decompile_uses_long_timeout_and_maps_unavailable():
    fb = FakeBridge()
    async with Client(create_server(fb), raise_exceptions=True) as c:
        r = await c.call_tool("ida_decompile", {"address": "0x140001000"})
        assert not r.is_error
        fb.raise_exc = BridgeError("decompiler_unavailable", "IDA Free: interactive only")
        r = await c.call_tool("ida_decompile", {"address": "0x140001000"})
    assert fb.calls[0][:2] == ("decompile", {"address": "0x140001000", "max_lines": 1000})
    assert fb.timeouts[0] == 90_000
    assert r.is_error and "[decompiler_unavailable]" in r.content[0].text
