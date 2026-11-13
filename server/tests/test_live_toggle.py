"""Live ON/OFF tests: drive Edit > Plugins > idamcp in real IDA Free 9.5 windows through
UI Automation (scoped to each IDA process) and check the bridge really starts and stops.

Run via scripts/run_live_tests.ps1 (add -TwoDatabases for the independence test). The file
sorts after the other live tests and leaves every bridge ON, as it found them.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest
from mcp import Client

from idamcp_server.bridge import BridgeManager, BridgeUnavailable, discover, state_dir
from idamcp_server.server import create_server

pytestmark = [pytest.mark.live, pytest.mark.anyio]

UI = Path(__file__).resolve().parents[2] / "scripts" / "ida_ui.ps1"


def _instances() -> dict[str, int]:
    try:
        return {i.name.lower(): i.pid for i in discover()}
    except Exception:
        return {}


PIDS = _instances()
if "sample.exe" not in PIDS:
    pytest.skip("needs sample.exe open in IDA with MCP turned on", allow_module_level=True)


def discovery_file(pid: int) -> Path:
    return state_dir() / "instances" / f"ida-{pid}.json"


def toggle(pid: int) -> None:
    """Clicks Edit > Plugins > idamcp in that IDA window."""
    r = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(UI), "-ProcessId", str(pid),
         "-Action", "menu", "-MenuPath", "Edit/Plugins/idamcp"],
        capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def wait_state(pid: int, on: bool, timeout: float = 15.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if discovery_file(pid).exists() == on:
            return
        time.sleep(0.2)
    raise AssertionError(f"pid {pid}: bridge did not turn {'ON' if on else 'OFF'}")


def set_state(pid: int, on: bool) -> None:
    if discovery_file(pid).exists() != on:
        toggle(pid)
    wait_state(pid, on)


def read_discovery(pid: int) -> dict:
    return json.loads(discovery_file(pid).read_text(encoding="utf-8"))


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) == 0


def listening_ports(pid: int) -> list[int]:
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"Get-NetTCPConnection -OwningProcess {pid} -State Listen -ErrorAction SilentlyContinue | "
         "ForEach-Object LocalPort"],
        capture_output=True, text=True, timeout=60,
    ).stdout.split()
    return [int(x) for x in out]


def bridge_log(pid: int) -> list[dict]:
    p = state_dir() / "logs" / f"bridge-{pid}.log"
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


@pytest.fixture
def pid():
    p = PIDS["sample.exe"]
    set_state(p, True)
    yield p
    set_state(p, True)  # leave it ON for whatever runs next


async def test_off_stops_everything_and_keeps_database(pid):
    mgr = BridgeManager()
    before = await mgr.call("get_metadata", database=str(pid))
    names_before = await mgr.call("list_functions", {"limit": 1000}, database=str(pid))
    disc = read_discovery(pid)
    # An authenticated client stays connected while we switch OFF.
    reader, writer = await asyncio.open_connection("127.0.0.1", disc["port"])
    writer.write((json.dumps({"id": 1, "method": "hello", "params": {"token": disc["token"]}}) + "\n").encode())
    await writer.drain()
    assert json.loads(await reader.readline())["ok"] is True

    toggle(pid)
    wait_state(pid, False)

    # Client disconnected, listener gone, nothing listening, discovery file removed.
    assert await asyncio.wait_for(reader.read(), timeout=10) == b""
    writer.close()
    assert not port_open(disc["port"])
    assert listening_ports(pid) == []
    assert not discovery_file(pid).exists()
    assert str(pid) not in {str(i.pid) for i in discover()}
    stops = [e for e in bridge_log(pid) if e.get("event") == "stopped"]
    assert stops and stops[-1]["reason"] == "user"
    # MCP clients get a clear error, not a hang.
    with pytest.raises(BridgeUnavailable):
        await mgr.call("status", database=str(pid))

    toggle(pid)
    wait_state(pid, True)
    after = await mgr.call("get_metadata", database=str(pid))
    names_after = await mgr.call("list_functions", {"limit": 1000}, database=str(pid))
    assert after["sha256"] == before["sha256"] and after["function_count"] == before["function_count"]
    assert names_after["items"] == names_before["items"], "toggling must not touch the database"
    await mgr.aclose()


async def test_repeated_cycles_fresh_token_and_reconnect(pid):
    """One long-lived MCP server object survives several OFF/ON cycles (reconnects each time)."""
    mgr = BridgeManager()
    async with Client(create_server(mgr), raise_exceptions=True) as c:
        tokens, ports = set(), set()
        for _ in range(5):
            d = read_discovery(pid)
            tokens.add(d["token"])
            ports.add(d["port"])
            r = await c.call_tool("ida_list_functions", {"filter": "idamcp_", "database": str(pid)})
            assert not r.is_error and len(r.structured_content["items"]) == 3
            # a write works immediately while ON (no separate write switch)
            r = await c.call_tool("ida_set_comment", {"address": "idamcp_add", "comment": "cycle",
                                                      "database": str(pid)})
            assert not r.is_error, r.content[0].text
            r = await c.call_tool("ida_set_comment", {"address": "idamcp_add", "comment": "",
                                                      "database": str(pid)})
            assert not r.is_error
            toggle(pid)
            wait_state(pid, False)
            r = await c.call_tool("ida_get_metadata", {"database": str(pid)})
            text = r.content[0].text
            assert r.is_error and ("MCP turned on" in text or "no open IDA database" in text), text
            toggle(pid)
            wait_state(pid, True)
        assert len(tokens) == 5, "every activation must use a fresh token"
        # The old token is rejected by the new bridge.
        d = read_discovery(pid)
        reader, writer = await asyncio.open_connection("127.0.0.1", d["port"])
        stale = next(t for t in tokens if t != d["token"])
        writer.write((json.dumps({"id": 1, "method": "hello", "params": {"token": stale}}) + "\n").encode())
        await writer.drain()
        resp = json.loads(await reader.readline())
        assert resp["ok"] is False and resp["error"]["code"] == "unauthenticated"
        writer.close()
        # Exactly one listener after many cycles (nothing leaked).
        assert listening_ports(pid) == [d["port"]]
    await mgr.aclose()


async def test_windows_have_independent_state(pid):
    if "sample_b.exe" not in PIDS:
        pytest.skip("needs sample_b.exe in a second IDA window (-TwoDatabases)")
    pid_b = PIDS["sample_b.exe"]
    set_state(pid_b, True)
    try:
        toggle(pid_b)
        wait_state(pid_b, False)
        visible = {i.name.lower() for i in discover()}
        assert "sample.exe" in visible and "sample_b.exe" not in visible
        mgr = BridgeManager()
        assert (await mgr.call("status", database="sample.exe"))["function_count"] > 0
        with pytest.raises(BridgeUnavailable, match="no open IDA database matches"):
            await mgr.call("status", database="sample_b.exe")
        # With only one enabled database, a write without `database` is unambiguous again.
        # (Only checkable when no unrelated IDA window has MCP on; never write to those.)
        if visible == {"sample.exe"}:
            async with Client(create_server(mgr), raise_exceptions=True) as c:
                r = await c.call_tool("ida_set_comment", {"address": "idamcp_add", "comment": "solo"})
                assert not r.is_error, r.content[0].text
                await c.call_tool("ida_set_comment", {"address": "idamcp_add", "comment": ""})
        # And the other way round: b ON, a OFF.
        toggle(pid_b)
        wait_state(pid_b, True)
        toggle(pid)
        wait_state(pid, False)
        visible = {i.name.lower() for i in discover()}
        assert visible >= {"sample_b.exe"} and "sample.exe" not in visible
        assert (await mgr.call("status", database="sample_b.exe"))["function_count"] > 0
        await mgr.aclose()
    finally:
        set_state(pid_b, True)
