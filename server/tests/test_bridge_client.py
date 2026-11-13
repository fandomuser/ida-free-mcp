"""Tests for discovery and the bridge client against a fake loopback bridge."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from idamcp_server import bridge as b

TOKEN = "a" * 64


class FakeBridgeServer:
    """Speaks the idamcp bridge protocol (newline-delimited JSON)."""

    def __init__(self, delay_s: float = 0.0) -> None:
        self.delay_s = delay_s
        self.requests: list[dict] = []
        self.server: asyncio.base_events.Server | None = None
        self.port = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        assert self.server
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        authed = False
        while line := await r.readline():
            req = json.loads(line)
            self.requests.append(req)
            rid, method, params = req["id"], req["method"], req.get("params", {})
            if not authed:
                if method == "hello" and params.get("token") == TOKEN:
                    authed = True
                    resp = {"id": rid, "ok": True, "result": {"pid": os.getpid()}}
                else:
                    resp = {"id": rid, "ok": False, "error": {"code": "unauthenticated", "message": "bad"}}
            elif method == "slow":
                await asyncio.sleep(self.delay_s)
                resp = {"id": rid, "ok": True, "result": "late"}
            elif method == "fail":
                resp = {"id": rid, "ok": False, "error": {"code": "not_found", "message": "nope"}}
            else:
                resp = {"id": rid, "ok": True, "result": {"method": method, "params": params}}
            try:
                w.write((json.dumps(resp) + "\n").encode())
                await w.drain()
            except ConnectionError:
                return
        w.close()


def write_discovery(state: Path, pid: int, port: int, **over) -> Path:
    d = state / "instances"
    d.mkdir(parents=True, exist_ok=True)
    data = {"pid": pid, "host": "127.0.0.1", "port": port, "token": TOKEN, "protocol": 1,
            "bridge_version": "1.0.0", "idb_path": "x.i64", "input_file": "x.exe",
            "started_at": "2026-01-01T00:00:00.000Z"}
    data.update(over)
    p = d / f"ida-{pid}.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("IDAMCP_STATE_DIR", str(tmp_path))
    return tmp_path


def test_discovery_filters_and_cleans(state):
    live = write_discovery(state, os.getpid(), 5555)
    dead = write_discovery(state, 99_999_999, 5556)  # no such process
    (state / "instances" / "ida-123.json").write_text("{not json", encoding="utf-8")
    (state / "instances" / "other.json").write_text("{}", encoding="utf-8")
    insts = b.discover()
    assert [i.port for i in insts] == [5555]
    assert insts[0].path == live
    assert not dead.exists(), "stale discovery file for a dead pid must be removed"


def test_discovery_rejects_non_loopback_and_bad_protocol(state):
    write_discovery(state, os.getpid(), 5555, host="192.168.1.10")
    assert b.discover() == []
    write_discovery(state, os.getpid(), 5555, protocol=2)
    assert b.discover() == []
    write_discovery(state, os.getpid(), 5555, token="short")
    assert b.discover() == []


@pytest.mark.anyio
async def test_call_roundtrip_and_auth(state):
    srv = FakeBridgeServer()
    await srv.start()
    try:
        write_discovery(state, os.getpid(), srv.port)
        mgr = b.BridgeManager(default_timeout_ms=2000)
        r = await mgr.call("list_functions", {"limit": 5, "filter": None})
        assert r == {"method": "list_functions", "params": {"limit": 5, "timeout_ms": 2000}}
        assert srv.requests[0]["method"] == "hello" and srv.requests[0]["params"]["token"] == TOKEN
        with pytest.raises(b.BridgeError) as ei:
            await mgr.call("fail")
        assert ei.value.code == "not_found"
        # connection is reused after an error response
        await mgr.call("status")
        assert sum(1 for q in srv.requests if q["method"] == "hello") == 1
        await mgr.aclose()
    finally:
        await srv.stop()


@pytest.mark.anyio
async def test_bad_token_is_reported(state):
    srv = FakeBridgeServer()
    await srv.start()
    try:
        write_discovery(state, os.getpid(), srv.port, token="b" * 64)
        mgr = b.BridgeManager()
        with pytest.raises(b.BridgeError) as ei:
            await mgr.call("status")
        assert ei.value.code == "unauthenticated"
        await mgr.aclose()
    finally:
        await srv.stop()


@pytest.mark.anyio
async def test_timeout_drops_connection(state, monkeypatch):
    monkeypatch.setattr(b, "_RESPONSE_MARGIN_S", 0.0)
    srv = FakeBridgeServer(delay_s=1.5)
    await srv.start()
    try:
        write_discovery(state, os.getpid(), srv.port)
        mgr = b.BridgeManager()
        with pytest.raises(b.BridgeError) as ei:
            await mgr.call("slow", timeout_ms=300)
        assert ei.value.code == "timeout"
        # A fresh connection is used afterwards; the late "slow" reply is never mis-matched.
        r = await mgr.call("status")
        assert r["method"] == "status"
        assert sum(1 for q in srv.requests if q["method"] == "hello") == 2
        await mgr.aclose()
    finally:
        await srv.stop()


@pytest.mark.anyio
async def test_no_instances(state):
    mgr = b.BridgeManager()
    with pytest.raises(b.BridgeUnavailable, match="No IDA database has MCP turned on"):
        await mgr.call("status")


@pytest.mark.anyio
async def test_connection_refused_is_unavailable(state):
    # Bind and close to get a port with nothing listening.
    s = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = s.sockets[0].getsockname()[1]
    s.close()
    await s.wait_closed()
    write_discovery(state, os.getpid(), port)
    mgr = b.BridgeManager()
    with pytest.raises(b.BridgeUnavailable):
        await mgr.call("status", retry=False)


@pytest.mark.anyio
async def test_reopened_database_new_token_reconnects(state, monkeypatch):
    """Same pid+port but a new token (database reopened) must not keep using the stale token."""
    srv = FakeBridgeServer()
    await srv.start()
    try:
        write_discovery(state, os.getpid(), srv.port)
        mgr = b.BridgeManager()
        await mgr.call("status")
        new_token = "c" * 64
        monkeypatch.setattr(sys.modules[__name__], "TOKEN", new_token)
        write_discovery(state, os.getpid(), srv.port, token=new_token, started_at="2026-01-02T00:00:00.000Z")
        r = await mgr.call("status")
        assert r["method"] == "status"
        hellos = [q for q in srv.requests if q["method"] == "hello"]
        assert hellos[-1]["params"]["token"] == new_token
        await mgr.aclose()
    finally:
        await srv.stop()


@pytest.mark.anyio
async def test_busy_handshake_is_unavailable(state):
    async def busy(r, w):
        await r.readline()
        w.write(b'{"id":null,"ok":false,"error":{"code":"busy","message":"too many connections"}}\n')
        await w.drain()
        w.close()

    s = await asyncio.start_server(busy, "127.0.0.1", 0)
    try:
        write_discovery(state, os.getpid(), s.sockets[0].getsockname()[1])
        mgr = b.BridgeManager()
        with pytest.raises(b.BridgeUnavailable, match="handshake"):
            await mgr.call("status")
    finally:
        s.close()
        await s.wait_closed()


def test_discovery_survives_bad_protocol_value(state):
    write_discovery(state, os.getpid(), 5555, protocol="not-a-number")
    assert b.discover() == []



def _sleeper():
    import subprocess
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])


def test_database_selector_matching(state):
    other = _sleeper()
    try:
        write_discovery(state, os.getpid(), 5555, input_file="C:\\bins\\a.exe", idb_path="C:\\bins\\a.exe.i64",
                        started_at="2026-01-01T00:00:00.000Z")
        write_discovery(state, other.pid, 5556, input_file="C:\\bins\\b.dll", idb_path="C:\\bins\\b.dll.i64",
                        started_at="2026-01-02T00:00:00.000Z")
        mgr = b.BridgeManager()
        assert mgr.resolve().port == 5556                      # most recently opened by default
        assert mgr.resolve("a.exe").port == 5555
        assert mgr.resolve("A.EXE").port == 5555               # case-insensitive
        assert mgr.resolve("a.exe.i64").port == 5555
        assert mgr.resolve("b").port == 5556                   # stem
        assert mgr.resolve(str(os.getpid())).port == 5555      # pid
        with pytest.raises(b.BridgeUnavailable, match="Open databases:"):
            mgr.resolve("c.exe")
        mgr.select("a.exe")
        assert mgr.resolve().port == 5555                      # selection changes the default
        assert mgr.resolve("b.dll").port == 5556               # explicit still wins
    finally:
        other.kill()


def test_ambiguous_database_name(state):
    other = _sleeper()
    try:
        write_discovery(state, os.getpid(), 5555, input_file="C:\\x\\app.exe")
        write_discovery(state, other.pid, 5556, input_file="C:\\y\\app.exe")
        with pytest.raises(b.BridgeUnavailable, match="ambiguous"):
            b.BridgeManager().resolve("app.exe")
    finally:
        other.kill()
