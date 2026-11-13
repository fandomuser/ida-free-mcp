"""Client for the idamcp bridge plugin running inside IDA.

The plugin publishes one discovery file per IDA process in
``%LOCALAPPDATA%\\idamcp\\instances\\ida-<pid>.json`` containing the loopback
port and a random token. This module discovers live instances, connects over
127.0.0.1, authenticates, and performs request/response calls using
newline-delimited JSON with per-call timeouts.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger("idamcp.bridge")

PROTOCOL_VERSION = 1
_DISCOVERY_NAME = re.compile(r"^ida-(\d+)\.json$")
_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
# Extra time we wait beyond the bridge-side deadline before giving up on a response.
_RESPONSE_MARGIN_S = 5.0


class BridgeError(Exception):
    """The bridge processed the request and reported an error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class BridgeUnavailable(Exception):
    """No usable IDA instance, or the connection failed."""


@dataclass(frozen=True)
class Instance:
    pid: int
    host: str
    port: int
    token: str
    idb_path: str
    input_file: str
    started_at: str
    bridge_version: str
    path: Path

    @property
    def name(self) -> str:
        """Short database name used to address this instance, e.g. "sample.exe"."""
        return Path(self.input_file).name if self.input_file else Path(self.idb_path).name

    def describe(self) -> dict[str, Any]:
        return {
            "database": self.name,
            "pid": self.pid,
            "port": self.port,
            "idb_path": self.idb_path,
            "input_file": self.input_file,
            "started_at": self.started_at,
            "bridge_version": self.bridge_version,
        }


def state_dir() -> Path:
    override = os.environ.get("IDAMCP_STATE_DIR")
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise BridgeUnavailable("LOCALAPPDATA is not set; cannot locate idamcp discovery files")
    return Path(base) / "idamcp"


def pid_alive(pid: int) -> bool:
    if sys.platform != "win32":  # pragma: no cover - the bridge is Windows-only
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        # Access denied still means the process exists.
        return ctypes.get_last_error() == 5
    try:
        code = wintypes.DWORD()
        if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
            return True
        return code.value == STILL_ACTIVE
    finally:
        k32.CloseHandle(h)


def _parse_instance(path: Path) -> Instance | None:
    m = _DISCOVERY_NAME.match(path.name)
    if not m:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        inst = Instance(
            pid=int(data["pid"]),
            host=str(data["host"]),
            port=int(data["port"]),
            token=str(data["token"]),
            idb_path=str(data.get("idb_path", "")),
            input_file=str(data.get("input_file", "")),
            started_at=str(data.get("started_at", "")),
            bridge_version=str(data.get("bridge_version", "")),
            path=path,
        )
        protocol = int(data.get("protocol", 0))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        log.warning("ignoring unreadable discovery file %s: %s", path, e)
        return None
    if inst.pid != int(m.group(1)) or not (0 < inst.port < 65536) or len(inst.token) < 32:
        log.warning("ignoring malformed discovery file %s", path)
        return None
    try:
        if not ipaddress.ip_address(inst.host).is_loopback:
            log.warning("ignoring discovery file %s: non-loopback host %s", path, inst.host)
            return None
    except ValueError:
        return None
    if protocol != PROTOCOL_VERSION:
        log.warning("ignoring %s: protocol %s != %s", path, protocol, PROTOCOL_VERSION)
        return None
    return inst


def discover(remove_stale: bool = True) -> list[Instance]:
    """Returns live instances, most recently started first."""
    d = state_dir() / "instances"
    if not d.is_dir():
        return []
    found: list[Instance] = []
    for p in d.glob("ida-*.json"):
        inst = _parse_instance(p)
        if inst is None:
            continue
        if not pid_alive(inst.pid):
            if remove_stale:
                try:
                    p.unlink()
                    log.info("removed stale discovery file %s (pid %d is gone)", p, inst.pid)
                except OSError:
                    pass
            continue
        found.append(inst)
    found.sort(key=lambda i: i.started_at, reverse=True)
    return found


class BridgeConnection:
    """One authenticated connection to one IDA instance. Calls are serialised."""

    def __init__(self, inst: Instance, connect_timeout_s: float = 5.0) -> None:
        self.inst = inst
        self._connect_timeout_s = connect_timeout_s
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._lock = asyncio.Lock()
        self._next_id = 0
        self.hello: dict[str, Any] = {}

    async def close(self) -> None:
        w, self._writer, self._reader = self._writer, None, None
        if w is not None:
            w.close()
            try:
                await w.wait_closed()
            except OSError:
                pass

    async def _roundtrip(self, method: str, params: dict[str, Any], timeout_s: float) -> Any:
        assert self._reader is not None and self._writer is not None
        self._next_id += 1
        rid = self._next_id
        line = json.dumps({"id": rid, "method": method, "params": params}, separators=(",", ":"))
        self._writer.write(line.encode("utf-8") + b"\n")
        await self._writer.drain()
        raw = await asyncio.wait_for(self._reader.readline(), timeout=timeout_s)
        if not raw:
            raise ConnectionError("bridge closed the connection")
        resp = json.loads(raw)
        if resp.get("id") != rid:
            raise ConnectionError(f"response id mismatch ({resp.get('id')} != {rid})")
        if not resp.get("ok"):
            err = resp.get("error") or {}
            raise BridgeError(str(err.get("code", "error")), str(err.get("message", "unknown error")))
        return resp.get("result")

    async def _ensure_connected(self) -> None:
        if self._writer is not None:
            return
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.inst.host, self.inst.port, limit=_MAX_RESPONSE_BYTES),
                timeout=self._connect_timeout_s,
            )
        except (OSError, asyncio.TimeoutError) as e:
            raise BridgeUnavailable(
                f"cannot connect to IDA (pid {self.inst.pid}) on {self.inst.host}:{self.inst.port}: {e}"
            ) from e
        try:
            self.hello = await self._roundtrip("hello", {"token": self.inst.token}, self._connect_timeout_s)
        except BridgeError:
            await self.close()
            raise  # e.g. unauthenticated: a real answer from the bridge
        except (OSError, ConnectionError, ValueError, asyncio.TimeoutError) as e:
            # Includes the bridge's "busy" reply (id null) and handshake timeouts.
            await self.close()
            raise BridgeUnavailable(f"handshake with IDA (pid {self.inst.pid}) failed: {e}") from e
        except BaseException:
            await self.close()
            raise
        log.info("connected to IDA pid=%d idb=%s", self.inst.pid, self.inst.idb_path)

    async def call(self, method: str, params: dict[str, Any], timeout_ms: int) -> Any:
        async with self._lock:
            await self._ensure_connected()
            sent = dict(params)
            sent["timeout_ms"] = timeout_ms
            try:
                return await self._roundtrip(method, sent, timeout_ms / 1000.0 + _RESPONSE_MARGIN_S)
            except BridgeError:
                raise
            except asyncio.TimeoutError as e:
                # Drop the connection: a late response must never be matched to a later request.
                await self.close()
                raise BridgeError(
                    "timeout",
                    f"IDA did not answer '{method}' within {timeout_ms / 1000:.0f}s (is a modal dialog open "
                    "in IDA?). The bridge refuses to start expired requests, so nothing was executed late.",
                ) from e
            except asyncio.CancelledError:
                await self.close()
                raise
            except (OSError, ConnectionError, ValueError) as e:
                await self.close()
                raise BridgeUnavailable(f"lost connection to IDA (pid {self.inst.pid}): {e}") from e


class BridgeManager:
    """Selects an IDA instance and routes calls to it."""

    def __init__(self, default_timeout_ms: int = 15000) -> None:
        self.default_timeout_ms = default_timeout_ms
        self._selected_pid: int | None = None
        self._conns: dict[int, BridgeConnection] = {}

    @property
    def selected_pid(self) -> int | None:
        return self._selected_pid

    def instances(self) -> list[Instance]:
        return discover()

    def select(self, database: str) -> Instance:
        insts = self.instances()
        if not insts:
            raise BridgeUnavailable("No IDA database has MCP turned on (Edit > Plugins > idamcp).")
        inst = self._match(insts, database)
        self._selected_pid = inst.pid
        return inst

    @staticmethod
    def _match(insts: list[Instance], database: str) -> Instance:
        """Finds the instance for a database selector: a pid, a file name, or a full path."""
        sel = database.strip()
        if sel.isdigit():
            for inst in insts:
                if inst.pid == int(sel):
                    return inst
        else:
            low = sel.lower()

            def keys(i: Instance) -> set[str]:
                ks = {i.input_file.lower(), i.idb_path.lower(), i.name.lower()}
                for p in (i.input_file, i.idb_path):
                    if p:
                        ks |= {Path(p).name.lower(), Path(p).stem.lower()}
                return ks - {""}

            hits = [i for i in insts if low in keys(i)]
            if len(hits) == 1:
                return hits[0]
            if len(hits) > 1:
                raise BridgeUnavailable(
                    f"database '{sel}' is ambiguous: " + ", ".join(f"{i.name} (pid {i.pid})" for i in hits)
                    + ". Pass the pid instead."
                )
        open_dbs = ", ".join(f"{i.name} (pid {i.pid})" for i in insts) or "none"
        raise BridgeUnavailable(f"no open IDA database matches '{sel}'. Open databases: {open_dbs}")

    def resolve(self, database: str | None = None) -> Instance:
        """The instance for `database`, else the selected one, else the most recently opened."""
        insts = self.instances()
        if not insts:
            raise BridgeUnavailable(
                "No IDA database has MCP turned on. In IDA Free 9.5, open the database and choose "
                "Edit > Plugins > idamcp (the Output window then shows '[idamcp] MCP ENABLED')."
            )
        if database:
            return self._match(insts, database)
        if self._selected_pid is not None:
            for inst in insts:
                if inst.pid == self._selected_pid:
                    return inst
            log.info("selected IDA pid %d is gone; falling back to most recent instance", self._selected_pid)
            self._selected_pid = None
        return insts[0]

    async def _connection(self, inst: Instance) -> BridgeConnection:
        conn = self._conns.get(inst.pid)
        # A reopened database in the same process gets a new token (and maybe port).
        if conn is not None and conn.inst != inst:
            await conn.close()
            conn = None
        if conn is None:
            conn = BridgeConnection(inst)
            self._conns[inst.pid] = conn
        return conn

    async def call(self, method: str, params: dict[str, Any] | None = None, *, retry: bool = True,
                   timeout_ms: int | None = None, database: str | None = None) -> Any:
        """Calls a bridge method on the instance chosen by `database` (see resolve()).
        `retry` re-attempts once on connection loss (read-only calls only)."""
        params = {k: v for k, v in (params or {}).items() if v is not None}
        tmo = timeout_ms or self.default_timeout_ms
        inst = self.resolve(database)
        conn = await self._connection(inst)
        try:
            return await conn.call(method, params, tmo)
        except BridgeUnavailable:
            if not retry:
                raise
            log.info("retrying %s after connection loss", method)
            inst = self.resolve(database)
            conn = await self._connection(inst)
            return await conn.call(method, params, tmo)

    async def hello(self, database: str | None = None) -> dict[str, Any]:
        inst = self.resolve(database)
        conn = await self._connection(inst)
        await conn.call("ping", {}, 5000)
        return conn.hello

    async def aclose(self) -> None:
        for conn in list(self._conns.values()):
            await conn.close()
        self._conns.clear()
