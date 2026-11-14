"""Live tests on a large binary (disposable copy, see run_live_tests.ps1 -LargeBinary):
full pagination, deadline truncation + resume, bounded responses, and turning MCP OFF
while requests are pending."""

from __future__ import annotations

import asyncio
import json
import os
import time

import pytest

from idamcp_server.bridge import BridgeManager, discover
from idamcp_server.compare import fetch_fingerprints

pytestmark = [pytest.mark.live, pytest.mark.anyio]

LARGE = os.environ.get("IDAMCP_LIVE_LARGE", "").lower()


def _pid() -> int | None:
    try:
        return next((i.pid for i in discover() if i.name.lower() == LARGE), None)
    except Exception:
        return None


PID = _pid() if LARGE else None
if PID is None:
    pytest.skip("needs a large binary open with MCP on (run_live_tests.ps1 -LargeBinary <path>)",
                allow_module_level=True)
DB = str(PID)


async def test_full_function_pagination():
    m = BridgeManager()
    first = await m.call("list_functions", {"limit": 1000}, database=DB)
    total = first["total"]
    assert total > 1000, "large-binary test needs > 1000 functions"
    seen, offset = [], 0
    while True:
        page = await m.call("list_functions", {"offset": offset, "limit": 1000}, database=DB)
        assert len(page["items"]) <= 1000
        seen += [f["address"] for f in page["items"]]
        if page["next_offset"] is None:
            break
        offset = page["next_offset"]
    assert len(seen) == len(set(seen)) == total
    await m.aclose()


async def test_deadline_truncation_and_resume():
    m = BridgeManager()
    # A text scan over the whole database cannot finish in 300 ms: it must stop with a cursor...
    r = await m.call("search_disassembly", {"text": "zz_no_such_text_zz", "max_results": 10},
                     database=DB, timeout_ms=300)
    assert r["truncated_by_deadline"] is True and r["next_start"]
    # ...and resuming continues strictly forward from that cursor.
    r2 = await m.call("search_disassembly", {"text": "zz_no_such_text_zz", "start": r["next_start"]},
                      database=DB, timeout_ms=300)
    if r2["next_start"]:
        assert int(r2["next_start"], 16) > int(r["next_start"], 16)
    # Response size stays bounded even for big pages.
    big = await m.call("list_functions", {"limit": 1000}, database=DB)
    assert len(json.dumps(big)) < 1_000_000
    await m.aclose()


async def test_fingerprint_whole_database():
    m = BridgeManager()

    async def call(database, method, *, timeout_ms=None, **params):
        return await m.call(method, params, database=database, timeout_ms=timeout_ms)

    t = time.time()
    fps, truncated = await fetch_fingerprints(call, DB, 50_000, 60_000)
    assert not truncated and len(fps) > 1000
    assert all(len(f["exact_hash"]) == 16 for f in fps)
    print(f"fingerprinted {len(fps)} functions in {time.time() - t:.1f}s")
    await m.aclose()


async def test_off_with_pending_requests():
    """Several requests in flight on separate connections, then MCP is switched OFF in IDA."""
    from test_live_toggle import discovery_file, toggle, wait_state  # UI helpers (same process-scoped UIA)

    disc = json.loads(discovery_file(PID).read_text(encoding="utf-8"))

    async def run_one(i: int):
        r, w = await asyncio.open_connection("127.0.0.1", disc["port"], limit=64 << 20)
        w.write((json.dumps({"id": 0, "method": "hello", "params": {"token": disc["token"]}}) + "\n").encode())
        await w.drain()
        assert json.loads(await r.readline())["ok"]
        # A full-database text scan for a string that does not exist runs until its 6 s deadline,
        # so while request 1 executes on IDA's main thread the others are queued behind it.
        req = {"id": i, "method": "search_disassembly",
               "params": {"text": "zz_no_such_text_zz", "code_only": False, "timeout_ms": 6000}}
        w.write((json.dumps(req) + "\n").encode())
        await w.drain()
        line = await asyncio.wait_for(r.readline(), timeout=120)
        w.close()
        return json.loads(line) if line else None  # None = connection closed by shutdown

    tasks = [asyncio.create_task(run_one(i)) for i in range(1, 7)]
    await asyncio.sleep(1.0)                      # first request is running, others are queued
    t0 = time.time()
    await asyncio.to_thread(toggle, PID)          # Edit > Plugins > idamcp (runs after the running request)
    await asyncio.to_thread(wait_state, PID, False, 120)
    results = await asyncio.gather(*tasks)
    elapsed = time.time() - t0
    finished = [x for x in results if x and x.get("ok")]
    cancelled = [x for x in results if x is None or not x.get("ok")]
    assert finished, "the request already running completes normally"
    assert cancelled, "queued requests are cancelled, not executed after OFF"
    for x in cancelled:
        # Acceptable outcomes for a queued request, none of which executes it:
        #   None              connection closed by the shutdown
        #   cancelled/disabled  cancelled by MCP being turned off
        #   timeout           expired while queued ("nothing was executed")
        assert x is None or x["error"]["code"] in ("cancelled", "disabled") or (
            x["error"]["code"] == "timeout" and "nothing was executed" in x["error"]["message"]), x
    assert not discovery_file(PID).exists()
    assert elapsed < 120
    # IDA is still responsive and MCP can be turned back on.
    await asyncio.to_thread(toggle, PID)
    await asyncio.to_thread(wait_state, PID, True, 30)
    m = BridgeManager()
    assert (await m.call("status", database=DB))["function_count"] > 1000
    await m.aclose()
