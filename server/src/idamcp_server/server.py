"""MCP tool definitions for idamcp.

All analysis happens inside IDA (via the bridge plugin). This module validates
inputs, routes calls to the selected IDA instance, and turns bridge errors into
actionable tool errors. It never executes code or scripts.
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any, Literal, Protocol

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__
from .bridge import BridgeError, BridgeManager, BridgeUnavailable

log = logging.getLogger("idamcp.server")

INSTRUCTIONS = """\
Tools for inspecting the database currently open in IDA Free 9.5 (disassembler only).
- Addresses are hex strings like "0x140001000" (an "h" suffix is accepted); most tools
  also accept a symbol name instead of an address.
- Lists are paginated: pass the returned `next_offset` (or `next_address`/`next_start`)
  back to continue. Work per call is time-bounded; `truncated_by_deadline: true` means
  call again with the cursor.
- There is NO decompiler: IDA Free's cloud decompiler is not used and nothing here
  produces pseudocode. Reason from disassembly, xrefs and the control-flow graph.
- MCP is turned on per IDA window (Edit > Plugins > idamcp); while on, reads and writes
  (renames, comments, function creation) are available. Changes can be undone in IDA (Ctrl+Z).
- Several databases can be open at once (one IDA window each). ida_status lists them; pass
  `database` (file name like "a.exe", or the IDA pid) to any tool to target one. Writes
  require `database` whenever more than one database is open.
- Start with ida_status / ida_get_metadata, then ida_list_functions, ida_get_disassembly,
  ida_get_xrefs_to, ida_get_callers / ida_get_callees.
"""

_HEX = re.compile(r"^0[xX]([0-9a-fA-F]{1,16})$")
_HEX_H = re.compile(r"^([0-9a-fA-F]{1,16})[hH]$")
_DECIMAL = re.compile(r"^\d+$")

READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)

Address = Annotated[
    str,
    Field(
        min_length=1,
        max_length=512,
        description='Hex address ("0x140001000") or a symbol name present in the database ("main").',
    ),
]
Offset = Annotated[int, Field(ge=0, description="Pagination offset (use next_offset from the previous page).")]
Limit = Annotated[int, Field(ge=1, le=1000, description="Maximum items to return (1-1000).")]
Filter = Annotated[
    str | None,
    Field(max_length=256, description="Case-insensitive substring filter on the name."),
]
XrefKind = Annotated[Literal["all", "code", "data"], Field(description="Filter by reference kind.")]
NewName = Annotated[str, Field(min_length=1, max_length=511, description="New name (no whitespace).")]
Comment = Annotated[str, Field(max_length=8192, description="Comment text; empty string deletes it.")]
Database = Annotated[
    str | None,
    Field(max_length=1024, description='Which open IDA database to use when several are open: file name '
                                       '("a.exe"), IDB name, full path, or IDA process id. Default: the '
                                       'selected/most recently opened one.'),
]


class Bridge(Protocol):
    """What the tools need from the bridge (BridgeManager, or a fake in tests)."""

    selected_pid: int | None

    async def call(self, method: str, params: dict[str, Any] | None = None, *, retry: bool = True,
                   timeout_ms: int | None = None, database: str | None = None) -> Any: ...

    def instances(self) -> list[Any]: ...

    def select(self, database: str) -> Any: ...

    async def hello(self, database: str | None = None) -> dict[str, Any]: ...

    async def aclose(self) -> None: ...


def normalize_address(value: str, field: str = "address") -> str:
    """Normalises an address argument: hex -> "0x..." (upper-case digits), names pass through."""
    v = value.strip()
    if m := _HEX.match(v):
        return "0x" + m.group(1).upper()
    if m := _HEX_H.match(v):
        return "0x" + m.group(1).upper()
    if _DECIMAL.match(v):
        raise ToolError(
            f"{field} '{v}' is ambiguous: write hex addresses with a 0x prefix (e.g. 0x{int(v):X} if you meant "
            "decimal, or 0x" + v + " if it was already hex)."
        )
    if not v or any(c.isspace() or ord(c) < 0x20 for c in v):
        raise ToolError(f"{field} must be a hex address like 0x140001000 or a symbol name without whitespace")
    return v


def _optional_hex(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    v = normalize_address(value, field)
    if not v.startswith("0x"):
        raise ToolError(f"{field} must be a hex address (e.g. 0x140010000), not a name")
    return v


def create_server(bridge: Bridge) -> MCPServer:
    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[None]:
        try:
            yield None
        finally:
            await bridge.aclose()

    mcp = MCPServer(
        "idamcp",
        version=__version__,
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
    )

    async def call(database: str | None, method: str, *, write: bool = False, **params: Any) -> Any:
        if write and not database and bridge.selected_pid is None and len(bridge.instances()) > 1:
            names = ", ".join(f"{i.describe().get('database')} (pid {i.pid})" for i in bridge.instances())
            raise ToolError("Several IDA databases are open; pass `database` to say which one to modify. "
                            f"Open: {names}")
        try:
            return await bridge.call(method, params, retry=not write, database=database)
        except BridgeError as e:
            raise ToolError(f"[{e.code}] {e.message}") from e
        except BridgeUnavailable as e:
            raise ToolError(str(e)) from e

    # ------------------------------------------------------------------ status
    @mcp.tool(title="IDA connection status", annotations=READ_ONLY)
    async def ida_status() -> dict[str, Any]:
        """Lists every IDA database with MCP turned on (name, pid, analysis state) and which one
        is used by default. Pass a database's name as `database` to any tool to work on it.
        Databases with MCP turned off in IDA are not visible."""
        insts = bridge.instances()
        out: dict[str, Any] = {
            "server_version": __version__,
            "databases": [],
        }
        if not insts:
            out["connected"] = False
            out["hint"] = ("No IDA database has MCP turned on. In IDA Free 9.5, open the database and choose "
                           "Edit > Plugins > idamcp; the Output window then shows '[idamcp] MCP ENABLED'.")
            return out
        default_pid = None
        try:
            default_pid = bridge.resolve().pid  # type: ignore[attr-defined]
        except Exception:  # fake bridges in tests may not implement resolve()
            default_pid = bridge.selected_pid or insts[0].pid
        for inst in insts:
            entry = inst.describe()
            entry["default"] = inst.pid == default_pid
            sel = str(inst.pid)
            try:
                hello = await bridge.hello(sel)
                st = await bridge.call("status", database=sel)
                entry.update(connected=True, function_count=st.get("function_count"),
                             auto_analysis_complete=st.get("auto_analysis_complete"),
                             capabilities=hello.get("capabilities"))
            except (BridgeError, BridgeUnavailable) as e:
                entry.update(connected=False, error=str(e))
            out["databases"].append(entry)
        out["connected"] = any(d.get("connected") for d in out["databases"])
        return out

    @mcp.tool(title="Select default database", annotations=READ_ONLY)
    async def ida_select_instance(
        database: Annotated[str, Field(min_length=1, max_length=1024,
                                       description="File name, IDB name, path, or IDA process id from ida_status.")],
    ) -> dict[str, Any]:
        """Sets the default database for calls that don't pass `database` (useful when several are open)."""
        try:
            inst = bridge.select(database)
        except BridgeUnavailable as e:
            raise ToolError(str(e)) from e
        return {"selected": inst.describe()}

    @mcp.tool(title="Database metadata", annotations=READ_ONLY)
    async def ida_get_metadata(database: Database = None) -> dict[str, Any]:
        """Input file, hashes, format, processor, bitness, image base, address range,
        entry point, compiler and counts (functions, segments, imports)."""
        return await call(database, "get_metadata")

    @mcp.tool(title="List segments", annotations=READ_ONLY)
    async def ida_list_segments(offset: Offset = 0, limit: Limit = 100, database: Database = None) -> dict[str, Any]:
        """Segments/sections with name, class, range, permissions (rwx) and bitness."""
        return await call(database, "list_segments", offset=offset, limit=limit)

    # --------------------------------------------------------------- functions
    @mcp.tool(title="List functions", annotations=READ_ONLY)
    async def ida_list_functions(offset: Offset = 0, limit: Limit = 100, filter: Filter = None, database: Database = None) -> dict[str, Any]:
        """Functions with address, name, size and flags (library/thunk/noreturn).
        Paginated; `total` is the number of functions in the database."""
        return await call(database, "list_functions", offset=offset, limit=limit, filter=filter)

    @mcp.tool(title="Function details", annotations=READ_ONLY)
    async def ida_get_function(address: Address, database: Database = None) -> dict[str, Any]:
        """Details of the function containing `address`: bounds, chunks, size, flags,
        comments and instruction count."""
        return await call(database, "get_function", address=normalize_address(address))

    @mcp.tool(title="Disassembly", annotations=READ_ONLY)
    async def ida_get_disassembly(
        address: Address,
        mode: Annotated[
            Literal["function", "linear"],
            Field(description="'function': all items of the containing function (incl. chunks); "
                              "'linear': consecutive items starting at address."),
        ] = "function",
        max_lines: Annotated[int, Field(ge=1, le=2000)] = 200,
        start_from: Annotated[
            str | None, Field(max_length=32, description="Function mode only: resume at this address "
                                                         "(next_address from the previous call).")
        ] = None,
        database: Database = None,
    ) -> dict[str, Any]:
        """IDA disassembly listing (text as shown in IDA, with labels and bytes). This is
        disassembly, not decompiled code."""
        return await call(
            database,
            "get_disassembly",
            address=normalize_address(address),
            mode=mode,
            max_lines=max_lines,
            start_from=_optional_hex(start_from, "start_from"),
        )

    @mcp.tool(title="Read bytes", annotations=READ_ONLY)
    async def ida_get_bytes(
        address: Address,
        size: Annotated[int, Field(ge=1, le=65536, description="Number of bytes (max 65536).")] = 256,
        database: Database = None,
    ) -> dict[str, Any]:
        """Raw database bytes as hex; `unloaded_ranges` marks bytes with no value in the database."""
        return await call(database, "get_bytes", address=normalize_address(address), size=size)

    # ----------------------------------------------------------------- strings
    @mcp.tool(title="List strings", annotations=READ_ONLY)
    async def ida_get_strings(
        offset: Offset = 0,
        limit: Limit = 100,
        min_length: Annotated[int, Field(ge=0, le=1_000_000)] = 0,
        database: Database = None,
    ) -> dict[str, Any]:
        """String literals from IDA's string list (address, length, encoding, text)."""
        return await call(database, "get_strings", offset=offset, limit=limit, min_length=min_length)

    @mcp.tool(title="Search strings", annotations=READ_ONLY)
    async def ida_search_strings(
        query: Annotated[str, Field(min_length=1, max_length=1024, description="Text to look for.")],
        match: Literal["contains", "exact", "prefix", "suffix"] = "contains",
        case_sensitive: bool = False,
        offset: Offset = 0,
        limit: Limit = 100,
        database: Database = None,
    ) -> dict[str, Any]:
        """Finds string literals by text. `next_offset` is a position in the string list:
        pass it back as `offset` to continue scanning."""
        return await call(
            database,
            "get_strings", query=query, match=match, case_sensitive=case_sensitive, offset=offset, limit=limit
        )

    # ------------------------------------------------------- imports/exports
    @mcp.tool(title="Imports", annotations=READ_ONLY)
    async def ida_get_imports(offset: Offset = 0, limit: Limit = 100, filter: Filter = None, database: Database = None) -> dict[str, Any]:
        """Imported functions (address of the import slot, name/ordinal, module).
        The filter matches the function or module name."""
        return await call(database, "get_imports", offset=offset, limit=limit, filter=filter)

    @mcp.tool(title="Exports", annotations=READ_ONLY)
    async def ida_get_exports(offset: Offset = 0, limit: Limit = 100, filter: Filter = None, database: Database = None) -> dict[str, Any]:
        """Exported symbols (entries with an export ordinal)."""
        return await call(database, "get_entries", kind="exports", offset=offset, limit=limit, filter=filter)

    @mcp.tool(title="Entry points", annotations=READ_ONLY)
    async def ida_get_entrypoints(offset: Offset = 0, limit: Limit = 100, database: Database = None) -> dict[str, Any]:
        """All entry points (program entry + exports); `is_program_entry` marks the start address."""
        return await call(database, "get_entries", kind="all", offset=offset, limit=limit)

    # ------------------------------------------------------------------ xrefs
    @mcp.tool(title="Cross-references to", annotations=READ_ONLY)
    async def ida_get_xrefs_to(
        address: Address,
        kind: XrefKind = "all",
        include_flow: Annotated[bool, Field(description="Include ordinary fall-through flow.")] = False,
        offset: Offset = 0,
        limit: Limit = 100,
        database: Database = None,
    ) -> dict[str, Any]:
        """References TO an address (who calls/jumps/reads/writes it), with the containing function."""
        return await call(database, "get_xrefs_to", address=normalize_address(address), kind=kind,
                          include_flow=include_flow, offset=offset, limit=limit)

    @mcp.tool(title="Cross-references from", annotations=READ_ONLY)
    async def ida_get_xrefs_from(
        address: Address,
        kind: XrefKind = "all",
        include_flow: Annotated[bool, Field(description="Include ordinary fall-through flow.")] = False,
        offset: Offset = 0,
        limit: Limit = 100,
        database: Database = None,
    ) -> dict[str, Any]:
        """References FROM the item at an address (call/jump targets, data accessed)."""
        return await call(database, "get_xrefs_from", address=normalize_address(address), kind=kind,
                          include_flow=include_flow, offset=offset, limit=limit)

    @mcp.tool(title="Callers", annotations=READ_ONLY)
    async def ida_get_callers(address: Address, limit: Limit = 200, database: Database = None) -> dict[str, Any]:
        """Functions that call (or jump to) the function containing `address`, grouped by caller
        with call sites; `data_references` lists places taking its address."""
        return await call(database, "get_callers", address=normalize_address(address), limit=limit)

    @mcp.tool(title="Callees", annotations=READ_ONLY)
    async def ida_get_callees(address: Address, limit: Limit = 200, database: Database = None) -> dict[str, Any]:
        """Targets called by the function containing `address`: direct calls, tail jumps, and
        indirect calls through pointers such as import slots."""
        return await call(database, "get_callees", address=normalize_address(address), limit=limit)

    # ---------------------------------------------------------- control flow
    @mcp.tool(title="Basic blocks", annotations=READ_ONLY)
    async def ida_get_basic_blocks(
        address: Address,
        max_blocks: Annotated[int, Field(ge=1, le=5000)] = 500,
        database: Database = None,
    ) -> dict[str, Any]:
        """Basic blocks of the function (range, type, successor/predecessor block ids)."""
        r = await call(database, "get_flowchart", address=normalize_address(address), max_blocks=max_blocks)
        r.pop("edges", None)
        return r

    @mcp.tool(title="Control-flow graph", annotations=READ_ONLY)
    async def ida_get_control_flow_graph(
        address: Address,
        include_instructions: Annotated[bool, Field(description="Embed disassembly per block.")] = False,
        max_blocks: Annotated[int, Field(ge=1, le=5000)] = 500,
        max_instructions: Annotated[int, Field(ge=1, le=2000)] = 1000,
        database: Database = None,
    ) -> dict[str, Any]:
        """The function's control-flow graph: blocks, edge list, block types (return,
        indirect jump, noreturn...), optionally with each block's instructions."""
        return await call(database, "get_flowchart", address=normalize_address(address),
                          include_instructions=include_instructions, max_blocks=max_blocks,
                          max_instructions=max_instructions)

    # ---------------------------------------------------------------- search
    @mcp.tool(title="Search bytes", annotations=READ_ONLY)
    async def ida_search_bytes(
        pattern: Annotated[
            str,
            Field(min_length=1, max_length=1024,
                  description='IDA byte pattern: hex bytes with ?? wildcards ("48 8B ?? 24 08"), or a '
                              'quoted string ("\\"GetProcAddress\\"").'),
        ],
        start: Annotated[str | None, Field(max_length=32, description="Start address (default: database min).")] = None,
        end: Annotated[str | None, Field(max_length=32, description="End address, exclusive (default: max).")] = None,
        max_results: Annotated[int, Field(ge=1, le=1000)] = 100,
        database: Database = None,
    ) -> dict[str, Any]:
        """Searches database bytes for a pattern. Continue with `start=next_start` if present."""
        return await call(database, "search_bytes", pattern=pattern, start=_optional_hex(start, "start"),
                          end=_optional_hex(end, "end"), max_results=max_results)

    @mcp.tool(title="Names", annotations=READ_ONLY)
    async def ida_get_names(offset: Offset = 0, limit: Limit = 100, filter: Filter = None, database: Database = None) -> dict[str, Any]:
        """Named locations (IDA's Names list) with demangled form and kind (function/code/data/string)."""
        return await call(database, "get_names", offset=offset, limit=limit, filter=filter)

    @mcp.tool(title="Comments", annotations=READ_ONLY)
    async def ida_get_comments(
        address: Address,
        end: Annotated[str | None, Field(max_length=32, description="End address (exclusive). Default: end of "
                                                                    "the containing function, else +4 KiB.")] = None,
        limit: Limit = 200,
        database: Database = None,
    ) -> dict[str, Any]:
        """Regular, repeatable and function comments from `address` up to `end`. To continue,
        pass `next_address` back as `address`."""
        return await call(database, "get_comments", address=normalize_address(address), end=_optional_hex(end, "end"),
                          limit=limit)

    # ----------------------------------------------------------------- writes
    WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True,
                            open_world_hint=False)

    @mcp.tool(title="Rename function", annotations=WRITE)
    async def ida_rename_function(address: Address, new_name: NewName, database: Database = None) -> dict[str, Any]:
        """Renames the function containing `address`."""
        return await call(database, "rename_function", write=True, address=normalize_address(address),
                          new_name=new_name)

    @mcp.tool(title="Rename symbol", annotations=WRITE)
    async def ida_rename_symbol(
        address: Address,
        new_name: Annotated[str, Field(max_length=511, description="New name; empty string removes "
                                                                   "the user-defined name.")],
        database: Database = None,
    ) -> dict[str, Any]:
        """Sets the name at any address (data, code label, function)."""
        return await call(database, "rename_symbol", write=True, address=normalize_address(address),
                          new_name=new_name)

    @mcp.tool(title="Set comment", annotations=WRITE)
    async def ida_set_comment(address: Address, comment: Comment, repeatable: bool = False, database: Database = None) -> dict[str, Any]:
        """Sets the regular (or repeatable) comment at an address."""
        return await call(database, "set_comment", write=True, address=normalize_address(address), comment=comment,
                          repeatable=repeatable)

    @mcp.tool(title="Set function comment", annotations=WRITE)
    async def ida_set_function_comment(address: Address, comment: Comment,
                                       repeatable: bool = False,
                                       database: Database = None,
                                   ) -> dict[str, Any]:
        """Sets the comment of the function containing `address`."""
        return await call(database, "set_function_comment", write=True, address=normalize_address(address),
                          comment=comment, repeatable=repeatable)

    @mcp.tool(title="Create function",
              annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False,
                                          idempotent_hint=False, open_world_hint=False))
    async def ida_create_function(
        address: Address,
        end: Annotated[str | None, Field(max_length=32, description="Optional end address (exclusive); "
                                                                    "default lets IDA determine it.")] = None,
        database: Database = None,
    ) -> dict[str, Any]:
        """Creates a function at an address that is not yet part of one."""
        return await call(database, "create_function", write=True, address=normalize_address(address),
                          end=_optional_hex(end, "end"))

    return mcp


def default_server(timeout_ms: int) -> MCPServer:
    return create_server(BridgeManager(default_timeout_ms=timeout_ms))
