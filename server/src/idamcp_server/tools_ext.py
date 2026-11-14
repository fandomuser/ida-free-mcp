"""v1.1 tools: types, stack frames, UI/navigation, code/data editing, advanced search,
instruction decoding, function analysis and crypto/constant analysis.

Each tool is a thin, validated wrapper over one bridge method implemented natively in
the IDA plugin (plugin/src/{types,frames,ui,edit,search,analysis}.cpp).
"""

from __future__ import annotations

from typing import Annotated, Any, Awaitable, Callable, Literal

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from .server import (
    READ_ONLY,
    Address,
    Database,
    Filter,
    Limit,
    Offset,
    _optional_hex,
    normalize_address,
)

Call = Callable[..., Awaitable[Any]]

WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
WRITE_NONIDEM = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False,
                                open_world_hint=False)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=True,
                              open_world_hint=False)
UI_ACTION = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True,
                            open_world_hint=False)

HEAVY_TIMEOUT_MS = 60_000

Declaration = Annotated[str, Field(min_length=1, max_length=16384, description="C declaration.")]
HexAddr = Annotated[str | None, Field(max_length=32, description="Hex address, e.g. 0x140001000.")]
MaxResults = Annotated[int, Field(ge=1, le=1000, description="Maximum matches (1-1000).")]


def _imm(value: int | str) -> int | str:
    """Immediates may be given as int or hex string; strings are normalised to 0x... form."""
    if isinstance(value, int):
        return value
    v = value.strip()
    if v.lower().startswith("0x"):
        return "0x" + v[2:].upper()
    if v.lower().endswith("h"):
        return "0x" + v[:-1].upper()
    if v.lstrip("-").isdigit():
        return int(v)
    return "0x" + v.upper()


def register_extended(mcp: MCPServer, call: Call) -> None:
    # ------------------------------------------------------------ A. types
    @mcp.tool(title="Function prototype", annotations=READ_ONLY)
    async def ida_get_function_type(address: Address, database: Database = None) -> dict[str, Any]:
        """Prototype of the function containing `address`: declaration, return type, calling
        convention and arguments (name, type, register/stack location). `guessed: true` means IDA
        inferred it; `has_type: false` with no declaration means IDA has no prototype."""
        return await call(database, "get_function_type", address=normalize_address(address))

    @mcp.tool(title="Set function prototype", annotations=WRITE)
    async def ida_set_function_type(
        address: Address,
        declaration: Annotated[str, Field(min_length=1, max_length=16384,
                                          description='C prototype, e.g. "int __fastcall check(const char *key, int len)".')],
        database: Database = None,
    ) -> dict[str, Any]:
        """Applies a C prototype to the function containing `address` (argument names/types,
        calling convention). Referenced types must exist (see ida_list_types / ida_declare_type)."""
        return await call(database, "set_function_type", write=True, address=normalize_address(address),
                          declaration=declaration)

    @mcp.tool(title="List local types", annotations=READ_ONLY)
    async def ida_list_types(
        kind: Literal["all", "struct", "union", "enum", "typedef", "function"] = "all",
        filter: Filter = None,
        offset: Offset = 0,
        limit: Limit = 100,
        database: Database = None,
    ) -> dict[str, Any]:
        """Local types in the database (structs, unions, enums, typedefs) with size and member count."""
        return await call(database, "list_types", kind=kind, filter=filter, offset=offset, limit=limit)

    @mcp.tool(title="Get type", annotations=READ_ONLY)
    async def ida_get_type(
        name: Annotated[str, Field(min_length=1, max_length=511, description="Local type name.")],
        max_members: Annotated[int, Field(ge=1, le=2000)] = 500,
        database: Database = None,
    ) -> dict[str, Any]:
        """A local type's C declaration and members: struct/union member names, byte offsets,
        sizes and types; enum member names and values."""
        return await call(database, "get_type", name=name, max_members=max_members)

    @mcp.tool(title="Declare type (struct/union/enum/typedef)", annotations=WRITE)
    async def ida_declare_type(
        declaration: Annotated[str, Field(min_length=1, max_length=16384,
                                          description='e.g. "struct packet { int len; char data[16]; }" or '
                                                      '"enum color { RED = 1, BLUE = 2 }".')],
        replace: Annotated[bool, Field(description="Redefine an existing type of the same name.")] = False,
        database: Database = None,
    ) -> dict[str, Any]:
        """Creates a local struct, union, enum or typedef from a C declaration, or (replace=true)
        edits an existing one by redefining it. Returns the stored layout."""
        return await call(database, "declare_type", write=True, declaration=declaration, replace=replace)

    @mcp.tool(title="Apply type to data", annotations=WRITE)
    async def ida_set_data_type(
        address: Address,
        declaration: Annotated[str, Field(min_length=1, max_length=16384,
                                          description='Type for the data, e.g. "struct packet", "uint32_t table[256]".')],
        database: Database = None,
    ) -> dict[str, Any]:
        """Applies a C type to data at `address` (structs, arrays, pointers...). The whole range must
        be mapped; overlapping items may need ida_undefine first."""
        return await call(database, "set_data_type", write=True, address=normalize_address(address),
                          declaration=declaration)

    # ------------------------------------------------------------ B. stack frames
    @mcp.tool(title="Stack frame", annotations=READ_ONLY)
    async def ida_get_stack_frame(
        address: Address,
        max_members: Annotated[int, Field(ge=1, le=2000)] = 500,
        database: Database = None,
    ) -> dict[str, Any]:
        """Stack frame of a function as stored in the IDA database: layout (locals, saved registers,
        return address, stack arguments) and members with frame offset, frame-pointer-relative
        offset, size, type and kind. These are database stack variables, not decompiler locals.
        Register arguments are listed by ida_get_function_type."""
        return await call(database, "get_stack_frame", address=normalize_address(address), max_members=max_members)

    @mcp.tool(title="Rename stack variable", annotations=WRITE)
    async def ida_rename_stack_variable(
        address: Address,
        new_name: Annotated[str, Field(min_length=1, max_length=511)],
        name: Annotated[str | None, Field(max_length=511, description="Current member name (e.g. var_28).")] = None,
        frame_offset: Annotated[int | None, Field(ge=0, description="Or: the member's frame_offset.")] = None,
        database: Database = None,
    ) -> dict[str, Any]:
        """Renames a stack frame member (local or stack argument) of the function containing
        `address`. Identify it by `name` or `frame_offset` from ida_get_stack_frame."""
        return await call(database, "rename_stack_variable", write=True, address=normalize_address(address),
                          new_name=new_name, name=name, frame_offset=frame_offset)

    # ------------------------------------------------------------ C. cursor / navigation
    @mcp.tool(title="Cursor position", annotations=READ_ONLY)
    async def ida_get_cursor(database: Database = None) -> dict[str, Any]:
        """Where the user is in IDA: cursor address, containing function, name, segment, the
        current line and the active view."""
        return await call(database, "get_cursor")

    @mcp.tool(title="Selection", annotations=READ_ONLY)
    async def ida_get_selection(database: Database = None) -> dict[str, Any]:
        """The address range the user has selected in IDA, if any."""
        return await call(database, "get_selection")

    @mcp.tool(title="Jump to address", annotations=UI_ACTION)
    async def ida_jump_to(address: Address, database: Database = None) -> dict[str, Any]:
        """Moves the user's IDA disassembly view to `address` (navigation only; the database is
        not modified)."""
        return await call(database, "jump_to", write=True, address=normalize_address(address))

    @mcp.tool(title="List bookmarks", annotations=READ_ONLY)
    async def ida_list_bookmarks(
        limit: Annotated[int, Field(ge=1, le=1024)] = 200, database: Database = None
    ) -> dict[str, Any]:
        """Bookmarks (marked positions) of the disassembly view with slot, address and description."""
        return await call(database, "list_bookmarks", limit=limit)

    @mcp.tool(title="Add bookmark", annotations=WRITE_NONIDEM)
    async def ida_add_bookmark(
        address: Address,
        description: Annotated[str, Field(min_length=1, max_length=1024)],
        database: Database = None,
    ) -> dict[str, Any]:
        """Bookmarks `address` in IDA with a description (stored in the database)."""
        return await call(database, "add_bookmark", write=True, address=normalize_address(address),
                          description=description)

    @mcp.tool(title="Delete bookmark", annotations=DESTRUCTIVE)
    async def ida_delete_bookmark(
        slot: Annotated[int, Field(ge=0, le=1023, description="Slot from ida_list_bookmarks.")],
        database: Database = None,
    ) -> dict[str, Any]:
        """Deletes the bookmark in `slot`."""
        return await call(database, "delete_bookmark", write=True, slot=slot)

    # ------------------------------------------------------------ D. code/data
    @mcp.tool(title="Item info", annotations=READ_ONLY)
    async def ida_get_item_info(address: Address, database: Database = None) -> dict[str, Any]:
        """Classification of the item at `address`: code/data/unknown/tail, item bounds, data type
        and element count, function, names, comments, xrefs, applied type and the listing line."""
        return await call(database, "get_item_info", address=normalize_address(address))

    @mcp.tool(title="Define code", annotations=WRITE)
    async def ida_define_code(
        address: Address,
        end: HexAddr = None,
        max_instructions: Annotated[int, Field(ge=1, le=4096)] = 1,
        database: Database = None,
    ) -> dict[str, Any]:
        """Converts undefined bytes at `address` into instructions: one by default, up to
        `max_instructions`, or a whole range [address, end) (max 64 KiB). Existing code is kept."""
        return await call(database, "define_code", write=True, address=normalize_address(address),
                          end=_optional_hex(end, "end"), max_instructions=max_instructions)

    @mcp.tool(title="Define data", annotations=WRITE)
    async def ida_define_data(
        address: Address,
        type: Literal["byte", "word", "dword", "qword", "float", "double", "string", "string16"],
        count: Annotated[int, Field(ge=1, le=65536, description="Array element count (numeric types).")] = 1,
        length: Annotated[int, Field(ge=0, le=65536, description="String length in bytes; 0 = up to terminator.")] = 0,
        database: Database = None,
    ) -> dict[str, Any]:
        """Defines data at `address`: numeric items/arrays, or a C (8-bit) / UTF-16 string. Fails
        if existing items are in the way (ida_undefine them first)."""
        return await call(database, "define_data", write=True, address=normalize_address(address), type=type,
                          count=count, length=length)

    @mcp.tool(title="Undefine", annotations=DESTRUCTIVE)
    async def ida_undefine(
        address: Address,
        size: Annotated[int, Field(ge=1, le=65536, description="Number of bytes (max 65536).")],
        allow_function_code: Annotated[bool, Field(description="Allow undefining instructions that belong to a "
                                                               "function.")] = False,
        database: Database = None,
    ) -> dict[str, Any]:
        """Turns the items in [address, address+size) back into unexplored bytes. Refuses ranges
        containing function code unless allow_function_code=true. Undo with Ctrl+Z in IDA."""
        return await call(database, "undefine", write=True, address=normalize_address(address), size=size,
                          allow_function_code=allow_function_code)

    @mcp.tool(title="Reanalyze range", annotations=WRITE)
    async def ida_reanalyze_range(
        start: Annotated[str, Field(max_length=32, description="Hex start address.")],
        end: Annotated[str, Field(max_length=32, description="Hex end address (exclusive, max 64 MiB range).")],
        database: Database = None,
    ) -> dict[str, Any]:
        """Schedules IDA auto-analysis for [start, end). Runs in the background."""
        return await call(database, "reanalyze_range", write=True, start=_optional_hex(start, "start"),
                          end=_optional_hex(end, "end"))

    # ------------------------------------------------------------ E/F. search & decode
    @mcp.tool(title="Decode instruction", annotations=READ_ONLY)
    async def ida_decode_instruction(
        address: Address,
        count: Annotated[int, Field(ge=1, le=200, description="Consecutive instructions to decode.")] = 1,
        database: Database = None,
    ) -> dict[str, Any]:
        """Structured decoding from IDA's processor module: mnemonic, size, bytes, operands (type,
        size, register, immediate value, memory address, base register, displacement), referenced
        addresses and control-flow class (call/return/jump/conditional_jump/indirect_jump/...)."""
        return await call(database, "decode_instruction", address=normalize_address(address), count=count)

    @mcp.tool(title="Search immediate value", annotations=READ_ONLY)
    async def ida_search_immediate(
        value: Annotated[int | str, Field(description='Value, e.g. 3735928559 or "0xDEADBEEF".')],
        start: HexAddr = None,
        end: HexAddr = None,
        max_results: MaxResults = 100,
        database: Database = None,
    ) -> dict[str, Any]:
        """Instructions with an immediate operand equal to `value`. Continue with start=next_start."""
        return await call(database, "search_immediate", value=_imm(value), start=_optional_hex(start, "start"),
                          end=_optional_hex(end, "end"), max_results=max_results)

    @mcp.tool(title="Search instructions", annotations=READ_ONLY)
    async def ida_search_instructions(
        mnemonic: Annotated[str | None, Field(max_length=32, description='e.g. "xor", "call", "rol".')] = None,
        operand_type: Literal["register", "memory", "phrase", "displacement", "immediate", "far_code",
                              "near_code"] | None = None,
        register: Annotated[str | None, Field(max_length=32, description='Register operand or base, e.g. "rcx".')] = None,
        immediate: Annotated[int | str | None, Field(description="Immediate operand value.")] = None,
        target: HexAddr = None,
        functions_only: bool = False,
        start: HexAddr = None,
        end: HexAddr = None,
        max_results: MaxResults = 100,
        database: Database = None,
    ) -> dict[str, Any]:
        """Finds instructions by mnemonic and/or operand criteria (decoded by IDA, not text
        matching). Filters combine with AND within one operand. Continue with start=next_start."""
        return await call(database, "search_instructions", mnemonic=mnemonic, operand_type=operand_type,
                          register=register, immediate=None if immediate is None else _imm(immediate),
                          target=_optional_hex(target, "target"), functions_only=functions_only,
                          start=_optional_hex(start, "start"), end=_optional_hex(end, "end"),
                          max_results=max_results)

    @mcp.tool(title="Search disassembly text", annotations=READ_ONLY)
    async def ida_search_disassembly(
        text: Annotated[str, Field(min_length=1, max_length=256, description="Substring of the listing line.")],
        case_sensitive: bool = False,
        code_only: bool = True,
        start: HexAddr = None,
        end: HexAddr = None,
        max_results: MaxResults = 100,
        database: Database = None,
    ) -> dict[str, Any]:
        """Substring search over rendered listing lines (names, operands, comments). Use
        ida_search_instructions for structured operand queries."""
        return await call(database, "search_disassembly", text=text, case_sensitive=case_sensitive,
                          code_only=code_only, start=_optional_hex(start, "start"), end=_optional_hex(end, "end"),
                          max_results=max_results)

    @mcp.tool(title="Search pointers to address", annotations=READ_ONLY)
    async def ida_search_pointers(
        target: Address,
        aligned_only: bool = True,
        start: HexAddr = None,
        end: HexAddr = None,
        max_results: MaxResults = 100,
        database: Database = None,
    ) -> dict[str, Any]:
        """Where `target` is stored as a pointer: offset references IDA recognised, plus raw
        pointer-sized values equal to it (e.g. vtables, callback tables)."""
        return await call(database, "search_pointers", target=normalize_address(target), aligned_only=aligned_only,
                          start=_optional_hex(start, "start"), end=_optional_hex(end, "end"),
                          max_results=max_results)

    # ------------------------------------------------------------ G/I. analysis
    @mcp.tool(title="Analyze function", annotations=READ_ONLY)
    async def ida_analyze_function(
        address: Address,
        detail: Literal["brief", "standard", "deep"] = "standard",
        database: Database = None,
    ) -> dict[str, Any]:
        """One-call function summary: size, prototype and calling convention, CFG metrics
        (blocks, edges, cyclomatic complexity, loops), callers, callees, imports, strings.
        standard adds arguments, globals, constants, stack frame, comments and a crypto heuristic;
        deep adds basic blocks, call sites and the mnemonic histogram. Lists are capped."""
        return await call(database, "analyze_function", timeout_ms=HEAVY_TIMEOUT_MS,
                          address=normalize_address(address), detail=detail)

    @mcp.tool(title="Function constants", annotations=READ_ONLY)
    async def ida_get_function_constants(
        address: Address,
        include_small: Annotated[bool, Field(description="Include values <= 0xFF.")] = False,
        limit: Limit = 200,
        database: Database = None,
    ) -> dict[str, Any]:
        """Immediate values used by a function (excluding values that are addresses), with use
        counts and sites; known algorithm constants are flagged as candidates."""
        return await call(database, "get_function_constants", address=normalize_address(address),
                          include_small=include_small, limit=limit)

    @mcp.tool(title="Find crypto constants", annotations=READ_ONLY)
    async def ida_find_crypto_constants(
        start: HexAddr = None,
        end: HexAddr = None,
        skip_tables: Annotated[bool, Field(description="Skip the data-table signature scan (when resuming).")] = False,
        max_results: MaxResults = 200,
        database: Database = None,
    ) -> dict[str, Any]:
        """Candidate cryptographic/hash/checksum code: known tables (AES S-boxes, CRC-32, SHA/MD5
        constants, Base64 alphabet, ...) and known immediates (MD5/SHA init, TEA delta, FNV,
        CRC polynomials, ...), grouped per function. Findings are candidates, not proof.
        Resume with start=next_start, skip_tables=true."""
        return await call(database, "find_crypto_constants", timeout_ms=HEAVY_TIMEOUT_MS,
                          start=_optional_hex(start, "start"), end=_optional_hex(end, "end"),
                          skip_tables=skip_tables, max_results=max_results)
