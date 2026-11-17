"""Load synthetic and real images through the installed plugin and loader on idalib."""

from __future__ import annotations

import idalib_session

idalib_session.start()

import hashlib
import os
import struct
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import ida_domain
import ida_frame
import ida_ida
import ida_idp
import ida_segment
import ida_segregs
import pytest
from ida_domain import Database
from ida_domain.base import DatabaseError
from ida_domain.comments import CommentKind
from ida_domain.database import IdaCommandOptions
from ida_domain.pseudocode import PseudocodeExpression, PseudocodeFunction, PseudocodeInstruction
from ida_domain.pseudocode import PseudocodeExpressionOp as Op
from ida_domain.pseudocode import PseudocodeInstructionOp as InsnOp
from ida_domain.segments import SegmentPermissions
from ida_domain.types import TypeAttr
from ida_domain.xrefs import XrefType
from packaging.version import Version
from roms import (
    BASE,
    FORMAT,
    MB_BASE,
    REAL_SHA256,
    THUMB_TEMPLATE_NO_RESET,
    make_indirect,
    make_large,
    make_long_jump,
    make_multiboot,
    make_palette,
    make_synthetic,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterator
    from contextlib import AbstractContextManager

    from ida_segment import segment_t

    Loader = Callable[..., AbstractContextManager[Database]]

REAL_ROM = Path(os.environ.get('IDAGBA_REAL_ROM', idalib_session.PACKAGE_ROOT.parent / 'danteInferno.gba'))
VCOUNT = 0x04000006


@pytest.fixture
def load(tmp_path: Path) -> Loader:
    """Open ROM bytes through the installed loader; yields the Database once analysis has settled."""

    @contextmanager
    def _load(name: str, data: bytes, file_type: str | None = FORMAT) -> Generator[Database, None, None]:
        if file_type and ida_domain.__ida_version__ < Version('9.2'):
            pytest.skip('idalib before IDA 9.2 exits on the -T switch that selects a loader')

        source = tmp_path / f'{name}.gba'
        source.write_bytes(data)
        log = tmp_path / f'{name}.log'
        options = IdaCommandOptions(
            auto_analysis=True,
            output_database=str(tmp_path / f'{name}.i64'),
            log_file=str(log),
            file_type=file_type,
        )
        try:
            db = Database.open(str(source), args=options, save_on_close=False)
        except DatabaseError as exc:
            pytest.fail(f'{exc}\nIDA log:\n{log.read_text(errors="replace") if log.exists() else ""}')

        with db:
            db.auto_analysis.wait()
            yield db

    return _load


def segment(db: Database, ea: int, name: str, start: int, end: int) -> segment_t:
    found = db.segments.get_at(ea)
    assert found is not None
    assert (found.start_ea, found.end_ea) == (start, end)
    assert db.segments.get_name(found) == name
    return found


def bytes_at(db: Database, ea: int, size: int) -> bytes:
    data = db.bytes.get_bytes_at(ea, size)
    assert data is not None
    assert len(data) == size
    return data


def named(db: Database, ea: int, expected: str) -> None:
    assert db.names.get_at(ea) == expected, (hex(ea), db.names.get_at(ea), expected)


def unloaded(db: Database, ea: int) -> bool:
    return not db.is_valid_ea(ea) or not db.bytes.is_value_initialized_at(ea)


def regular_comment(db: Database, ea: int) -> str | None:
    info = db.comments.get_at(ea)
    return info.comment if info else None


def repeatable_comment(db: Database, ea: int) -> str:
    info = db.comments.get_at(ea, CommentKind.REPEATABLE)
    if info:
        return info.comment

    function = db.functions.get_at(ea)
    return db.functions.get_comment(function, repeatable=True) if function else ''


def has_xref(db: Database, source: int, destination: int, kind: XrefType | None = None) -> bool:
    return any(xref.from_ea == source and (kind is None or xref.type == kind) for xref in db.xrefs.to_ea(destination))


def thumb(ea: int) -> int:
    return ida_segregs.get_sreg(ea, ida_idp.str2reg('T'))


def function_start(db: Database, ea: int) -> int | None:
    function = db.functions.get_at(ea)
    return function.start_ea if function else None


def type_text(db: Database, ea: int) -> str:
    applied = db.types.get_at(ea)
    assert applied is not None, hex(ea)
    return str(applied)


def show_instructions(db: Database, *addresses: int) -> None:
    for ea in addresses:
        assert db.bytes.get_disassembly_at(ea), hex(ea)


def check_entry(db: Database, *, multiboot: bool = False) -> None:
    entry = MB_BASE + 0xC0 if multiboot else BASE
    named(db, entry, 'GBA_MB_ENTRY' if multiboot else 'GBA_ROM_ENTRY')
    assert thumb(entry) == 0


def subexpressions(expr: PseudocodeExpression) -> Iterator[PseudocodeExpression]:
    yield expr
    for child in (expr.x, expr.y, expr.z):
        if child is not None:
            yield from subexpressions(child)

    for arg in expr.call_args or ():
        yield from subexpressions(arg.expression)


def contains_object(item: PseudocodeExpression | PseudocodeInstruction, address: int) -> bool:
    expressions = subexpressions(item) if isinstance(item, PseudocodeExpression) else item.walk_expressions()
    return any(expr.obj_ea == address for expr in expressions)


def hardware_loop(cfunc: PseudocodeFunction) -> bool:
    """Some loop re-reads VCOUNT in its condition, directly or through a variable loaded in its body."""
    for loop in cfunc.find_loops():
        details = loop.while_details or loop.do_details or loop.for_details
        assert details is not None
        used = {expr.variable_index for expr in subexpressions(details.condition) if expr.op == Op.VAR}
        loaded = {
            expr.x.variable_index
            for expr in details.body.walk_expressions()
            if expr.op == Op.ASG
            and expr.x is not None
            and expr.x.op == Op.VAR
            and expr.y is not None
            and contains_object(expr.y, VCOUNT)
        }
        if contains_object(details.condition, VCOUNT) or used & loaded:
            return True

    return False


def ram_write(cfunc: PseudocodeFunction, address: int) -> bool:
    return any(
        expr.op in (Op.ASG, Op.ASG_ADD, Op.PREINC, Op.POSTINC)
        and expr.x is not None
        and contains_object(expr.x, address)
        for expr in cfunc.walk_expressions()
    )


def palette_writes(cfunc: PseudocodeFunction) -> dict[tuple[int | None, int], int]:
    writes = {}
    for expr in cfunc.walk_expressions():
        target, value = expr.x, expr.y
        if expr.op != Op.ASG or target is None or value is None or target.op != Op.IDX:
            continue

        member, index = target.x, target.y
        if member is None or index is None or member.op != Op.MEMREF or member.x is None:
            continue

        if member.x.obj_ea == 0x05000000 and index.number is not None and value.number is not None:
            writes[member.member_offset, index.number.value] = value.number.value

    return writes


def helper_calls(cfunc: PseudocodeFunction) -> tuple[list[tuple[str | None, int]], int]:
    calls = [
        (expr.x.helper_name, len(expr.call_args or ()))
        for expr in cfunc.walk_expressions()
        if expr.op == Op.CALL and expr.x is not None and expr.x.op == Op.HELPER
    ]
    return calls, sum(insn.op == InsnOp.ASM for insn in cfunc.walk_instructions())


@pytest.mark.parametrize('file_type', [FORMAT, None], ids=['explicit', 'auto'])
def test_synthetic(load: Loader, file_type: str | None):
    original, _ = make_synthetic()
    with load('synthetic', original, file_type) as db:
        check_entry(db)
        size = 0x1000
        for base, name in ((0x08000000, 'ROM'), (0x0A000000, 'ROM_WS1'), (0x0C000000, 'ROM_WS2')):
            segment(db, base, name, base, base + size)

        for ea, name, start, end in (
            (0, 'BIOS', 0, 0x4000),
            (0x02000000, 'EWRAM', 0x02000000, 0x02040000),
            (0x03000000, 'IWRAM', 0x03000000, 0x03008000),
            (0x03FFFF00, 'IWRAM_BIOS_MIRROR', 0x03FFFF00, 0x04000000),
            (0x04000000, 'IO', 0x04000000, 0x04000804),
            (0x05000000, 'PALETTE', 0x05000000, 0x05000400),
            (0x06000000, 'VRAM', 0x06000000, 0x06018000),
            (0x07000000, 'OAM', 0x07000000, 0x07000400),
            (0x0E000000, 'SAVE', 0x0E000000, 0x0E010000),
        ):
            segment(db, ea, name, start, end)

        assert ida_ida.inf_get_start_ea() == BASE
        assert db.start_ip == BASE
        rx = SegmentPermissions.READ | SegmentPermissions.EXEC
        rw = SegmentPermissions.READ | SegmentPermissions.WRITE
        for ea, permissions, kind in (
            (BASE, rx, ida_segment.SEG_CODE),
            (0x02000000, rw | SegmentPermissions.EXEC, ida_segment.SEG_DATA),
            (0x04000000, rw, ida_segment.SEG_DATA),
            (0, rx, ida_segment.SEG_CODE),
            (0x0E000000, rw, ida_segment.SEG_DATA),
        ):
            found = db.segments.get_at(ea)
            assert found is not None
            assert found.perm == permissions, hex(ea)
            assert found.type == kind, hex(ea)

        show_instructions(db, BASE, 0x08000220, 0x08000240, 0x08000268, 0x08000700, 0x03000100)
        assert bytes_at(db, BASE, size) == original
        assert bytes_at(db, 0x0A000000, size) == original
        assert bytes_at(db, 0x0C000000, size) == original
        assert unloaded(db, BASE + size)
        assert unloaded(db, 0x0A000000 + size)
        assert bytes_at(db, 0x03000100, 8) == original[0x800:0x808]
        assert bytes_at(db, 0x03002000, 12) == original[0x840:0x84C]
        assert bytes_at(db, 0x02000100, 8) == original[0x860:0x868]
        assert bytes_at(db, 0x03002100, 8) == original[0x870:0x878]
        assert db.bytes.is_code_at(0x03000100)
        for ea in (0x03001000, 0x02001000, 0x04000010, 0x0E000000, 0, 0x05000000, 0x06000000, 0x07000000):
            assert unloaded(db, ea), hex(ea)

        assert not db.bytes.is_code_at(BASE + 4)
        assert not db.bytes.is_code_at(BASE + 0x800)
        assert not db.bytes.is_code_at(0x03002004), 'Prologue-looking data became code'
        for offset, suffix, item_size in (
            (0x04, 'LOGO', 156),
            (0xA0, 'TITLE', 12),
            (0xAC, 'GAME_CODE', 4),
            (0xB0, 'MAKER_CODE', 2),
            (0xB2, 'FIXED', 1),
            (0xB3, 'UNIT_CODE', 1),
            (0xB4, 'DEVICE_TYPE', 1),
            (0xB5, 'RESERVED1', 7),
            (0xBC, 'VERSION', 1),
            (0xBD, 'CHECKSUM', 1),
            (0xBE, 'RESERVED2', 2),
        ):
            named(db, BASE + offset, 'GBA_HDR_' + suffix)
            assert db.bytes.get_data_size_at(BASE + offset) == item_size

        named(db, 0x0A000000 + 0xA0, 'GBA_HDR_TITLE_WS1')
        for source, destination, lma_name in (
            (0x08000800, 0x03000100, 'GBA_DATA_LMA'),
            (0x08000840, 0x03002000, 'GBA_IWRAM_LMA'),
            (0x08000860, 0x02000100, 'GBA_EWRAM_LMA'),
            (0x08000870, 0x03002100, 'GBA_IWRAM0_LMA'),
        ):
            named(db, source, lma_name)
            for address in (source, destination):
                provenance = repeatable_comment(db, address)
                assert f'{source:#010x}' in provenance
                assert f'{destination:#010x}' in provenance

        named(db, 0x0C000000 + 0xA0, 'GBA_HDR_TITLE_WS2')
        assert db.functions.get_at(0x0A000000) is None
        assert db.functions.get_at(0x0C000000) is None
        assert not any(0x0A000000 <= f.start_ea < 0x0E000000 for f in db.functions.get_all()), 'ROM views analyzed'

        for ea, name in (
            (0x08000220, 'GBA_STARTUP'),
            (0x08000700, 'main'),
            (0x080002E8, 'GBA_ClearMem'),
            (0x080002FA, 'GBA_BxR3'),
            (0x08000780, '__libc_init_array'),
            (0x080002FC, 'GBA_CopyMemChk'),
            (0x080002FE, 'GBA_CopyMem'),
        ):
            named(db, ea, name)

        assert thumb(0x08000240) == 0
        assert thumb(0x08000268) == 1
        for ea in (0x080002E8, 0x080002FA, 0x080002FC):
            assert thumb(ea) == 1
            assert function_start(db, ea) == ea

        assert thumb(0x08000700) == 1
        assert thumb(0x08000780) == 1
        assert thumb(0x03000100) == 0
        assert db.functions.get_at(0x08000700) is not None
        assert function_start(db, 0x080002FC) == 0x080002FC
        assert function_start(db, 0x080002FE) == 0x080002FC
        assert db.functions.get_at(0x03000100) is not None
        assert has_xref(db, 0x080002D8, 0x08000780)
        assert has_xref(db, 0x080002E2, 0x08000700)
        assert has_xref(db, 0x08000720, 0x03000100)
        assert has_xref(db, 0x08000730, 0x0A000880)

        for ea, name, item_size in (
            (0x04000006, 'REG_VCOUNT', 2),
            (0x04000084, 'REG_SOUNDCNT_X', 2),
            (0x04000090, 'REG_WAVE_RAM', 16),
            (0x040000A0, 'REG_FIFO_A', 4),
            (0x040000A4, 'REG_FIFO_B', 4),
            (0x04000120, 'REG_SIOMULTI0', 2),
            (0x04000122, 'REG_SIOMULTI1', 2),
            (0x0400012A, 'REG_SIOMLT_SEND', 2),
            (0x04000300, 'REG_POSTFLG', 1),
            (0x04000301, 'REG_HALTCNT', 1),
            (0x04000800, 'REG_MEMCNT', 4),
        ):
            named(db, ea, name)
            assert db.bytes.get_data_size_at(ea) == item_size, (name, db.bytes.get_data_size_at(ea))

        assert 'volatile' in type_text(db, 0x04000090)
        assert 'volatile' in type_text(db, 0x04000006)
        for ea, name, item_size in (
            (0x03007FF0, 'GBA_SOUND_BUFFER', 4),
            (0x03007FF8, 'GBA_IRQ_FLAGS', 2),
            (0x03007FFA, 'GBA_SOFT_RESET_FLAG', 1),
            (0x03007FFC, 'GBA_IRQ_HANDLER', 4),
            (0x03FFFFF0, 'GBA_SOUND_BUFFER_MIRROR', 4),
            (0x03FFFFF8, 'GBA_IRQ_FLAGS_MIRROR', 2),
            (0x03FFFFFA, 'GBA_SOFT_RESET_FLAG_MIRROR', 1),
            (0x03FFFFFC, 'GBA_IRQ_HANDLER_MIRROR', 4),
        ):
            named(db, ea, name)
            assert db.bytes.get_data_size_at(ea) == item_size

        irq_type = type_text(db, 0x03007FFC)
        assert 'volatile' in irq_type
        assert '(' in irq_type
        for ea, name in (
            (0x080000C4, 'GBA_GPIO_DATA'),
            (0x080000C6, 'GBA_GPIO_DIRECTION'),
            (0x080000C8, 'GBA_GPIO_CONTROL'),
            (0x0D000000, 'GBA_EEPROM'),
        ):
            named(db, ea, name)
            assert db.bytes.get_data_size_at(ea) == 2
            assert 'volatile' in type_text(db, ea)

        segment(db, 0x0D000000, 'EEPROM', 0x0D000000, 0x0E000000)
        named(db, 0x07000000, 'GBA_OAM')
        assert db.heads.bounds(0x07000000)[1] == 0x07000400
        assert regular_comment(db, 0x080002E6) == 'BIOS SWI 0x00 SoftReset'

        main = db.pseudocode.decompile(0x08000700)
        db.pseudocode.decompile(0x03000100)
        assert hardware_loop(main), 'Loop no longer polls VCOUNT on each iteration'
        assert ram_write(main, 0x03002000), 'Initialized RAM was incorrectly folded as constant'


def test_crt0_without_soft_reset(load: Loader):
    rom, _ = make_synthetic(THUMB_TEMPLATE_NO_RESET)
    with load('no_reset', rom) as db:
        for ea, name in (
            (0x08000700, 'main'),
            (0x080002E6, 'GBA_ClearMem'),
            (0x080002F8, 'GBA_BxR3'),
            (0x080002FA, 'GBA_CopyMemChk'),
            (0x080002FC, 'GBA_CopyMem'),
        ):
            named(db, ea, name)

        for ea in (0x080002E6, 0x080002F8, 0x080002FA):
            assert thumb(ea) == 1
            assert function_start(db, ea) == ea

        assert function_start(db, 0x080002FC) == 0x080002FA
        assert has_xref(db, 0x080002E2, 0x08000700)


def test_palette(load: Loader):
    with load('palette', make_palette()) as db:
        check_entry(db)
        palette = db.types.get_by_name('GBA_PaletteRAM')
        assert palette is not None
        assert db.types.get_details(palette).size == 0x400
        # Inspect each member while the generator still owns the udt_type_data_t its tinfo_t points into.
        members = []
        for member in db.types.get_udt_members(palette):
            element = db.types.get_array_element_type(member.type)
            unsigned16 = element is not None and TypeAttr.UINT16 in db.types.get_details(element).attributes
            members.append((member.name, member.offset, db.types.get_array_length(member.type), unsigned16))

        assert members == [('BG_PALETTE', 0, 256, True), ('OBJ_PALETTE', 0x200, 256, True)]

        named(db, 0x05000000, 'GBA_PALETTE')
        applied = db.types.get_at(0x05000000)
        assert applied is not None
        assert db.types.get_details(applied).name == 'GBA_PaletteRAM'
        assert db.heads.bounds(0x05000000)[1] == 0x05000400
        assert all(unloaded(db, ea) for ea in range(0x05000000, 0x05000400))
        found = db.segments.get_at(0x05000000)
        assert found is not None
        assert found.perm == SegmentPermissions.READ | SegmentPermissions.WRITE
        assert found.type == ida_segment.SEG_DATA
        writes = palette_writes(db.pseudocode.decompile(0x08000700))
        assert writes == {(0, 0): 20903, (0, 241): 0x7FFF, (0x200, 0): 0x7FFF, (0x200, 255): 0x7FFF}, writes


def test_thumb_long_jump(load: Loader):
    with load('long_jump', make_long_jump()) as db:
        check_entry(db)
        function = db.functions.get_at(0x08000F20)
        assert function is not None
        assert function.start_ea == 0x08000700
        assert ida_frame.get_spd(function, 0x08000F20) == -24
        assert has_xref(db, 0x08000708, 0x08000F20, XrefType.JUMP_NEAR)
        show_instructions(db, 0x08000700, 0x08000708, 0x08000F20)
        db.pseudocode.decompile(0x08000700)


def test_large(load: Loader):
    with load('large', make_large()) as db:
        check_entry(db)
        size = 0x01000004
        for base, name in ((0x08000000, 'ROM'), (0x0A000000, 'ROM_WS1'), (0x0C000000, 'ROM_WS2')):
            segment(db, base, name, base, base + size)
            assert bytes_at(db, base + size - 4, 4) == struct.pack('<I', 0xA55A3CC3)
            assert unloaded(db, base + size)

        segment(db, 0x0DFFFF00, 'EEPROM', 0x0DFFFF00, 0x0E000000)


def test_multiboot(load: Loader):
    image = make_multiboot()
    with load('multiboot', image, None) as db:
        check_entry(db, multiboot=True)
        assert not db.is_valid_ea(BASE)
        assert db.segments.get_by_name('EEPROM') is None
        assert ida_ida.inf_get_start_ea() == MB_BASE + 0xC0
        assert bytes_at(db, MB_BASE, 0x1000) == image
        named(db, MB_BASE + 0x220, 'GBA_STARTUP')
        named(db, MB_BASE + 0x700, 'main')
        assert thumb(MB_BASE + 0x700) == 1
        assert db.functions.get_at(MB_BASE + 0x700) is not None
        assert bytes_at(db, 0x03000100, 8) == image[0x800:0x808]
        assert has_xref(db, MB_BASE + 0x720, 0x03000100)
        named(db, MB_BASE + 0xC4, 'GBA_MB_BOOT_MODE')
        assert 'volatile' in type_text(db, MB_BASE + 0xC4)
        show_instructions(db, MB_BASE + 0xC0, MB_BASE + 0x240, MB_BASE + 0x700)


def test_indirect(load: Loader):
    with load('indirect', make_indirect()) as db:
        check_entry(db)
        show_instructions(db, 0x08000700, 0x08000714, 0x08000718, 0x08000900, 0x08000940)
        assert thumb(0x08000700) == 0
        assert function_start(db, 0x08000700) == 0x08000700
        assert has_xref(db, 0x08000714, 0x08000940, XrefType.CALL_NEAR)
        assert thumb(0x08000940) == 1
        assert function_start(db, 0x08000940) == 0x08000940
        named(db, 0x08000900, 'GBA_IrqMain')
        assert thumb(0x08000900) == 0
        assert function_start(db, 0x08000900) == 0x08000900
        assert has_xref(db, 0x08000708, 0x08000900)
        assert regular_comment(db, 0x08000718) == 'BIOS SWI 0x05 VBlankIntrWait'

        # The plugin installs the lifter; BIOS calls must be helper calls, not __asm.
        # The remainder comes back in R1, the high half of SWI_Div's R1:R0 result.
        for ea, expected in (
            (0x08000700, [('SWI_VBlankIntrWait', 0)]),
            (0x08000940, [('SWI_Div', 2), ('HIDWORD', 1)]),
        ):
            calls, asm = helper_calls(db.pseudocode.decompile(ea))
            assert calls == expected, (hex(ea), calls)
            assert not asm, hex(ea)

        # Halt leaves every register unchanged, so r0 stays live from entry and remains an argument.
        ida_segregs.split_sreg_range(0x08000960, ida_idp.str2reg('T'), 1, ida_segregs.SR_user)
        assert db.functions.create(0x08000960)
        cfunc = db.pseudocode.decompile(0x08000960)
        calls, asm = helper_calls(cfunc)
        assert calls == [('SWI_Halt', 0)]
        assert not asm
        function_type = cfunc.get_func_type()
        assert function_type is not None
        assert db.types.get_func_argument_count(function_type) == 1, str(cfunc)


def test_real(load: Loader):
    if not REAL_ROM.is_file():
        pytest.skip(f'{REAL_ROM} is missing; set IDAGBA_REAL_ROM')

    source = REAL_ROM.read_bytes()
    assert hashlib.sha256(source).hexdigest() == REAL_SHA256
    with load('real', source) as db:
        check_entry(db)
        size = 170740
        for base, name in ((0x08000000, 'ROM'), (0x0A000000, 'ROM_WS1'), (0x0C000000, 'ROM_WS2')):
            segment(db, base, name, base, base + size)

        named(db, 0x080000C0, 'GBA_STARTUP')
        named(db, 0x08000870, 'main')
        named(db, 0x08012B20, '__libc_init_array')
        assert thumb(0x080000E0) == 0
        assert thumb(0x08000108) == 1
        assert thumb(0x08000870) == 1
        assert thumb(0x08012B20) == 1
        for interior in (0x08000952, 0x080009D6, 0x08000A3C, 0x08000B62):
            assert function_start(db, interior) == 0x08000870, hex(interior)

        assert has_xref(db, 0x08001302, 0x080009D6, XrefType.JUMP_NEAR)
        show_instructions(db, BASE, 0x080000C0, 0x080000E0, 0x08000108, 0x08000870, 0x030018DC)
        assert bytes_at(db, BASE, size) == source
        assert bytes_at(db, 0x03002A20, 12) == source[0x297BC:0x297C8]
        assert bytes_at(db, 0x03000000, 0x21B0) == source[0x2760C:0x297BC]
        assert bytes_at(db, 0x02000000, 0x324) == source[0x297C8:0x29AEC]
        assert unloaded(db, 0x030021B0)
        named(db, 0x03007FFC, 'GBA_IRQ_HANDLER')
        assert has_xref(db, 0x0801436C, 0x03007FFC)
        assert bytes_at(db, 0x030018DC, 2)
        assert db.functions.get_at(0x030018DC) is not None, 'no analyzed function at populated IWRAM 0x030018DC'
        assert has_xref(db, 0x08003C02, 0x08003C2C)
        assert has_xref(db, 0x08003C02, 0x030018DC)
        assert has_xref(db, 0x08003C24, 0x030018DC)
        entry_comment = repeatable_comment(db, BASE)
        for clue in ('ROM TITLE', 'SBTP', '27', 'SRAM_V113'):
            assert clue in entry_comment

        for ea in (0x08000870, 0x08012B20, 0x030018DC):
            db.pseudocode.decompile(ea)
