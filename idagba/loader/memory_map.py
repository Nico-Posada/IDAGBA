"""GBA address space: segments, static ROM views and file mapping.

ROM wait-state views are static: IDB patches are not synchronized. The EEPROM
window is mapped at 0x0D000000 for carts up to 16 MiB, otherwise at 0x0DFFFF00
when the ROM leaves room.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import ida_loader
from ida_domain.segments import AddressingMode, AddSegmentFlags, PredefinedClass, SegmentPermissions

from idagba.errors import LoadError, require
from idagba.rom import BASE, MB_BASE

if TYPE_CHECKING:
    from ida_domain import Database
    from ida_idaapi import loader_input_t
    from ida_segment import segment_t


@dataclass(frozen=True, slots=True)
class MemoryRegion:
    """Flat memory region with a half-open [start, end) address range."""

    name: str
    start: int
    end: int
    permissions: SegmentPermissions
    segment_class: PredefinedClass


def _segment(db: Database, ea: int) -> segment_t:
    segment = db.segments.get_at(ea)
    if segment is None:
        msg = f'No segment at {ea:#x}'
        raise LoadError(msg)

    return segment


def map_image(db: Database, li: loader_input_t, size: int, base: int) -> None:
    rx = SegmentPermissions.READ | SegmentPermissions.EXEC
    rw = SegmentPermissions.READ | SegmentPermissions.WRITE
    code, data = PredefinedClass.CODE, PredefinedClass.DATA
    cartridge = base == BASE
    regions = [
        MemoryRegion('BIOS', 0, 0x4000, rx, code),
        MemoryRegion('EWRAM', 0x02000000, 0x02040000, rw | SegmentPermissions.EXEC, data),
        MemoryRegion('IWRAM', 0x03000000, 0x03008000, rw | SegmentPermissions.EXEC, data),
        MemoryRegion('IWRAM_BIOS_MIRROR', 0x03FFFF00, 0x04000000, rw, data),
        MemoryRegion('IO', 0x04000000, 0x04000804, rw, data),
        MemoryRegion('PALETTE', 0x05000000, 0x05000400, rw, data),
        MemoryRegion('VRAM', 0x06000000, 0x06018000, rw, data),
        MemoryRegion('OAM', 0x07000000, 0x07000400, rw, data),
    ]
    # GBATEK: EEPROM answers anywhere above 0x0D000000 on carts up to 16 MiB, else at 0x0DFFFF00.
    eeprom = 0x0D000000 if size <= 0x01000000 else 0x0DFFFF00
    if cartridge:
        regions += (
            MemoryRegion('ROM', BASE, BASE + size, rx, code),
            MemoryRegion('ROM_WS1', 0x0A000000, 0x0A000000 + size, rx, code),
            MemoryRegion('ROM_WS2', 0x0C000000, 0x0C000000 + size, rx, code),
        )
        if 0x0C000000 + size <= eeprom:
            regions.append(MemoryRegion('EEPROM', eeprom, 0x0E000000, rw, data))
    regions.append(MemoryRegion('SAVE', 0x0E000000, 0x0E010000, rw, data))
    flags = AddSegmentFlags.NOSREG | AddSegmentFlags.SPARSE | AddSegmentFlags.NOAA
    for region in regions:
        segment = db.segments.add(0, region.start, region.end, region.name, region.segment_class, flags)
        if segment is None:
            msg = f'Cannot create segment {region.name}'
            raise LoadError(msg)

        # Changing addressing re-plans the whole segment for analysis, which would analyze the NOAA ROM views.
        if db.segments.get_bitness(segment) != 32:
            db.segments.set_addressing_mode(segment, AddressingMode.BIT32)
        db.segments.set_permissions(segment, region.permissions)
        # ida_domain assigns perm on the kernel object without committing it; the SDK requires update() after that.
        segment.update()
        actual = db.segments.get_at(region.start)
        require(
            actual is not None
            and actual.start_ea == region.start
            and actual.end_ea == region.end
            and actual.perm == region.permissions
            and db.segments.get_class(actual) == region.segment_class.value
            and db.segments.get_bitness(actual) == 32,
            f'Segment {region.name} does not have the required extent, permissions, class, or bitness',
        )

    if cartridge:
        for view in (BASE, 0x0A000000, 0x0C000000):
            require(
                li.file2base(0, view, view + size, ida_loader.FILEREG_PATCHABLE if view == BASE else 0),  # ty: ignore[invalid-argument-type]
                f'Cannot map ROM view at {view:#x}',
            )
            if view != BASE:
                db.segments.set_comment(
                    _segment(db, view),
                    f'Static view of ROM at {BASE:#010x}; IDB patches are not synchronized between views.',
                    repeatable=True,
                )

        eeprom_segment = db.segments.get_by_name('EEPROM')
        if eeprom_segment:
            db.segments.set_comment(
                eeprom_segment,
                'Serial EEPROM window, if the cart has one: bit 0 carries data and transfers '
                'use DMA3 in 64-bit units. Not linear memory.',
                repeatable=True,
            )
    else:
        require(
            li.file2base(0, MB_BASE, MB_BASE + size, ida_loader.FILEREG_PATCHABLE),  # ty: ignore[invalid-argument-type]
            f'Cannot map multiboot image at {MB_BASE:#x}',
        )
        db.segments.set_comment(
            _segment(db, MB_BASE),
            f'Multiboot image occupies {MB_BASE:#010x}..{MB_BASE + size:#010x}; no cartridge ROM is mapped.',
            repeatable=True,
        )

    # ponytail: explicit static views, not mirror/bank emulation; add validated views only when needed.
    db.segments.set_comment(
        _segment(db, 0x03FFFF00),
        'Static mirror of IWRAM 0x03007F00..0x03008000; IDB patches are not synchronized.',
        repeatable=True,
    )
    db.segments.set_comment(
        _segment(db, 0x0E000000),
        'Unknown SRAM/Flash bus window, not a detected chip size; serial EEPROM is not mapped here.',
        repeatable=True,
    )
