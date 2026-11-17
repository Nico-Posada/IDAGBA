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

    from idagba.rom import Image


@dataclass(frozen=True, slots=True)
class MemoryRegion:
    """Flat memory region with a half-open [start, end) address range."""

    name: str
    start: int
    end: int
    permissions: SegmentPermissions
    segment_class: PredefinedClass
    comment: str | None = None


def _regions(image: Image) -> list[MemoryRegion]:
    size = len(image.rom)
    rx = SegmentPermissions.READ | SegmentPermissions.EXEC
    rw = SegmentPermissions.READ | SegmentPermissions.WRITE
    code, data = PredefinedClass.CODE, PredefinedClass.DATA
    multiboot = f'Multiboot image occupies {MB_BASE:#010x}..{MB_BASE + size:#010x}; no cartridge ROM is mapped.'
    regions = [
        MemoryRegion('BIOS', 0, 0x4000, rx, code),
        MemoryRegion(
            'EWRAM', 0x02000000, 0x02040000, rw | SegmentPermissions.EXEC, data, multiboot if image.multiboot else None
        ),
        MemoryRegion('IWRAM', 0x03000000, 0x03008000, rw | SegmentPermissions.EXEC, data),
        # A static copy of the top of IWRAM, not an emulated mirror.
        MemoryRegion(
            'IWRAM_BIOS_MIRROR',
            0x03FFFF00,
            0x04000000,
            rw,
            data,
            'Static mirror of IWRAM 0x03007F00..0x03008000; IDB patches are not synchronized.',
        ),
        MemoryRegion('IO', 0x04000000, 0x04000804, rw, data),
        MemoryRegion('PALETTE', 0x05000000, 0x05000400, rw, data),
        MemoryRegion('VRAM', 0x06000000, 0x06018000, rw, data),
        MemoryRegion('OAM', 0x07000000, 0x07000400, rw, data),
    ]
    if not image.multiboot:
        static = f'Static view of ROM at {BASE:#010x}; IDB patches are not synchronized between views.'
        regions += (
            MemoryRegion('ROM' + suffix, view, view + size, rx, code, static if suffix else None)
            for view, suffix in image.views
        )
        # GBATEK: EEPROM answers anywhere above 0x0D000000 on carts up to 16 MiB, else at 0x0DFFFF00.
        eeprom = 0x0D000000 if size <= 0x01000000 else 0x0DFFFF00
        if 0x0C000000 + size <= eeprom:
            regions.append(
                MemoryRegion(
                    'EEPROM',
                    eeprom,
                    0x0E000000,
                    rw,
                    data,
                    'Serial EEPROM window, if the cart has one: bit 0 carries data and transfers '
                    'use DMA3 in 64-bit units. Not linear memory.',
                )
            )

    regions.append(
        MemoryRegion(
            'SAVE',
            0x0E000000,
            0x0E010000,
            rw,
            data,
            'Unknown SRAM/Flash bus window, not a detected chip size; serial EEPROM is not mapped here.',
        )
    )
    return regions


def _create(db: Database, region: MemoryRegion) -> None:
    flags = AddSegmentFlags.NOSREG | AddSegmentFlags.SPARSE | AddSegmentFlags.NOAA
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
    if region.comment:
        db.segments.set_comment(segment, region.comment, repeatable=True)


def map_image(db: Database, li: loader_input_t, image: Image) -> None:
    for region in _regions(image):
        _create(db, region)

    size = len(image.rom)
    for view, _ in image.views:
        # Only the image's own address is patchable; the wait-state views are static copies of the file.
        patchable = ida_loader.FILEREG_PATCHABLE if view == image.base else 0
        require(
            li.file2base(0, view, view + size, patchable),  # ty: ignore[invalid-argument-type]
            f'Cannot map image at {view:#x}',
        )
