"""The GBA memory map as IDA segments, with the image file mapped into it."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

import ida_loader
from ida_domain.segments import AddressingMode, AddSegmentFlags, PredefinedClass, SegmentPermissions

from idagba import hardware as hw
from idagba.errors import LoadError, require

if TYPE_CHECKING:
    from ida_domain import Database
    from ida_idaapi import loader_input_t

    from idagba.rom import Image


@dataclass(frozen=True, slots=True)
class MemoryRegion:
    """One memory region, created as an IDA segment."""

    name: str
    start: int
    size: int
    permissions: SegmentPermissions
    segment_class: PredefinedClass
    comment: str | None = None

    @property
    def end(self) -> int:
        return self.start + self.size


RX = SegmentPermissions.READ | SegmentPermissions.EXEC
RW = SegmentPermissions.READ | SegmentPermissions.WRITE
RWX = RW | SegmentPermissions.EXEC
CODE = PredefinedClass.CODE
DATA = PredefinedClass.DATA

# The regions every image has.
REGIONS = (
    MemoryRegion('BIOS', hw.BASE_BIOS, hw.SIZE_BIOS, RX, CODE),
    MemoryRegion('EWRAM', hw.BASE_EWRAM, hw.SIZE_EWRAM, RWX, DATA),
    MemoryRegion('IWRAM', hw.BASE_IWRAM, hw.SIZE_IWRAM, RWX, DATA),
    MemoryRegion('IWRAM_BIOS_MIRROR', hw.BASE_IO - 0x100, 0x100, RW, DATA, 'Static copy of the end of IWRAM.'),
    # 0x804 instead of 0x400 so the segment includes REG_MEMCNT at 0x800.
    MemoryRegion('IO', hw.BASE_IO, 0x804, RW, DATA),
    MemoryRegion('PALETTE', hw.BASE_PALETTE_RAM, hw.SIZE_PALETTE_RAM, RW, DATA),
    MemoryRegion('VRAM', hw.BASE_VRAM, hw.SIZE_VRAM, RW, DATA),
    MemoryRegion('OAM', hw.BASE_OAM, hw.SIZE_OAM, RW, DATA),
)
SAVE = MemoryRegion(
    'SAVE', hw.BASE_SRAM, 0x10000, RW, DATA, 'SRAM or Flash, if the cart has one. The chip is not detected.'
)

# A cartridge up to 16 MiB shows its EEPROM in this whole region, a larger one only in the last 0x100 bytes
# https://mgba-emu.github.io/gbatek/#gbacartbackupeeprom
EEPROM = MemoryRegion(
    'EEPROM',
    hw.BASE_ROM2_EX,
    hw.BASE_SRAM - hw.BASE_ROM2_EX,
    RW,
    DATA,
    'Serial EEPROM port, if the cart has one.',
)
EEPROM_LARGE_ROM = replace(EEPROM, start=hw.BASE_SRAM - 0x100, size=0x100)


def map_image(db: Database, li: loader_input_t, image: Image) -> None:
    for region in _regions(image):
        _create(db, region)

    size = len(image.rom)
    for view, _ in image.views:
        # Patches apply at the load address only; the other views are static copies.
        patchable = ida_loader.FILEREG_PATCHABLE if view == image.base else 0
        require(
            li.file2base(0, view, view + size, patchable),  # ty: ignore[invalid-argument-type]
            f'Cannot map image at {view:#x}',
        )


def _regions(image: Image) -> list[MemoryRegion]:
    regions = [*REGIONS]
    if not image.multiboot:
        size = len(image.rom)
        note = f'Static copy of ROM at {hw.BASE_ROM0:#010x}.'

        # The static copies are DATA so that FLIRT, which scans CODE segments for library code, leaves them alone.
        regions += (
            MemoryRegion('ROM' + suffix, view, size, RX, DATA if suffix else CODE, note if suffix else None)
            for view, suffix in image.views
        )

        # The EEPROM gets the first of its two places that the last ROM view leaves free.
        for eeprom in (EEPROM, EEPROM_LARGE_ROM):
            if hw.BASE_ROM2 + size <= eeprom.start:
                regions.append(eeprom)
                break

    regions.append(SAVE)
    return regions


def _create(db: Database, region: MemoryRegion) -> None:
    flags = AddSegmentFlags.NOSREG | AddSegmentFlags.SPARSE | AddSegmentFlags.NOAA
    segment = db.segments.add(0, region.start, region.end, region.name, region.segment_class, flags)
    if segment is None:
        msg = f'Cannot create segment {region.name}'
        raise LoadError(msg)

    # Setting the addressing mode makes IDA analyze the segment, so skip it when it is already 32-bit.
    if db.segments.get_bitness(segment) != 32:
        db.segments.set_addressing_mode(segment, AddressingMode.BIT32)

    # set_permissions only changes the object; update() saves it.
    db.segments.set_permissions(segment, region.permissions)
    segment.update()
    if region.comment:
        db.segments.set_comment(segment, region.comment, repeatable=True)

    _check(db, region)


def _check(db: Database, region: MemoryRegion) -> None:
    """Raise unless the database holds the segment exactly as the region describes it."""
    segment = db.segments.get_at(region.start)
    require(
        segment is not None
        and segment.start_ea == region.start
        and segment.end_ea == region.end
        and segment.perm == region.permissions
        and db.segments.get_class(segment) == region.segment_class.value
        and db.segments.get_bitness(segment) == 32,
        f'Segment {region.name} does not have the required extent, permissions, class, or bitness',
    )


__all__ = ['MemoryRegion', 'map_image']
