"""Naming and typing primitives, hardware annotations and the load report.

Cartridges whose bytes 0xC4..0xC9 are zero get volatile GPIO port items.

Palette RAM is GBA_PALETTE, a named GBA_PaletteRAM struct containing 256-entry
BG_PALETTE and OBJ_PALETTE unsigned-short arrays. Colors use BGR555; BG entry 0
is the backdrop. Applying the type leaves all 0x400 bytes uninitialized and writable.
OAM is GBA_OAM, 128 GBA_OAMEntry records whose fourth halfwords form affine matrices.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_domain.comments import CommentKind
from ida_domain.names import SetNameFlags
from ida_domain.types import TypeApplyFlags

from idagba.crt0 import StartupRecovery, StartupRecoveryFailure
from idagba.errors import require
from idagba.hardware import HEADER_FIELDS, REGISTERS, WORKSPACE
from idagba.logging import log, warn

if TYPE_CHECKING:
    from ida_domain import Database

    from idagba.hardware import HardwareAnnotation
    from idagba.rom import HeaderFacts, Image


class Annotator:
    """Names, types and comments one image's database."""

    def __init__(self, db: Database, image: Image) -> None:
        self.db, self.image = db, image

    def name(self, ea: int, text: str) -> None:
        db = self.db
        existing = db.names.get_at(ea)
        if existing == text:
            return

        if existing and db.bytes.has_user_name_at(ea):
            warn(f'Retaining existing name {existing} at {ea:#x}; requested {text}')
            return

        require(db.names.set_name(ea, text, SetNameFlags.NOWARN), f'Cannot name {ea:#x} {text}')

    def comment(self, ea: int, text: str) -> None:
        require(self.db.comments.set_at(ea, text, CommentKind.REPEATABLE), f'Cannot annotate {ea:#x}')

    def data(self, ea: int, size: int, width: int, text: str, *, declaration: str | None = None) -> None:
        db = self.db
        create = {1: db.bytes.create_byte_at, 2: db.bytes.create_word_at, 4: db.bytes.create_dword_at}[width]
        require(create(ea, size // width), f'Cannot create {size}-byte data at {ea:#x}')
        if declaration:
            require(
                db.types.apply_declaration_at(ea, declaration, TypeApplyFlags.DEFINITE), f'Cannot apply type at {ea:#x}'
            )

        self.name(ea, text)

    def apply(self, annotation: HardwareAnnotation, base: int, suffix: str = '') -> None:
        """Create one table entry relative to base."""
        ea = base + annotation.offset
        self.data(ea, annotation.size, annotation.width, annotation.name + suffix, declaration=annotation.declaration)
        if annotation.comment:
            self.comment(ea, annotation.comment)

    def hardware(self) -> None:
        self._header()
        self._cartridge_ports()
        self._video_memory()
        self._io_registers()
        self._bios_workspace()

    def _header(self) -> None:
        rom, base = self.image.rom, self.image.base
        for view, suffix in self.image.views:
            for annotation in HEADER_FIELDS:
                self.apply(annotation, view, suffix)
                if annotation.declaration:
                    self.comment(
                        view + annotation.offset, repr(rom[annotation.offset : annotation.offset + annotation.size])
                    )

        if self.image.multiboot:
            for offset, field in ((0xC4, 'GBA_MB_BOOT_MODE'), (0xC5, 'GBA_MB_SLAVE_ID')):
                self.data(base + offset, 1, 1, field, declaration='volatile unsigned char value;')
                self.comment(base + offset, 'Multiboot header field; the BIOS overwrites it before entry')

    def _cartridge_ports(self) -> None:
        rom, base = self.image.rom, self.image.base
        # GBATEK: carts with the ROM-chip I/O port keep these six bytes zero-filled.
        if not self.image.multiboot and len(rom) >= 0xCA and not any(rom[0xC4:0xCA]):
            for offset, port, text in (
                (0xC4, 'GBA_GPIO_DATA', 'Cartridge I/O port data, bits 0..3 (RTC/solar/gyro/rumble on some carts)'),
                (0xC6, 'GBA_GPIO_DIRECTION', 'Cartridge I/O port direction, bits 0..3 (0=input, 1=output)'),
                (0xC8, 'GBA_GPIO_CONTROL', 'Cartridge I/O port control: bit 0 enables reads (0=write-only)'),
            ):
                self.data(base + offset, 2, 2, port, declaration='volatile unsigned short value;')
                self.comment(base + offset, text)

        eeprom = self.db.segments.get_by_name('EEPROM')
        if eeprom:
            self.data(eeprom.start_ea, 2, 2, 'GBA_EEPROM', declaration='volatile unsigned short value;')

    def _video_memory(self) -> None:
        require(
            self.db.types.parse_declarations(
                None,  # ty: ignore[invalid-argument-type]  # None selects the database's local library
                'struct GBA_PaletteRAM { unsigned short BG_PALETTE[256]; unsigned short OBJ_PALETTE[256]; };'
                'struct GBA_OAMEntry'
                ' { unsigned short attr0; unsigned short attr1; unsigned short attr2; short affine; };'
                'struct GBA_OAM { struct GBA_OAMEntry obj[128]; };',
            )
            == 0,
            'Cannot define GBA palette/OAM types',
        )
        self.data(0x05000000, 0x400, 2, 'GBA_PALETTE', declaration='struct GBA_PaletteRAM value;')
        self.comment(
            0x05000000,
            'BGR555 colors: bits 0..4 red, 5..9 green, 10..14 blue; bit 15 unused. '
            'BG palette entry 0 is the backdrop color; OBJ palette starts at 0x05000200.',
        )
        self.data(0x07000000, 0x400, 2, 'GBA_OAM', declaration='struct GBA_OAM value;')
        self.comment(
            0x07000000,
            'OBJ attributes 0..2 per entry; the affine halfwords of entries 4n..4n+3 form '
            'matrix n (PA, PB, PC, PD; signed 8.8 fixed point).',
        )

    def _io_registers(self) -> None:
        scalar = {1: 'unsigned char', 2: 'unsigned short', 4: 'unsigned int'}
        for register in REGISTERS:
            ea = 0x04000000 + register.offset
            array = f'[{register.count}]' if register.count > 1 else ''
            declaration = f'volatile {scalar[register.width]} value{array};'
            self.data(ea, register.width * register.count, register.width, register.name, declaration=declaration)
            self.comment(ea, register.access_description)

    def _bios_workspace(self) -> None:
        for workspace_base, suffix in ((0x03000000, ''), (0x03FF8000, '_MIRROR')):
            for annotation in WORKSPACE:
                self.apply(annotation, workspace_base, suffix)

        for address, text in (
            (0x03007F00, 'BIOS default IRQ stack area, 160 bytes (SP_irq starts at 0x03007FA0)'),
            (0x03007FA0, 'BIOS default supervisor stack area, 64 bytes (SP_svc starts at 0x03007FE0)'),
            (0x03007FE0, 'BIOS reserved area, 16 bytes'),
            (0x03007FF4, 'BIOS reserved area, 4 bytes'),
        ):
            self.comment(address, text)

    def report(self, facts: HeaderFacts, recovery: StartupRecovery | StartupRecoveryFailure) -> None:
        base = self.image.base
        kind = 'multiboot image' if self.image.multiboot else 'cartridge'
        lines = [
            f'GBA {kind}: {facts.size} bytes at {base:#010x}',
            f'Title={facts.title!r}, game={facts.game_code!r}, maker={facts.maker!r}',
            f'Unit={facts.unit:#x}, device={facts.device:#x}, version={facts.version}',
            f'Entry word={facts.entry_word:#010x}, logo valid={facts.logo_valid}, fixed={facts.fixed:#04x}',
            f'Reserved1={facts.reserved1!r}, reserved2={facts.reserved2!r}',
            f'Checksum stored={facts.checksum_stored:#04x}, computed={facts.checksum_computed:#04x}',
            'Save SDK clues (advisory only): ' + (', '.join(facts.save_markers) or 'none'),
        ]
        lines += ['Warning: ' + warning for warning in facts.warnings]
        if isinstance(recovery, StartupRecoveryFailure):
            lines.append('Startup recovery not applied: ' + recovery.reason)
        else:
            lines.append(f'Stock devkitARM startup at {recovery.start:#010x}')
            lines.extend(
                f'{copy.name}: {copy.source:#010x} -> {copy.destination:#010x}, {copy.size:#x} bytes'
                for copy in recovery.copies
            )
            lines.append(f'Code pointers: constructors={recovery.constructors:#010x}, main={recovery.main:#010x}')
            lines.extend(note.text for note in recovery.notes)

        self.comment(base, '\n'.join(lines))
        for line in lines:
            log(line)
