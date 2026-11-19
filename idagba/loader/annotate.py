"""Names, types and comments for the hardware, plus the load report."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ida_domain.comments import CommentKind
from ida_domain.names import SetNameFlags
from ida_domain.types import TypeApplyFlags

from idagba.crt0 import StartupRecovery, StartupRecoveryFailure
from idagba.errors import require
from idagba.hardware import (
    BASE_IO,
    BASE_IWRAM,
    BASE_IWRAM_MIRROR,
    BASE_OAM,
    BASE_PALETTE_RAM,
    HEADER_FIELDS,
    REGISTERS,
    SIZE_OAM,
    SIZE_PALETTE_RAM,
    WORKSPACE,
)
from idagba.logging import log, warn

if TYPE_CHECKING:
    from ida_domain import Database

    from idagba.hardware import HardwareAnnotation
    from idagba.rom import HeaderFacts, Image


class Annotator:
    """Names, types and comments things in the database of one image."""

    def __init__(self, db: Database, image: Image) -> None:
        self.db, self.image = db, image

    def name(self, ea: int, text: str) -> None:
        db = self.db
        existing = db.names.get_at(ea)
        if existing == text:
            return

        # keep a name that was set by hand
        if existing and db.bytes.has_user_name_at(ea):
            warn(f'Retaining existing name {existing} at {ea:#x}; requested {text}')
            return

        require(db.names.set_name(ea, text, SetNameFlags.NOWARN), f'Cannot name {ea:#x} {text}')

    def comment(self, ea: int, text: str) -> None:
        # repeatable comments also show up wherever the address is used
        require(self.db.comments.set_at(ea, text, CommentKind.REPEATABLE), f'Cannot annotate {ea:#x}')

    def data(self, ea: int, size: int, width: int, text: str, *, declaration: str | None = None) -> None:
        db = self.db

        # size bytes of data, in items of width bytes
        create = {1: db.bytes.create_byte_at, 2: db.bytes.create_word_at, 4: db.bytes.create_dword_at}[width]
        require(create(ea, size // width), f'Cannot create {size}-byte data at {ea:#x}')

        # a definite type is one IDA will not replace with a guess
        if declaration:
            require(
                db.types.apply_declaration_at(ea, declaration, TypeApplyFlags.DEFINITE), f'Cannot apply type at {ea:#x}'
            )

        self.name(ea, text)

    def apply(self, annotation: HardwareAnnotation, base: int, suffix: str = '') -> None:
        """Create one entry of a hardware table at base."""
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
        base = self.image.base

        # label the header in every view
        for view, suffix in self.image.views:
            for annotation in HEADER_FIELDS:
                self.apply(annotation, view, suffix)

        # two extra bytes the BIOS fills in
        if self.image.multiboot:
            for offset, field in ((0xC4, 'GBA_MB_BOOT_MODE'), (0xC5, 'GBA_MB_SLAVE_ID')):
                self.data(base + offset, 1, 1, field, declaration='volatile unsigned char value;')

    def _cartridge_ports(self) -> None:
        rom, base = self.image.rom, self.image.base

        # carts with a GPIO port keep these six header bytes zero
        # https://mgba-emu.github.io/gbatek/#gbacartioportgpio
        if not self.image.multiboot and len(rom) >= 0xCA and not any(rom[0xC4:0xCA]):
            for offset, port in ((0xC4, 'GBA_GPIO_DATA'), (0xC6, 'GBA_GPIO_DIRECTION'), (0xC8, 'GBA_GPIO_CONTROL')):
                self.data(base + offset, 2, 2, port, declaration='volatile unsigned short value;')

        # the EEPROM is read and written through one port
        eeprom = self.db.segments.get_by_name('EEPROM')
        if eeprom:
            self.data(eeprom.start_ea, 2, 2, 'GBA_EEPROM', declaration='volatile unsigned short value;')

    def _video_memory(self) -> None:
        # types for the palette and the sprite table (OAM)
        decls = """
            struct GBA_PaletteRAM {
                unsigned short BG_PALETTE[256];
                unsigned short OBJ_PALETTE[256];
            };

            struct GBA_OAMEntry {
                unsigned short attr0;
                unsigned short attr1;
                unsigned short attr2;
                short affine;
            };

            struct GBA_OAM {
                struct GBA_OAMEntry obj[128];
            };
        """

        # add them to the database
        require(
            self.db.types.parse_declarations(
                None,  # ty: ignore[invalid-argument-type]  # None selects the database's local library
                decls,
            )
            == 0,
            'Cannot define GBA palette/OAM types',
        )

        self.data(BASE_PALETTE_RAM, SIZE_PALETTE_RAM, 2, 'GBA_PALETTE', declaration='struct GBA_PaletteRAM value;')
        self.comment(BASE_PALETTE_RAM, 'BG colors, then OBJ colors at 0x05000200. Each color is 15-bit BGR.')
        self.data(BASE_OAM, SIZE_OAM, 2, 'GBA_OAM', declaration='struct GBA_OAM value;')
        self.comment(BASE_OAM, '128 sprites. The affine fields of every four sprites hold one affine matrix.')

    def _io_registers(self) -> None:
        # one typed, named and commented item per register
        scalar = {1: 'unsigned char', 2: 'unsigned short', 4: 'unsigned int'}
        for register in REGISTERS:
            ea = BASE_IO + register.offset

            # volatile makes the decompiler keep every read and write
            array = f'[{register.count}]' if register.count > 1 else ''
            declaration = f'volatile {scalar[register.width]} value{array};'
            self.data(ea, register.width * register.count, register.width, register.name, declaration=declaration)
            self.comment(ea, register.access_description)

    def _bios_workspace(self) -> None:
        # BIOS variables, also through the IWRAM mirror
        for workspace_base, suffix in ((BASE_IWRAM, ''), (BASE_IWRAM_MIRROR, '_MIRROR')):
            for annotation in WORKSPACE:
                self.apply(annotation, workspace_base, suffix)

    def report(self, facts: HeaderFacts, recovery: StartupRecovery | StartupRecoveryFailure) -> None:
        base = self.image.base
        kind = 'multiboot image' if self.image.multiboot else 'cartridge'

        # bytes without the b prefix
        def brepr(s: bytes) -> str:
            return repr(s)[1:]

        lines = [
            f'GBA {kind}: {facts.size} bytes at {base:#010x}',
            'Title: ' + brepr(facts.title.strip(b'\0')),
            'Game: ' + brepr(facts.game_code.rstrip(b'\0')),
            'Maker: ' + brepr(facts.maker),
        ]

        # these are usually zero, so only show them when set
        if facts.unit:
            lines.append(f'Unit: {facts.unit:#x}')

        if facts.device:
            lines.append(f'Device: {facts.device:#x}')

        if facts.version:
            lines.append(f'Version: {facts.version}')

        if facts.reserved1.strip(b'\0') or facts.reserved2.strip(b'\0'):
            lines.append(f'Non-null reserved bytes: {brepr(facts.reserved1)} + {brepr(facts.reserved2)}')

        if facts.save_markers:
            lines.append('Save SDK clues (advisory only): ' + (', '.join(facts.save_markers) or 'none'))

        lines += [f'Warning: {warning}' for warning in facts.warnings]

        # add the comments to the entry point before adding the sloppy dkA comments
        self.comment(base, '\n'.join(lines))

        if isinstance(recovery, StartupRecoveryFailure):
            lines.append(f'Startup recovery not applied: {recovery.reason}')
        else:
            lines.append(f'Stock devkitARM startup found at {recovery.start:#010x}!')
            lines.extend(
                f'{copy.name}: {copy.source:#010x} -> {copy.destination:#010x}, {copy.size:#x} bytes'
                for copy in recovery.copies
            )

        # log everything to the console
        for line in lines:
            log(line)
