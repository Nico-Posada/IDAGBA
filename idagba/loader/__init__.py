"""IDA-side GBA loader: maps the image, annotates hardware, applies crt0 and seeds analysis.

Thumb BL long-jump recognition is enabled before analysis so internal branches
do not split functions and turn stack locals into bogus arguments. Existing IDBs
with such splits need a fresh load or manual function-boundary repair; changing
the option alone does not remove old function definitions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import ida_ida
import ida_idp
import ida_loader
from ida_domain import Database
from ida_domain.base import IdaDomainError

from idagba.crt0 import recover_startup
from idagba.errors import LoadError, require
from idagba.hardware import BASE_EWRAM, BASE_ROM0, SIZE_EWRAM, SIZE_ROM0
from idagba.loader.analysis import schedule_post_analysis
from idagba.loader.annotate import Annotator
from idagba.loader.memory_map import map_image
from idagba.loader.startup import apply_recovery, seed_analysis
from idagba.logging import error
from idagba.recognition import FORMAT, MB_FORMAT, RELAXED_FORMAT, recognize
from idagba.rom import HEADER_SIZE, HeaderFacts, Image, header_facts

if TYPE_CHECKING:
    from ida_idaapi import loader_input_t


def load_file(li: loader_input_t, neflags: int, format_name: str) -> int:
    try:
        require(
            not neflags & ida_loader.NEF_RELOAD and neflags & ida_loader.NEF_FIRST,
            'Only a fresh first-file load is supported; reload/additional-file loads are refused',
        )
        require(format_name in (FORMAT, RELAXED_FORMAT, MB_FORMAT), 'Unsupported selected format')
        multiboot = format_name == MB_FORMAT
        size = li.size()
        require(
            HEADER_SIZE <= size <= (SIZE_EWRAM if multiboot else SIZE_ROM0),
            'Image size must be 192 bytes through 32 MiB (256 KiB for multiboot)',
        )
        li.seek(0)
        rom = li.read(size)
        require(len(rom) == size, 'Short cartridge read')
        expected = recognize(rom, size, 'input.mb' if multiboot else 'input.gba')
        require(expected == format_name, 'Header does not match the selected recognition path')
        image = Image(rom, BASE_EWRAM if multiboot else BASE_ROM0)
        facts = header_facts(image)
        require(ida_idp.set_processor_type('ARM:ARM7TDMI', ida_idp.SETPROC_LOADER), 'Cannot select ARM7TDMI processor')
        # Thumb-1 compilers also use BL for long intra-function jumps.
        ida_idp.process_config_directive('ARM_DISABLE_BL_JUMPS = NO')
        ida_ida.inf_set_app_bitness(32)
        ida_ida.inf_set_be(False)  # noqa: FBT003
        db = Database.open()
        require(not ida_ida.inf_is_be() and db.bitness == 32, 'Cannot establish 32-bit little-endian addressing')
        _setup_database(Annotator(db, image), li, facts)
    except (LoadError, IdaDomainError) as exc:
        error(f'Load failed: {exc}')
        return 0

    return 1


def _setup_database(annotator: Annotator, li: loader_input_t, facts: HeaderFacts) -> None:
    db, image = annotator.db, annotator.image
    map_image(db, li, image)
    annotator.hardware()
    recovery = recover_startup(image.rom, image.base)
    apply_recovery(annotator, recovery)
    annotator.report(facts, recovery)
    seed_analysis(annotator, recovery)
    schedule_post_analysis(db, image, recovery)
