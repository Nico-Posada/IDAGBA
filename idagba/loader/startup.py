"""Apply a recovered crt0 to the database and seed analysis from the entry and startup code."""

from __future__ import annotations

from typing import TYPE_CHECKING

import ida_funcs
import ida_ida
from ida_domain.xrefs import XrefType

from idagba.arm import set_thumb
from idagba.crt0 import StartupRecovery, StartupRecoveryFailure
from idagba.errors import require

if TYPE_CHECKING:
    from idagba.loader.annotate import Annotator


def apply_recovery(annotator: Annotator, recovery: StartupRecovery | StartupRecoveryFailure) -> None:
    if isinstance(recovery, StartupRecoveryFailure):
        return

    rom = annotator.image.rom
    for copy in recovery.copies:
        source, dest, size = copy.source, copy.destination, copy.size
        offset = source - recovery.base
        annotator.db.bytes.set_bytes_at(dest, rom[offset : offset + size])
        annotator.data(source, size, 1, copy.name)
        text = f'Stock crt0 copy: {source:#010x} -> {dest:#010x}, {size:#x} bytes; RAM remains mutable'
        annotator.comment(source, text)
        annotator.comment(dest, text)

    for hint in recovery.hints:
        annotator.comment(hint.address, hint.text)


def seed_analysis(annotator: Annotator, recovery: StartupRecovery | StartupRecoveryFailure) -> None:
    _seed_entry(annotator)
    if isinstance(recovery, StartupRecovery):
        _seed_helpers(annotator, recovery)
        _seed_calls(annotator, recovery)


def _seed_entry(annotator: Annotator) -> None:
    db, image = annotator.db, annotator.image
    entry = image.entry
    set_thumb(entry, 0)
    require(ida_ida.inf_set_start_cs(0) and ida_ida.inf_set_start_ea(entry), 'Cannot establish flat entry address')
    db.start_ip = entry
    require(
        db.entries.add(entry, 'GBA_MB_ENTRY' if image.multiboot else 'GBA_ROM_ENTRY', make_code=True),
        'Cannot add image entry',
    )
    db.auto_analysis.schedule_function(entry)
    target = image.entry_target
    if target is not None:
        annotator.name(target, 'GBA_STARTUP')


def _seed_helpers(annotator: Annotator, recovery: StartupRecovery) -> None:
    """Name the memory helpers behind the crt0 body and make each a function."""
    db = annotator.db
    start = recovery.start
    set_thumb(start, 0)
    set_thumb(start + 0x28, 1)
    helpers = recovery.clear_mem
    for delta, routine in ((0, 'GBA_ClearMem'), (0x12, 'GBA_BxR3'), (0x14, 'GBA_CopyMemChk')):
        address = helpers + delta
        set_thumb(address, 1)
        annotator.name(address, routine)
        if delta == 0x14:
            require(db.instructions.create(address) == 2, 'Cannot decode CopyMemChk')
            require(
                ida_funcs.add_func(address, helpers + 0x28),
                'Cannot establish CopyMemChk with its CopyMem interior entry',
            )

        db.auto_analysis.schedule_function(address)

    annotator.name(helpers + 0x16, 'GBA_CopyMem')


def _seed_calls(annotator: Annotator, recovery: StartupRecovery) -> None:
    """Schedule the two routines crt0 calls through r3 and reference them from their call sites."""
    db = annotator.db
    start = recovery.start
    for pointer, routine, callsite in (
        (recovery.constructors, '__libc_init_array', 0x98),
        (recovery.main, 'main', 0xA2),
    ):
        address = pointer & ~1
        set_thumb(address, pointer & 1)
        annotator.name(address, routine)
        db.auto_analysis.schedule_function(address)
        require(
            db.instructions.create(start + callsite) == 4,
            f'Cannot decode proven Thumb callsite at {start + callsite:#x}',
        )
        require(
            db.xrefs.add_code_ref(start + callsite, address, XrefType.CALL_NEAR),
            f'Cannot add proven startup call to {routine}',
        )
