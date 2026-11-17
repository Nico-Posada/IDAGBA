"""Apply a recovered crt0 to the database and seed analysis from the entry and startup code."""

from __future__ import annotations

from typing import TYPE_CHECKING

import ida_funcs
import ida_ida
from ida_domain.xrefs import XrefType

from idagba.arm import set_thumb
from idagba.crt0 import StartupRecovery, StartupRecoveryFailure
from idagba.errors import require
from idagba.loader.annotate import comment, data, name
from idagba.rom import BASE, entry_target

if TYPE_CHECKING:
    from ida_domain import Database


def apply_recovery(db: Database, rom: bytes, recovery: StartupRecovery | StartupRecoveryFailure) -> None:
    if isinstance(recovery, StartupRecoveryFailure):
        return

    for copy in recovery.copies:
        source, dest, size = copy.source, copy.destination, copy.size
        offset = source - recovery.base
        db.bytes.set_bytes_at(dest, rom[offset : offset + size])
        data(db, source, size, 1, copy.name)
        text = f'Stock crt0 copy: {source:#010x} -> {dest:#010x}, {size:#x} bytes; RAM remains mutable'
        comment(db, source, text)
        comment(db, dest, text)

    for hint in recovery.hints:
        comment(db, hint.address, hint.text)


def seed_analysis(db: Database, rom: bytes, recovery: StartupRecovery | StartupRecoveryFailure, base: int) -> None:
    entry = base if base == BASE else base + 0xC0
    set_thumb(entry, 0)
    require(ida_ida.inf_set_start_cs(0) and ida_ida.inf_set_start_ea(entry), 'Cannot establish flat entry address')
    db.start_ip = entry
    require(
        db.entries.add(entry, 'GBA_ROM_ENTRY' if base == BASE else 'GBA_MB_ENTRY', make_code=True),
        'Cannot add image entry',
    )
    db.auto_analysis.schedule_function(entry)
    target = entry_target(rom, len(rom), base, entry - base)
    if target is not None:
        name(db, target, 'GBA_STARTUP')
    if isinstance(recovery, StartupRecoveryFailure):
        return

    start = recovery.start
    set_thumb(start, 0)
    set_thumb(start + 0x28, 1)
    helpers = recovery.clear_mem
    for delta, routine in ((0, 'GBA_ClearMem'), (0x12, 'GBA_BxR3'), (0x14, 'GBA_CopyMemChk')):
        address = helpers + delta
        set_thumb(address, 1)
        name(db, address, routine)
        if delta == 0x14:
            require(db.instructions.create(address) == 2, 'Cannot decode CopyMemChk')
            require(
                ida_funcs.add_func(address, helpers + 0x28),
                'Cannot establish CopyMemChk with its CopyMem interior entry',
            )
        db.auto_analysis.schedule_function(address)

    name(db, helpers + 0x16, 'GBA_CopyMem')
    for pointer, routine, callsite in (
        (recovery.constructors, '__libc_init_array', 0x98),
        (recovery.main, 'main', 0xA2),
    ):
        address = pointer & ~1
        set_thumb(address, pointer & 1)
        name(db, address, routine)
        db.auto_analysis.schedule_function(address)
        require(
            db.instructions.create(start + callsite) == 4,
            f'Cannot decode proven Thumb callsite at {start + callsite:#x}',
        )
        require(
            db.xrefs.add_code_ref(start + callsite, address, XrefType.CALL_NEAR),
            f'Cannot add proven startup call to {routine}',
        )
