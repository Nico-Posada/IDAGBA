"""Hex-Rays lifter: GBA BIOS SWI/SVC instructions become typed helper calls.

The idagba plugin installs it on databases created by the idagba loader; it needs the ARM
decompiler. One microcode filter matches BIOS SVCs and hands each to that call's udc_filter_t
prototype (never installed itself), which emits a call carrying the GBATEK register arguments
and results, so the pseudocode shows SWI_CpuFastSet(src, dst, mode) instead of __asm { SVC 0xC }.
From another script, `from idagba import lifter; lifter.install()` does the same.

Reference: https://problemkaputt.de/gbatek.htm#biosfunctions
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import ida_hexrays
from ida_domain import Database
from ida_domain.microcode import MicrocodeFilter, MicrocodeLifter

from idagba import arm
from idagba.bios import BIOS_PROTOTYPES, SPOILS

if TYPE_CHECKING:
    from ida_hexrays import codegen_t


class _Prototype(MicrocodeFilter):
    """One BIOS call's __usercall prototype; only its apply() is used, via _BiosCalls."""

    def __init__(self, declaration: str) -> None:
        super().__init__()
        if '__spoils' not in declaration:
            declaration = declaration.replace('__usercall', SPOILS, 1)

        if not self.init(declaration):
            msg = f'Cannot parse BIOS call prototype: {declaration}'
            raise ValueError(msg)

    def match(self, cdg: codegen_t) -> bool:
        # udc_filter_t.apply() re-checks match(); _BiosCalls only dispatches matching SVCs here.
        return True


class _BiosCalls(MicrocodeLifter):
    def __init__(self, db: Database) -> None:
        super().__init__()
        self.db = db
        self.prototypes = {number: _Prototype(declaration) for number, declaration in BIOS_PROTOTYPES.items()}

    def match(self, cdg: codegen_t) -> bool:
        return arm.swi_number(self.db, cdg.insn) in self.prototypes

    def apply(self, cdg: codegen_t) -> int:
        number = arm.swi_number(self.db, cdg.insn)
        if number is None:  # match() admitted only BIOS SVCs
            return ida_hexrays.MERR_INSN

        return self.prototypes[number].apply(cdg)


_lifter: _BiosCalls | None = None


def install() -> bool:
    """Register the BIOS call lifter for the open database; True when the decompiler is available."""
    global _lifter
    if _lifter:
        return True

    if not ida_hexrays.init_hexrays_plugin():
        return False

    lifter = _BiosCalls(Database.open())
    lifter.install()
    _lifter = lifter
    ida_hexrays.clear_cached_cfuncs()
    return True


def uninstall() -> None:
    global _lifter
    if _lifter is None:
        return

    _lifter.uninstall()
    _lifter = None
    ida_hexrays.clear_cached_cfuncs()
