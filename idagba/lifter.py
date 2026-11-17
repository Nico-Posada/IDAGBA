"""Hex-Rays lifter that turns BIOS calls from inline asm into normal calls.

Off: __asm { SVC 0xC }
On:  SWI_CpuFastSet(src, dst, mode)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import ida_hexrays
from ida_domain import Database
from ida_domain.microcode import MicrocodeFilter, MicrocodeLifter

from idagba import arm
from idagba.bios import BIOS_PROTOTYPES

if TYPE_CHECKING:
    from ida_hexrays import codegen_t

_lifter: _BiosCalls | None = None


def install() -> bool:
    """Install the lifter for the open database; False when the decompiler is missing."""
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


class _BiosCalls(MicrocodeLifter):
    def __init__(self, db: Database) -> None:
        super().__init__()
        self.db = db
        self.prototypes = {number: _Prototype(declaration) for number, declaration in BIOS_PROTOTYPES.items()}

    def match(self, cdg: codegen_t) -> bool:
        return arm.swi_number(self.db, cdg.insn) in self.prototypes

    def apply(self, cdg: codegen_t) -> int:
        number = arm.swi_number(self.db, cdg.insn)
        if number is None:  # match() already ruled this out
            return ida_hexrays.MERR_INSN

        return self.prototypes[number].apply(cdg)


class _Prototype(MicrocodeFilter):
    """The prototype of one BIOS call."""

    def __init__(self, declaration: str) -> None:
        super().__init__()
        # A call that does not list what it clobbers is assumed to clobber R0-R3, as in libtonc.
        if '__spoils' not in declaration:
            declaration = declaration.replace('__usercall', '__usercall __spoils<R0,R1,R2,R3>', 1)

        if not self.init(declaration):
            msg = f'Cannot parse BIOS call prototype: {declaration}'
            raise ValueError(msg)

    def match(self, cdg: codegen_t) -> bool:
        # _BiosCalls has already matched the instruction.
        return True
