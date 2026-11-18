"""Hex-Rays lifters that turn BIOS calls and calls through veneers into normal calls.

BIOS calls, lifted from the SVC instruction:
Off: __asm { SVC 0xC }
On:  SWI_CpuFastSet(src, dst, mode)

Veneer calls, retargeted in the generated microcode before the decompiler analyzes any call:
Off: sub_8017890(dst, 0, 12)    a bx pc veneer the linker placed in front of ARM code in IWRAM
On:  sub_30013B8(dst, 0, 12)
Off: sub_80015B2(a, b)          bx r5, with the callee loaded into r5 by the caller
On:  sub_3000024(a, b)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import ida_allins
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
from ida_domain import Database
from ida_domain.microcode import MicroBlockArray, MicrocodeFilter, MicrocodeLifter, MicroOpcode, reg2mreg
from ida_domain.operands import RegisterOperand

from idagba import arm
from idagba.bios import BIOS_PROTOTYPES

if TYPE_CHECKING:
    from ida_funcs import func_t
    from ida_hexrays import codegen_t, mba_t

_installed: tuple[_BiosCalls, _VeneerCalls] | None = None


def install() -> bool:
    """Install the lifters for the open database; False when the decompiler is missing."""
    global _installed
    if _installed:
        return True

    if not ida_hexrays.init_hexrays_plugin():
        return False

    db = Database.open()
    bios, veneers = _BiosCalls(db), _VeneerCalls(db)
    bios.install()
    veneers.hook()
    _installed = bios, veneers
    ida_hexrays.clear_cached_cfuncs()
    return True


def uninstall() -> None:
    global _installed
    if _installed is None:
        return

    bios, veneers = _installed
    bios.uninstall()
    veneers.unhook()
    _installed = None
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


class _VeneerCalls(ida_hexrays.Hexrays_Hooks):
    """Point each call that goes through a stub at the code the stub reaches.

    Not ida_domain's DecompilerHooks: it sends every decompiler event through Python, which costs more time than
    this hook itself, and its collect_warnings makes IDA print a TypeError on every decompilation.
    """

    def __init__(self, db: Database) -> None:
        super().__init__()
        self.db = db

    def microcode(self, mba: mba_t) -> int:
        for insn in MicroBlockArray(mba).instructions():
            callee = insn.l.global_address
            if callee is None or insn.opcode not in (MicroOpcode.CALL, MicroOpcode.GOTO):
                continue

            target = self._behind_thunks(callee)
            if insn.opcode == MicroOpcode.GOTO:
                # A jump to another function decompiles as a tail call; a jump to a mere label would not.
                if target != callee and self._function(target) is not None:
                    insn.l.set_global_addr(target, insn.l.size)

                continue

            register = self._bx_register(target)
            if register is not None:
                # bl to a lone bx rN is an indirect call through rN; the decompiler then follows the register.
                insn.opcode = MicroOpcode.ICALL
                insn.l.set_register(reg2mreg(ida_idp.str2reg('CS')), 2)
                insn.r.set_register(reg2mreg(register), 4)
            elif target != callee:
                insn.l.set_global_addr(target, insn.l.size)

        return ida_hexrays.MERR_OK

    def _behind_thunks(self, ea: int) -> int:
        """Where a call to ea ends up after every thunk with a fixed target on the way."""
        seen = set()
        while ea not in seen:
            seen.add(ea)
            function = self._function(ea)
            # Not db.functions.get_flags: it raises on IDA 9.5's FUNC_OVERSIZED, which ida_domain 0.6 lacks.
            if function is None or not function.flags & ida_funcs.FUNC_THUNK:
                break

            # IDA returns (target, address of the pointer it read); its stub claims a plain int.
            target, _ = ida_funcs.calc_thunk_func_target(function)  # ty: ignore[not-iterable]
            if target == ida_idaapi.BADADDR:
                break

            ea = target

        return ea

    def _bx_register(self, ea: int) -> int | None:
        """The register of a function that is one `bx rN`: libgcc's _call_via_rN, crt0's GBA_BxR3."""
        function = self._function(ea)
        insn = self.db.instructions.get_at(ea) if function is not None else None
        if function is None or insn is None or insn.itype != ida_allins.ARM_bx or ea + insn.size != function.end_ea:
            return None

        operand = self.db.instructions.get_operand(insn, 0)
        # bx lr is a return and bx pc a mode switch; neither holds a callee.
        if not isinstance(operand, RegisterOperand) or operand.register_number >= ida_idp.str2reg('SP'):
            return None

        return operand.register_number

    def _function(self, ea: int) -> func_t | None:
        """The function that starts at ea; ea is whatever a call held and may be unmapped."""
        function = self.db.functions.get_at(ea) if self.db.is_valid_ea(ea) else None
        return function if function is not None and function.start_ea == ea else None
