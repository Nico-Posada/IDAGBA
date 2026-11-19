"""Decompiler hooks that show BIOS calls and calls through stubs as normal calls.

BIOS calls
Off: __asm { SVC 0xC }
On:  SWI_CpuFastSet(src, dst, mode)

Calls through a linker veneer
Off: sub_8017890(dst, 0, 12)
On:  sub_30013B8(dst, 0, 12)

Calls through a bx rN helper
Off: sub_80015B2(a, b, sub_3000024) => a3(a1, a2)
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
    """Install the hooks for the open database. Returns False when there is no decompiler."""
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

    # drop pseudocode that was made without the hooks
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

    # drop pseudocode that was made with the hooks
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

        # a call clobbers r0-r3 unless its prototype says otherwise, as in libtonc
        if '__spoils' not in declaration:
            declaration = declaration.replace('__usercall', '__usercall __spoils<R0,R1,R2,R3>', 1)

        if not self.init(declaration):
            msg = f'Cannot parse BIOS call prototype: {declaration}'
            raise ValueError(msg)

    def match(self, cdg: codegen_t) -> bool:
        # _BiosCalls already matched the instruction
        return True


# TODO(2026-11-19): This hooks Hex-Rays directly because ida_domain's DecompilerHooks is slow and makes IDA print a
# TypeError on every decompilation. Update to use ida_domain's wrapper when that's fixed.
class _VeneerCalls(ida_hexrays.Hexrays_Hooks):
    """Point each call that goes through a stub at the code the stub reaches."""

    def __init__(self, db: Database) -> None:
        super().__init__()
        self.db = db

    def microcode(self, mba: mba_t) -> int:
        # runs on the fresh microcode of a function, before the decompiler looks at its calls
        for insn in MicroBlockArray(mba).instructions():
            # only calls and jumps to a fixed address
            callee = insn.l.global_address
            if callee is None or insn.opcode not in (MicroOpcode.CALL, MicroOpcode.GOTO):
                continue

            target = self._behind_thunks(callee)
            if insn.opcode == MicroOpcode.GOTO:
                # only retarget a jump that lands on a function, so it decompiles as a tail call
                if target != callee and self._function(target) is not None:
                    insn.l.set_global_addr(target, insn.l.size)

                continue

            register = self._bx_register(target)
            if register is not None:
                # make it an indirect call through rN, which the decompiler resolves itself
                insn.opcode = MicroOpcode.ICALL

                # icall takes the segment in l and the target in r
                insn.l.set_register(reg2mreg(ida_idp.str2reg('CS')), 2)
                insn.r.set_register(reg2mreg(register), 4)
            elif target != callee:
                # point the call at the end of the thunk chain
                insn.l.set_global_addr(target, insn.l.size)

        return ida_hexrays.MERR_OK

    def _behind_thunks(self, ea: int) -> int:
        """Follow the thunks from ea to the code they end at."""
        seen = set()
        while ea not in seen:
            seen.add(ea)
            function = self._function(ea)

            # TODO(2026-11-19): db.functions.get_flags raises on IDA 9.5's FUNC_OVERSIZED,
            # so update to ida_domain's wrapper when that's fixed
            if function is None or not function.flags & ida_funcs.FUNC_THUNK:
                break

            # this returns a (target, pointer address) pair, though its type stub says int
            target, _ = ida_funcs.calc_thunk_func_target(function)  # ty: ignore[not-iterable]
            if target == ida_idaapi.BADADDR:
                break

            ea = target

        return ea

    def _bx_register(self, ea: int) -> int | None:
        """The register rN when the function at ea is only `bx rN`, like libgcc's _call_via_rN."""
        function = self._function(ea)
        insn = self.db.instructions.get_at(ea) if function is not None else None

        # the whole function must be the one bx instruction
        if function is None or insn is None or insn.itype != ida_allins.ARM_bx or ea + insn.size != function.end_ea:
            return None

        operand = self.db.instructions.get_operand(insn, 0)

        # bx lr is a return and bx pc a mode switch, so neither is a call
        if not isinstance(operand, RegisterOperand) or operand.register_number >= ida_idp.str2reg('SP'):
            return None

        return operand.register_number

    def _function(self, ea: int) -> func_t | None:
        """The function that starts at ea, if there is one."""
        function = self.db.functions.get_at(ea) if self.db.is_valid_ea(ea) else None
        return function if function is not None and function.start_ea == ea else None
