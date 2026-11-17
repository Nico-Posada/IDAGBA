"""Post-analysis passes that extend IDA's native ARM analysis.

After normal analysis, bounded passes (re-run on auto_empty until nothing new, at most four)
follow only analyzed code: shared Thumb literal/BX veneers (per call site, into the image or a
verified RAM copy), constant ARM handlers stored to the BIOS IRQ vector (register tracker), and
BIOS SWI numbers (comments only). Constant-register BX calls such as ldr/mov lr,pc/bx are
already resolved by IDA's ARM module. Overlays and decompression are left to the analyst.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import ida_allins
import ida_regfinder
from ida_domain.base import IdaDomainError
from ida_domain.hooks import DatabaseHooks
from ida_domain.names import SetNameFlags
from ida_domain.operands import MemoryOperand, OperandType, RegisterOperand
from ida_domain.xrefs import XrefType

from idagba import arm
from idagba.bios import BIOS_CALL_NAMES
from idagba.crt0 import StartupCopy, StartupRecovery, StartupRecoveryFailure, code_pointer
from idagba.errors import LoadError, require
from idagba.hardware import IRQ_VECTORS
from idagba.logging import log, warn
from idagba.rom import HEADER_SIZE

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ida_domain import Database
    from ida_ua import insn_t

    from idagba.rom import Image

_MAX_PASSES = 4
_pending: PostAnalysis | None = None


class PostAnalysis(DatabaseHooks):
    """Re-run native-analysis extensions on auto_empty until a pass resolves nothing new."""

    def __init__(
        self,
        db: Database,
        image: tuple[int, int],
        copies: Sequence[StartupCopy],
        reserved: Sequence[tuple[int, int]],
    ) -> None:
        super().__init__()
        self.db, self.image, self.copies, self.reserved = db, image, copies, reserved
        self.passes = 0

    def auto_empty(self) -> None:
        global _pending
        self.passes += 1
        try:
            found = self._run_pass()
        except (LoadError, IdaDomainError) as exc:
            warn(f'Post-analysis stopped: {exc}')
            found = 0

        # ponytail: bounded re-runs over analyzed code only; raise _MAX_PASSES for deeper chains.
        if not found or self.passes >= _MAX_PASSES:
            self.unhook()
            _pending = None

    def closebase(self) -> None:
        global _pending
        self.unhook()
        _pending = None

    def _run_pass(self) -> int:
        """One pass over the analyzed code; the number of new code references it proved."""
        swis = self._annotate_swis()
        branches = self._resolve_veneers()
        handlers = self._resolve_irq_handlers()
        log(f'Post-analysis pass: {branches} veneer calls, {handlers} IRQ handlers, {swis} BIOS calls')
        return branches + handlers

    def _decode(self, ea: int | None) -> insn_t | None:
        db = self.db
        if ea is None or not db.is_valid_ea(ea) or not db.bytes.is_code_at(ea):
            return None

        return db.instructions.get_at(ea)

    def _function_start(self, ea: int) -> int | None:
        function = self.db.functions.get_at(ea)
        return function.start_ea if function else None

    def _function_starts(self) -> list[int]:
        return [function.start_ea for function in self.db.functions.get_all()]

    def _claim(self, site: int, pointer: int) -> int | None:
        """Schedule the code behind a proven pointer; its address, or None when site already references it."""
        db = self.db
        address = pointer & ~1
        if not code_pointer(pointer, self.image, self.copies, self.reserved) or any(
            xref.from_ea == site for xref in db.xrefs.to_ea(address)
        ):
            return None

        if db.bytes.is_data_at(address) or db.bytes.is_tail_at(address):
            return None

        if db.bytes.is_code_at(address):
            if arm.thumb_state(address) != pointer & 1:
                return None
        else:
            arm.set_thumb(address, pointer & 1)

        db.auto_analysis.schedule_function(address)
        return address

    def _annotate_swis(self) -> int:
        db = self.db
        count = 0
        # ponytail: rescans every analyzed instruction per pass; track changed functions if large ROMs stall.
        for function_ea in self._function_starts():
            function = db.functions.get_at(function_ea)
            if function is None:
                continue

            for insn in list(db.functions.get_instructions(function)):
                ea = insn.ea
                if not db.bytes.is_code_at(ea):
                    continue

                number = arm.swi_number(db, insn)
                if number is None or db.comments.get_at(ea):
                    continue

                if number < len(BIOS_CALL_NAMES):
                    count += db.comments.set_at(ea, f'BIOS SWI {number:#04x} {BIOS_CALL_NAMES[number]}')

        return count

    def _resolve_veneers(self) -> int:
        """Shared Thumb BX veneers: the register differs per caller, so resolve at each call site.

        Constant-register BX (e.g. ldr r1,=main; mov lr,pc; bx r1) is resolved natively by IDA's ARM module.
        """
        db = self.db
        count = 0
        for ea in self._function_starts():
            function = db.functions.get_at(ea)
            first = self._decode(ea) if arm.thumb_state(ea) == 1 else None
            if function is None or first is None:
                continue

            branch = first if first.itype == ida_allins.ARM_bx else self._decode(ea + first.size)
            if branch is None or branch.itype != ida_allins.ARM_bx or branch.ea + branch.size != function.end_ea:
                continue

            target = db.instructions.get_operand(branch, 0)
            if not isinstance(target, RegisterOperand):
                continue

            for call in list(db.xrefs.calls_to_ea(ea)):
                load = first if branch is not first else self._decode(db.heads.get_previous(call))
                if branch is first and (
                    load is None
                    or load.ea + load.size != call
                    or self._function_start(load.ea) != self._function_start(call)
                ):
                    continue

                pointer = self._literal(load, target.register_number)
                if pointer is not None:
                    count += self._link_call(call, pointer)

        return count

    def _literal(self, load: insn_t | None, reg: int) -> int | None:
        """Value loaded by `ldr reg, =literal` from a pool inside the image or a RAM copy."""
        db = self.db
        if load is None or load.itype != ida_allins.ARM_ldr:
            return None

        destination = db.instructions.get_operand(load, 0)
        source = db.instructions.get_operand(load, 1)
        if (
            not isinstance(destination, RegisterOperand)
            or destination.register_number != reg
            or not isinstance(source, MemoryOperand)
            or not source.is_direct_memory()
        ):
            return None

        pool = source.get_address()
        if pool is None or (
            pool % 4
            or not (
                self.image[0] <= pool <= self.image[1] - 4
                or any(c.destination <= pool <= c.destination + c.size - 4 for c in self.copies)
            )
        ):
            return None

        return db.bytes.get_dword_at(pool, allow_uninitialized=True)

    def _link_call(self, site: int, pointer: int) -> bool:
        """Add a proven call reference from site; True only when it is new."""
        db = self.db
        address = self._claim(site, pointer)
        if address is None:
            return False

        # Keep the actual branch-to-veneer call as well as its proven callee.
        require(db.xrefs.add_code_ref(site, address, XrefType.CALL_NEAR), f'Cannot add resolved call at {site:#x}')
        if not db.comments.get_at(site):
            db.comments.set_at(site, f'Literal/BX veneer resolves to {address:#010x}')

        return True

    def _resolve_irq_handlers(self) -> int:
        """Constant ARM handlers stored to the BIOS IRQ vector near a load of its address."""
        db = self.db
        count = 0
        for vector in IRQ_VECTORS:
            for load in self._vector_loads(vector):
                function = db.functions.get_at(load)
                if function is None:
                    continue

                ea = load
                # ponytail: short fixed window after the vector load, not dataflow over the function.
                for _ in range(8):
                    following = db.heads.get_next(ea)
                    if following is None or following >= function.end_ea:
                        break

                    ea = following
                    insn = self._decode(ea)
                    if insn is None:
                        break

                    handler = self._stored_handler(insn, vector)
                    if handler is not None:
                        count += self._install_irq_handler(ea, handler)

        return count

    def _vector_loads(self, vector: int) -> set[int]:
        """Instructions that reference the vector directly or through a literal pool entry."""
        db = self.db
        loads = set()
        for xref in db.xrefs.to_ea(vector):
            if db.bytes.is_code_at(xref.from_ea):
                loads.add(xref.from_ea)
            else:
                loads.update(pool.from_ea for pool in db.xrefs.to_ea(xref.from_ea) if db.bytes.is_code_at(pool.from_ea))

        return loads

    def _stored_handler(self, insn: insn_t, vector: int) -> int | None:
        """Constant ARM pointer that `str handler, [reg, #displacement]` writes to the vector."""
        db = self.db
        if insn.itype != ida_allins.ARM_str:
            return None

        stored = db.instructions.get_operand(insn, 0)
        address = db.instructions.get_operand(insn, 1)
        if (
            not isinstance(address, MemoryOperand)
            or address.type != OperandType.DISPLACEMENT
            or not isinstance(stored, RegisterOperand)
        ):
            return None

        phrase, displacement = address.get_phrase_number(), address.get_displacement()
        if phrase is None or displacement is None:
            return None

        target = ida_regfinder.find_reg_value(insn.ea, phrase)
        if target is None or (target + displacement) & 0xFFFFFFFF != vector:
            return None

        handler = ida_regfinder.find_reg_value(insn.ea, stored.register_number)
        return None if handler is None or handler % 4 else handler

    def _install_irq_handler(self, site: int, handler: int) -> bool:
        """Reference and name the handler that site installs; True only when it is new."""
        db = self.db
        if self._claim(site, handler) is None:
            return False

        if not db.bytes.has_user_name_at(handler):
            db.names.set_name(handler, 'GBA_IrqMain', SetNameFlags.NOWARN | SetNameFlags.FORCE)

        require(db.xrefs.add_data_ref(site, handler, XrefType.OFFSET), f'Cannot reference IRQ handler from {site:#x}')
        if not db.comments.get_at(site):
            db.comments.set_at(site, f'Installs ARM BIOS IRQ handler {handler:#010x}')

        return True


def schedule_post_analysis(db: Database, image: Image, recovery: StartupRecovery | StartupRecoveryFailure) -> None:
    global _pending
    recovered = isinstance(recovery, StartupRecovery)
    copies = recovery.copies if recovered else ()
    reserved = recovery.reserved if recovered else ((image.base, image.base + HEADER_SIZE),)
    _pending = PostAnalysis(db, (image.base, image.end), copies, reserved)
    _pending.hook()
    require(_pending.is_hooked, 'Cannot schedule post-analysis passes')
