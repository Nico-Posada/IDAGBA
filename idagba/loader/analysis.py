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
from idagba.loader.annotate import log

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ida_domain import Database
    from ida_ua import insn_t

_MAX_PASSES = 4
_pending: PostAnalysis | None = None


class PostAnalysis(DatabaseHooks):
    """Re-run native-analysis extensions on auto_empty until a pass resolves nothing new."""

    def __init__(
        self,
        db: Database,
        rom: bytes,
        copies: Sequence[StartupCopy],
        protected: Sequence[tuple[int, int]],
        base: int,
    ) -> None:
        super().__init__()
        self.db, self.rom, self.copies, self.protected, self.base = db, rom, copies, protected, base
        self.passes = 0

    def auto_empty(self) -> None:
        global _pending
        self.passes += 1
        try:
            found = _post_analysis(self.db, self.rom, self.copies, self.protected, self.base)
        except (LoadError, IdaDomainError) as exc:
            log(f'Post-analysis stopped: {exc}')
            found = 0
        # ponytail: bounded re-runs over analyzed code only; raise _MAX_PASSES for deeper chains.
        if not found or self.passes >= _MAX_PASSES:
            self.unhook()
            _pending = None

    def closebase(self) -> None:
        global _pending
        self.unhook()
        _pending = None


def schedule_post_analysis(
    db: Database, rom: bytes, recovery: StartupRecovery | StartupRecoveryFailure, base: int
) -> None:
    global _pending
    recovered = isinstance(recovery, StartupRecovery)
    copies = recovery.copies if recovered else ()
    protected = recovery.protected if recovered else ((base, base + 0xC0),)
    _pending = PostAnalysis(db, rom, copies, protected, base)
    _pending.hook()
    require(_pending.is_hooked, 'Cannot schedule post-analysis passes')


def _decode(db: Database, ea: int | None) -> insn_t | None:
    if ea is None or not db.is_valid_ea(ea) or not db.bytes.is_code_at(ea):
        return None

    return db.instructions.get_at(ea)


def _function_start(db: Database, ea: int) -> int | None:
    function = db.functions.get_at(ea)
    return function.start_ea if function else None


def _function_starts(db: Database) -> list[int]:
    return [function.start_ea for function in db.functions.get_all()]


def _link_call(
    db: Database,
    site: int,
    pointer: int,
    *,
    rom: bytes,
    copies: Sequence[StartupCopy],
    protected: Sequence[tuple[int, int]],
    base: int,
) -> bool:
    """Add a proven call reference from site; True only when it is new."""
    address = pointer & ~1
    if not code_pointer(pointer, rom, copies, protected, base) or any(
        xref.from_ea == site for xref in db.xrefs.to_ea(address)
    ):
        return False

    if db.bytes.is_data_at(address) or db.bytes.is_tail_at(address):
        return False

    if db.bytes.is_code_at(address):
        if arm.thumb_state(address) != pointer & 1:
            return False
    else:
        arm.set_thumb(address, pointer & 1)

    db.auto_analysis.schedule_function(address)
    # Keep the actual branch-to-veneer call as well as its proven callee.
    require(db.xrefs.add_code_ref(site, address, XrefType.CALL_NEAR), f'Cannot add resolved call at {site:#x}')
    if not db.comments.get_at(site):
        db.comments.set_at(site, f'Literal/BX veneer resolves to {address:#010x}')
    return True


def _post_analysis(
    db: Database,
    rom: bytes,
    copies: Sequence[StartupCopy],
    protected: Sequence[tuple[int, int]],
    base: int,
) -> int:
    swis = 0
    # ponytail: rescans every analyzed instruction per pass; track changed functions if large ROMs stall.
    # Constant-register BX (e.g. ldr r1,=main; mov lr,pc; bx r1) is resolved natively by IDA's ARM module.
    for function_ea in _function_starts(db):
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
                swis += db.comments.set_at(ea, f'BIOS SWI {number:#04x} {BIOS_CALL_NAMES[number]}')

    branches = _resolve_veneers(db, rom, copies, protected, base)
    handlers = _resolve_irq_handlers(db, rom, copies, protected, base)
    log(f'Post-analysis pass: {branches} veneer calls, {handlers} IRQ handlers, {swis} BIOS calls')
    return branches + handlers


def _literal(
    db: Database, load: insn_t | None, reg: int, *, rom: bytes, copies: Sequence[StartupCopy], base: int
) -> int | None:
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
            base <= pool <= base + len(rom) - 4
            or any(c.destination <= pool <= c.destination + c.size - 4 for c in copies)
        )
    ):
        return None

    return db.bytes.get_dword_at(pool, allow_uninitialized=True)


def _resolve_veneers(
    db: Database,
    rom: bytes,
    copies: Sequence[StartupCopy],
    protected: Sequence[tuple[int, int]],
    base: int,
) -> int:
    """Shared Thumb BX veneers: the register differs per caller, so resolve at each call site."""
    count = 0
    for ea in _function_starts(db):
        function = db.functions.get_at(ea)
        first = _decode(db, ea) if arm.thumb_state(ea) == 1 else None
        if function is None or first is None:
            continue

        branch = first if first.itype == ida_allins.ARM_bx else _decode(db, ea + first.size)
        if branch is None or branch.itype != ida_allins.ARM_bx or branch.ea + branch.size != function.end_ea:
            continue

        target = db.instructions.get_operand(branch, 0)
        if not isinstance(target, RegisterOperand):
            continue

        for call in list(db.xrefs.calls_to_ea(ea)):
            load = first if branch is not first else _decode(db, db.heads.get_previous(call))
            if branch is first and (
                load is None or load.ea + load.size != call or _function_start(db, load.ea) != _function_start(db, call)
            ):
                continue

            pointer = _literal(db, load, target.register_number, rom=rom, copies=copies, base=base)
            if pointer is not None:
                count += _link_call(db, call, pointer, rom=rom, copies=copies, protected=protected, base=base)

    return count


def _resolve_irq_handlers(
    db: Database,
    rom: bytes,
    copies: Sequence[StartupCopy],
    protected: Sequence[tuple[int, int]],
    base: int,
) -> int:
    """Constant ARM handlers stored to the BIOS IRQ vector near a load of its address."""
    count = 0
    for vector in IRQ_VECTORS:
        loads = set()
        for xref in db.xrefs.to_ea(vector):
            if db.bytes.is_code_at(xref.from_ea):
                loads.add(xref.from_ea)
            else:
                loads.update(pool.from_ea for pool in db.xrefs.to_ea(xref.from_ea) if db.bytes.is_code_at(pool.from_ea))

        for load in loads:
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
                insn = _decode(db, ea)
                if insn is None:
                    break

                if insn.itype != ida_allins.ARM_str:
                    continue

                stored = db.instructions.get_operand(insn, 0)
                address = db.instructions.get_operand(insn, 1)
                if (
                    not isinstance(address, MemoryOperand)
                    or address.type != OperandType.DISPLACEMENT
                    or not isinstance(stored, RegisterOperand)
                ):
                    continue

                phrase, displacement = address.get_phrase_number(), address.get_displacement()
                if phrase is None or displacement is None:
                    continue

                target = ida_regfinder.find_reg_value(ea, phrase)
                if target is None or (target + displacement) & 0xFFFFFFFF != vector:
                    continue

                handler = ida_regfinder.find_reg_value(ea, stored.register_number)
                if (
                    handler is None
                    or not code_pointer(handler, rom, copies, protected, base)
                    or handler % 4
                    or any(x.from_ea == ea for x in db.xrefs.to_ea(handler))
                ):
                    continue

                code = db.bytes.is_code_at(handler)
                user_named = db.bytes.has_user_name_at(handler)
                if db.bytes.is_data_at(handler) or db.bytes.is_tail_at(handler) or (code and arm.thumb_state(handler)):
                    continue

                if not code:
                    arm.set_thumb(handler, 0)
                db.auto_analysis.schedule_function(handler)
                if not user_named:
                    db.names.set_name(handler, 'GBA_IrqMain', SetNameFlags.NOWARN | SetNameFlags.FORCE)
                require(
                    db.xrefs.add_data_ref(ea, handler, XrefType.OFFSET), f'Cannot reference IRQ handler from {ea:#x}'
                )
                if not db.comments.get_at(ea):
                    db.comments.set_at(ea, f'Installs ARM BIOS IRQ handler {handler:#010x}')
                count += 1

    return count
