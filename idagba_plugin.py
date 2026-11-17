"""IDA plugin entry point for idagba: installs the loader link and manages the BIOS call lifter."""

from __future__ import annotations

from pathlib import Path

import ida_diskio
import ida_idaapi
from ida_domain import Database
from ida_domain.hooks import DatabaseHooks, UIHooks

from idagba import lifter
from idagba.install import install_loader_link
from idagba.logging import error
from idagba.recognition import FORMAT_MARKER


def PLUGIN_ENTRY() -> IdaGbaPlugin:
    return IdaGbaPlugin()


class IdaGbaPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_HIDE
    wanted_name = 'GBA loader and BIOS call lifter'
    comment = 'Installs the Game Boy Advance loader and decompiles BIOS SWI/SVC instructions as typed helper calls'
    help = ''
    wanted_hotkey = ''

    def init(self) -> IdaGbaPlugmod:
        return IdaGbaPlugmod()


class IdaGbaPlugmod(ida_idaapi.plugmod_t):
    def __init__(self) -> None:
        super().__init__()
        loader_entry = Path(__file__).resolve().parent / 'loaders' / 'idagba_loader.py'
        try:
            install_loader_link(Path(ida_diskio.get_user_idadir()) / 'loaders', loader_entry)
        except OSError as exc:
            error(f'Cannot install the loader into $IDAUSR/loaders: {exc}')

        self._hooks = (_Opened(), _Closing())
        for hook in self._hooks:
            hook.hook()

    def run(self, arg: int) -> bool:
        return True

    def __del__(self) -> None:
        for hook in getattr(self, '_hooks', ()):
            hook.unhook()


class _Opened(UIHooks):
    def database_inited(self, is_new_database: int, idc_script: str) -> None:
        if FORMAT_MARKER in (Database.open().format or ''):
            lifter.install()


class _Closing(DatabaseHooks):
    def closebase(self) -> None:
        lifter.uninstall()
