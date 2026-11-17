"""Messages for IDA's output window, prefixed by severity."""

from __future__ import annotations

import ida_kernwin


def log(message: str) -> None:
    ida_kernwin.msg(f'[GBA] {message}\n')


def warn(message: str) -> None:
    ida_kernwin.msg(f'[GBA WARN] {message}\n')


def error(message: str) -> None:
    ida_kernwin.msg(f'[GBA ERROR] {message}\n')
