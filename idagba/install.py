"""Puts the loader file where IDA looks for loaders."""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def install_loader_link(loaders_dir: Path, target: Path) -> Path:
    """Link target into loaders_dir, or copy it where symlinks are not allowed.

    Raises:
        FileExistsError: a file with that name exists and is not ours.
        OSError: the link or the copy could not be created.
    """
    link = loaders_dir / target.name
    loaders_dir.mkdir(parents=True, exist_ok=True)
    if link.is_symlink():
        if link.resolve() == target.resolve():
            return link

        # loader stub is stale, delete it
        link.unlink()
    elif link.exists():
        if _first_line(link) != _first_line(target):
            msg = f'{link} exists and was not installed by idagba'
            raise FileExistsError(msg)

        if link.read_bytes() == target.read_bytes():
            return link

        # we have an outdated copy, delete it
        link.unlink()

    try:
        link.symlink_to(target)
    except OSError:  # Windows without Developer Mode or administrator rights
        shutil.copyfile(target, link)

    return link


def _first_line(path: Path) -> str:
    with path.open(encoding='utf-8') as file:
        return file.readline()
