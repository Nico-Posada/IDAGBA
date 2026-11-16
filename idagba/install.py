"""Make IDA discover the loader: IDA scans only its loaders/ directories."""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def _first_line(path: Path) -> str:
    with path.open(encoding='utf-8') as file:
        return file.readline()


def install_loader_link(loaders_dir: Path, target: Path) -> Path:
    """Make loaders_dir/<target.name> resolve to target: a symlink, or a copy where symlinks are refused.

    Raises:
        FileExistsError: a regular file with that name exists and is not a copy of an idagba entry file.
        OSError: the directory, the link and the copy cannot be created.
    """
    link = loaders_dir / target.name
    loaders_dir.mkdir(parents=True, exist_ok=True)
    if link.is_symlink():
        if link.resolve() == target.resolve():
            return link

        link.unlink()  # stale or dangling: the plugin directory moved
    elif link.exists():
        if _first_line(link) != _first_line(target):
            msg = f'{link} exists and was not installed by idagba'
            raise FileExistsError(msg)

        if link.read_bytes() == target.read_bytes():
            return link

        link.unlink()  # outdated copy from an earlier version
    try:
        link.symlink_to(target)
    except OSError:  # Windows without Developer Mode or administrator rights
        shutil.copyfile(target, link)
    return link
