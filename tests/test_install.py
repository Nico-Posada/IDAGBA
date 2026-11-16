from __future__ import annotations

from pathlib import Path

import pytest

from idagba.install import install_loader_link


def _entry(directory: Path, body: str = 'pass\n') -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / 'idagba_loader.py'
    target.write_text('"""IDA loader entry for idagba."""\n' + body)
    return target


def test_symlink_is_created_and_kept(tmp_path: Path):
    target = _entry(tmp_path / 'plugin' / 'loaders')
    loaders = tmp_path / 'usr' / 'loaders'
    link = install_loader_link(loaders, target)
    assert link == loaders / target.name
    assert link.is_symlink()
    assert link.resolve() == target.resolve()
    inode = link.lstat().st_ino
    assert install_loader_link(loaders, target).lstat().st_ino == inode


def test_symlink_into_another_directory_is_retargeted(tmp_path: Path):
    old = _entry(tmp_path / 'old')
    target = _entry(tmp_path / 'new')
    loaders = tmp_path / 'loaders'
    install_loader_link(loaders, old)
    link = install_loader_link(loaders, target)
    assert link.resolve() == target.resolve()


def test_copy_fallback_is_refreshed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def refuse(*_: object) -> None:
        raise OSError

    monkeypatch.setattr(Path, 'symlink_to', refuse)
    target = _entry(tmp_path / 'plugin')
    loaders = tmp_path / 'loaders'
    link = install_loader_link(loaders, target)
    assert not link.is_symlink()
    assert link.read_bytes() == target.read_bytes()
    _entry(tmp_path / 'plugin', 'x = 1\n')
    install_loader_link(loaders, target)
    assert link.read_bytes() == target.read_bytes()


def test_foreign_file_is_left_alone(tmp_path: Path):
    target = _entry(tmp_path / 'plugin')
    loaders = tmp_path / 'loaders'
    loaders.mkdir()
    foreign = loaders / target.name
    foreign.write_text('"""Someone else."""\n')
    with pytest.raises(FileExistsError):
        install_loader_link(loaders, target)
    assert foreign.read_text() == '"""Someone else."""\n'
