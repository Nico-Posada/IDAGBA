"""Build the FLIRT signatures next to this script from the runtime libraries of the two GBA toolchains.

- `gba_agbcc.sig`: libgcc and libc of pret/agbcc, the rebuilt gcc 2.9x of Nintendo's AGB SDK that
  commercial games were compiled with.
- `gba_devkitarm.sig`: devkitARM's libgcc, newlib libc/libm and libsysbase (ARM and Thumb multilibs),
  plus libgba, libtonc and maxmod, used by homebrew.

Steps: drop libgcc's fixed-point members, run pelf on every archive, run sigmake, and if it reports
collisions keep one name per group of identical modules and run sigmake again. pelf gives Thumb
functions an odd offset; IDA reads that as Thumb state, so it stays.

Inputs, all on Linux (the shipped files come from agbcc da598c1 and devkitARM r68: gcc 16.1.0, newlib 4.6.0,
libgba 0.5.4, libtonc 1.4.5, maxmod 1.0.15):

    git clone https://github.com/pret/agbcc && (cd agbcc && ./build.sh)
    docker cp "$(docker create devkitpro/devkitarm)":/opt/devkitpro devkitpro
    uv run sig/build.py "$IDADIR/tools/flair" agbcc devkitpro

Build with the flair tools of IDA 9.2 to 9.4. Their sigmake writes signature format 10, which every
supported IDA reads. The sigmake of IDA 9.5 writes format 11, and IDA 9.4 and older refuse such a
file with "unexpected signature file version" and name nothing.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    flair, agbcc, devkitpro = (Path(arg).resolve() for arg in sys.argv[1:4])
    arm = devkitpro / 'devkitARM'
    libgcc = arm / 'lib' / 'gcc' / 'arm-none-eabi' / '16.1.0'
    newlib = arm / 'arm-none-eabi' / 'lib'
    signatures = {
        'gba_agbcc': ('GBA agbcc (AGB SDK gcc 2.9x) libgcc and libc', [agbcc / 'libgcc.a', agbcc / 'libc.a']),
        'gba_devkitarm': (
            'GBA devkitARM libgcc, newlib, libgba, libtonc and maxmod',
            [
                libgcc / 'libgcc.a',
                libgcc / 'thumb' / 'libgcc.a',
                *(newlib / mode / name for mode in ('', 'thumb') for name in ('libc.a', 'libm.a', 'libsysbase.a')),
                devkitpro / 'libgba' / 'lib' / 'libgba.a',
                devkitpro / 'libgba' / 'lib' / 'libmm.a',
                devkitpro / 'libtonc' / 'lib' / 'libtonc.a',
            ],
        ),
    }
    with tempfile.TemporaryDirectory() as work:
        builder = _Builder(flair, arm / 'bin' / 'arm-none-eabi-ar', Path(work))
        for name, (title, archives) in signatures.items():
            builder.build(name, title, archives)


class _Builder:
    def __init__(self, flair: Path, ar: Path, work: Path) -> None:
        self.flair, self.ar, self.work = flair, ar, work

    def build(self, name: str, title: str, archives: list[Path]) -> None:
        patterns = [self._pattern(f'{name}_{index}', archive) for index, archive in enumerate(archives)]
        sig = Path(__file__).resolve().parent / f'{name}.sig'
        exc = self.work / f'{name}.exc'
        command = [self.flair / 'sigmake', f'-n{title}', *patterns, self.work / sig.name]
        if subprocess.run(command, check=False, capture_output=True).returncode:  # noqa: S603
            if exc.exists():  # sigmake fails on collisions after listing them there
                _keep_one_per_collision(exc)

            _run(command)

        shutil.copyfile(self.work / sig.name, sig)
        _run([self.flair / 'zipsig', sig])

    def _pattern(self, stem: str, archive: Path) -> Path:
        if archive.name == 'libgcc.a':
            archive = self._without_fixed_point(stem, archive)

        pattern = self.work / f'{stem}.pat'
        # Untyped symbols are local labels (agbcc's Ldiv0, .gcc2_compiled.) that would split functions,
        # except in these hand-written assembly libraries, whose functions lack a .type directive.
        untyped_functions = archive.name in {'libgba.a', 'libmm.a', 'libtonc.a'}
        # Under 8 known bytes a pattern (return -1, return 0) matches unrelated game code.
        _run([self.flair / 'pelf', '-M8', *([] if untyped_functions else ['-N']), archive, pattern])
        return pattern

    def _without_fixed_point(self, stem: str, archive: Path) -> Path:
        copy = self.work / f'{stem}.a'
        shutil.copyfile(archive, copy)
        members = _run([self.ar, 't', copy]).split()
        # Fixed-point helpers (_addQQ.o, _fractSQHA.o, ...) are 1600 members GBA code never calls.
        _run([self.ar, 'd', copy, *(m for m in members if re.search(r'QQ|HQ|SQ|DQ|TQ|HA|SA|DA|TA', m))])
        return copy


def _keep_one_per_collision(exc: Path) -> None:
    """Select one more module in each group sigmake could not split by the names the modules reference.

    The modules left unselected in a group are identical down to their references (abs/labs), so any name is right.
    """
    text = '\n'.join(line for line in exc.read_text().splitlines() if not line.startswith(';'))
    groups = []
    for group in re.split(r'\n\s*\n', text.strip()):
        lines = group.splitlines()
        if open_lines := [i for i, line in enumerate(lines) if not line.startswith('+')]:
            best = min(open_lines, key=lambda i: _preference(lines[i].split()[0]))
            lines[best] = f'+{lines[best]}'

        groups.append('\n'.join(lines))

    exc.write_text('\n\n'.join(groups) + '\n')


def _preference(name: str) -> tuple[bool, int, str]:
    """Prefer the public spelling (tolower over _tolower), then the shortest name."""
    return name.startswith('_'), len(name), name


def _run(command: list) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout  # noqa: S603


if __name__ == '__main__':
    main()
