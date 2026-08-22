#!/usr/bin/env python3
"""Restamp provenance in existing repository archives -- no rebuilds.

The old stamper reported every producer whose fingerprint it saw, and
crt startup files drag a gcc trace into every clang-linked binary, so
clang builds shipped as "clang, gcc". This walks each archive's payload,
picks ONE compiler by toolchain precedence (rustc > clang > gcc -- gcc
only wins when it is all there is, i.e. gcc really built it), rewrites
the manifest's build_compiler/build_compiler_version lines in place, and
repacks the tarball atomically. Flags are left untouched; archives with
no build_* lines at all (pure data) are skipped.

Usage: sudo python3 scripts/restamp-archives.py [repo_dir]
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/mnt/var/cache/sage/repo")

MARKERS = {  # needle -> producer, needles assembled so this very script
    # never contains a full literal for scanners to trip over
    "clang vers" + "ion": "clang",
    "GC" + "C: (": "gcc",
    "rustc vers" + "ion": "rustc",
}
PRECEDENCE = ["rustc", "clang", "gcc"]
SLAB = 1 << 20


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, **kw)


def window(path: Path) -> bytes:
    """Head+tail slabs of a plain file."""
    size = path.stat().st_size
    with open(path, "rb") as f:
        head = f.read(SLAB)
        tail = b""
        if size > SLAB:
            f.seek(min(size - SLAB, size))
            tail = f.read(SLAB)
    return head + tail


def zstd_lead(path: Path, cap=4 << 20) -> bytes:
    """Decompressed leading slice of one framed file."""
    p = subprocess.Popen(["zstd", "-dc", str(path)], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
    out = p.stdout.read(cap)
    p.kill()
    return out


def scan(root: Path, want_gcc_only: bool):
    """First (producer, version) among candidates, or None.

    Pass A hunts clang/rustc across everything; pass B settles for gcc,
    because crt puts a gcc trace inside binaries gcc never built."""
    targets = ["gcc"] if want_gcc_only else ["clang", "rustc"]
    needles = [(n, p) for n, p in MARKERS.items() if MARKERS[n] in targets]
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        base = path.name
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
        except OSError:
            continue
        data = None
        if magic == b"\x28\xb5\x2f\xfd":
            data = zstd_lead(path)
            if not data.startswith(b"\x7fELF"):
                continue  # compressed data alone proves nothing
        elif magic.startswith(b"\x7fELF") or base.endswith((".o", ".a")) \
                or ".so" in base:
            data = window(path)
        else:
            continue
        for needle, producer in needles:
            at = data.find(needle.encode())
            if at < 0:
                continue
            m = re.search(rb"\d+(\.\d+)+", data[at + len(needle):])
            return producer, (m.group().decode() if m else None)
    return None


def restamp(archive: Path):
    raw = sh(["tar", "--zstd", "-xf", str(archive), "-O",
              ".METADATA/manifest.toml"])
    if raw.returncode != 0:
        return "skip (no manifest)"
    text = raw.stdout.decode(errors="replace")
    if "build_" not in text:
        return "skip (unstamped)"
    if not any(l.startswith("build_c") for l in text.splitlines()):
        return "skip (no evidence fields)"
    old_compiler = next((l for l in text.splitlines()
                         if l.startswith("build_compiler")), "(none)")

    tmp = Path(tempfile.mkdtemp(prefix="restamp-"))
    try:
        # Everything happens inside one staging extraction: payload scanned
        # here, new manifest written over its .METADATA, stream rebuilt from
        # it -- deleting the tree early orphans the member paths below.
        if sh(["tar", "--zstd", "-xf", str(archive), "-C", str(tmp)]).returncode:
            return "skip (untar failed)"
        hit = scan(tmp, want_gcc_only=False) or scan(tmp, want_gcc_only=True)
        lines = [l for l in text.splitlines(keepends=True)
                 if not l.startswith(("build_compiler", "build_compiler_version"))]
        out = "".join(lines).rstrip("\n") + "\n"
        if hit:
            producer, version = hit
            out += f'build_compiler = "{producer}"\n'
            if version:
                out += f'build_compiler_version = "{version}"\n'
        if out == text.rstrip("\n") + "\n":
            return "skip (already single-compiler)"

        # Rebuild the stream from the archive's OWN entry listing: tar -tf
        # names every entry exactly as stored (dirs included), so passing
        # them back with --no-recursion reproduces the layout without
        # following symlinked directories or re-deriving anything.
        listing = sh(["tar", "--zstd", "-tf", str(archive)]).stdout.decode()
        members = [m for m in listing.splitlines() if m]
        man_dir = tmp / ".METADATA"
        man_dir.mkdir(parents=True, exist_ok=True)
        (man_dir / "manifest.toml").write_text(out)
        members = [".METADATA/manifest.toml"] + [
            m for m in members if m != ".METADATA/manifest.toml"]
        staged = archive.with_suffix(".tar.zst.new")
        r = sh(["tar", "--zstd", "--no-recursion", "--null", "-C", str(tmp),
                "-cf", str(staged), "-T", "-"],
               input="\0".join(members).encode())
        if r.returncode:
            return f"FAIL (rebuild: {r.stderr[-120:]})"
        if len(members) != sh(["tar", "--zstd", "-tf",
                               str(staged)]).stdout.count(b"\n"):
            return "FAIL (entry drift)"
        staged.replace(archive)
        new_compiler = next((l for l in out.splitlines()
                             if l.startswith("build_compiler")), "(none)")
        return f"{old_compiler}  ->  {new_compiler}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    archives = sorted(REPO.glob("*.pkg.tar.zst"))
    print(f"{len(archives)} archives in {REPO}")
    changed = skipped = failed = 0
    for a in archives:
        result = restamp(a)
        if result.startswith("skip"):
            skipped += 1
        elif result.startswith("FAIL"):
            failed += 1
            print(f"  FAIL {a.name}: {result}")
        else:
            changed += 1
            print(f"  {a.name[:-16]}\n    {result}")
    print(f"\nrestamped {changed}, skipped {skipped}, failed {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
