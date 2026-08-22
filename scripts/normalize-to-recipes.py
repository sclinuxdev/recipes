#!/usr/bin/env python3
"""Normalize repository artifacts to the releases the recipes declare.

The git tree is the single source of truth for stepping: an archive whose
embedded release (or filename) disagrees with its recipe is rewritten --
manifest release line swapped through the archive's own entry listing,
file renamed -- until every published name lands on recipe-declared
<name>-<version>-<release>. Stale releases nothing declares are removed.

Usage: sudo python3 scripts/normalize-to-recipes.py [--dry-run]
"""

import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

RECIPES = Path("/home/ir/recipes")
REPO = Path("/mnt/var/cache/sage/repo")
MIRROR = Path("/mnt/recipes")
DRY = "--dry-run" in sys.argv


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, **kw)


def rewrite_release(archive: Path, declared_rel: str, out_path: Path) -> str | None:
    """Copy archive to out_path with its manifest release set; None on error."""
    raw = sh(["tar", "--zstd", "-xf", str(archive), "-O",
              ".METADATA/manifest.toml"])
    if raw.returncode != 0:
        return "no manifest"
    tmp = Path(tempfile.mkdtemp(prefix="norm-"))
    try:
        if sh(["tar", "--zstd", "-xf", str(archive), "-C", str(tmp)]).returncode:
            return "untar failed"
        man = tmp / ".METADATA" / "manifest.toml"
        text = man.read_text()
        lines = []
        for l in text.splitlines(keepends=True):
            if l.startswith("release = "):
                l = f'release = "{declared_rel}"\n'
            lines.append(l)
        man.write_text("".join(lines))
        members = [m for m in sh(["tar", "--zstd", "-tf",
                                  str(archive)]).stdout.decode().splitlines() if m]
        members = [".METADATA/manifest.toml"] + [
            m for m in members if m != ".METADATA/manifest.toml"]
        r = sh(["tar", "--zstd", "--no-recursion", "--null", "-C", str(tmp),
                "-cf", str(out_path), "-T", "-"],
               input="\0".join(members).encode())
        if r.returncode:
            return f"rebuild: {r.stderr[-100:]}"
        if len(members) != sh(["tar", "--zstd", "-tf",
                               str(out_path)]).stdout.count(b"\n"):
            return "entry drift"
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    recipes = {}
    for rc in sorted(RECIPES.glob("*/*/*/recipe.toml")):
        p = tomllib.load(open(rc, "rb"))["package"]
        recipes.setdefault(f"{p['name']}-{p['version']}-{p['release']}",
                           p)

    # One archive per recipe row: pick the best existing build of this
    # name-version (exact declared release first, then newest), rewrite it
    # onto the declared stem when it drifted, and drop every leftover.
    consumed = set()
    kept = rewritten = 0
    missing = []
    for rc in sorted(RECIPES.glob("*/*/*/recipe.toml")):
        p = tomllib.load(open(rc, "rb"))["package"]
        stem = f"{p['name']}-{p['version']}-{p['release']}"
        name_ver = stem.rsplit("-", 1)[0]
        cands = sorted(
            (a for a in REPO.glob(f"{name_ver}-*.pkg.tar.zst")
             if str(a) not in consumed),
            key=lambda a: (a.name != f"{stem}-x86_64.pkg.tar.zst",
                           a.name != f"{stem}-any.pkg.tar.zst", a.name))
        # The recipe's own mirror dir is the only other honest home for its
        # build output -- no tree walks.
        mirror_dir = MIRROR / rc.parent.relative_to(RECIPES)
        mirror_hits = sorted(mirror_dir.glob(f"{stem}-*.pkg.tar.zst"))
        if mirror_hits:
            cands.append(mirror_hits[0])
        if not cands:
            missing.append(stem)
            continue
        src = cands[0]
        arch = src.name[len(stem) + 1:-len(".pkg.tar.zst")]
        dest = REPO / f"{stem}-{arch}.pkg.tar.zst"
        exact = src.name == dest.name
        if DRY:
            tag = "keep" if exact else f"{src.name} -> {dest.name}"
            print(f"  {tag}")
        else:
            if not exact:
                err = rewrite_release(src, p["release"], dest)
                if err:
                    print(f"FAIL {stem}: {err}")
                    continue
                if src.exists():
                    src.unlink()
                rewritten += 1
                consumed.add(str(dest))  # a fresh output is not an orphan
                print(f"  {src.name} -> {dest.name}")
            else:
                man = sh(["tar", "--zstd", "-xf", str(src), "-O",
                          ".METADATA/manifest.toml"]).stdout.decode()
                want = f'release = "{p["release"]}"'
                if want not in man.splitlines() and any(
                        l.startswith("release = ") for l in man.splitlines()):
                    err = rewrite_release(src, p["release"],
                                          src.with_suffix(".tar.zst.new"))
                    if err:
                        print(f"FAIL {stem} inline: {err}")
                        continue
                    src.with_suffix(".tar.zst.new").replace(src)
                    rewritten += 1
                    print(f"  inlined release fix: {src.name}")
                else:
                    kept += 1
        consumed.update(str(a) for a in cands[:1] if a != dest)
        if exact:
            consumed.add(str(dest))

    # Whatever no recipe consumed is a superseded release.
    removed = 0
    for a in sorted(REPO.glob("*.pkg.tar.zst")):
        if str(a) not in consumed:
            removed += 1
            print(f"  orphan removed: {a.name}")
            if not DRY:
                a.unlink()

    print(f"\nrewrote {rewritten}, kept {kept}, orphans {removed}, "
          f"{len(missing)} recipes without artifact")
    for m in missing:
        print(f"  MISSING: {m}")


if __name__ == "__main__":
    sys.exit(main())
