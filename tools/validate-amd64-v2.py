#!/usr/bin/env python3
"""Fail-closed static and staged-payload audit for amd64 recipe-v2 trees.

This intentionally does not pretend that TOML parsing proves a build.  The
normal CI job runs the static checks; a builder can pass --build to invoke Sage
for every recipe and --staging to additionally check an already produced pkg/
tree against the declared output boundary.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path


INSTALL_KEYS = ("install_files", "install_excludes")
TRANSFORM_KEYS = ("install_copies", "install_moves", "install_removes", "install_generates", "install_symlinks")


def rel_safe(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and not value.startswith("data/")


def payload_match(patterns: list[str], rel: str) -> bool:
    return any(fnmatch.fnmatchcase(rel, pattern) for pattern in patterns)


def staged_files(staging: Path) -> list[str]:
    return sorted(
        p.relative_to(staging).as_posix()
        for p in staging.rglob("*")
        if p.is_file() or p.is_symlink()
    )


def check_staging(recipe: dict, staging: Path, label: str, errors: list[str]) -> None:
    build = recipe.get("build", {})
    files = build.get("install_files", [])
    excludes = build.get("install_excludes", [])
    actual = staged_files(staging)
    if not files:
        return
    for pattern in files:
        if not any(fnmatch.fnmatchcase(path, pattern) for path in actual):
            errors.append(f"{label}: install_files pattern matched nothing: {pattern}")
    for path in actual:
        if not payload_match(files, path) or payload_match(excludes, path):
            errors.append(f"{label}: staged payload is outside declared boundary: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=Path(__file__).resolve().parents[1], type=Path)
    parser.add_argument("--build", action="store_true", help="invoke Sage for every recipe (slow, networked)")
    parser.add_argument("--sage", default="sage", help="Sage executable used with --build")
    parser.add_argument("--staging", type=Path, help="audit one existing recipe pkg/ staging directory")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    recipes = sorted(args.root.glob("**/amd64/*/recipe.toml"))
    errors: list[str] = []
    warnings: list[str] = []
    counts = {"recipes": 0, "v1": 0, "v2": 0, "v2_split": 0}
    parsed: list[tuple[Path, dict]] = []

    for path in recipes:
        counts["recipes"] += 1
        try:
            with path.open("rb") as stream:
                recipe = tomllib.load(stream)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"{path}: cannot parse TOML: {exc}")
            continue
        parsed.append((path, recipe))
        schema = recipe.get("schema_version", 1)
        if schema == 1:
            counts["v1"] += 1
            continue
        if schema != 2:
            errors.append(f"{path}: unsupported schema_version {schema}")
            continue
        counts["v2"] += 1
        package = recipe.get("package", {})
        name = package.get("name", path.parent.name)
        build = recipe.get("build")
        if not isinstance(build, dict):
            errors.append(f"{path}: v2 recipe has no [build] table")
            continue
        if name.endswith(("-libs", "-dev")):
            counts["v2_split"] += 1
            if not build.get("install_files") and not build.get("outputs"):
                errors.append(f"{path}: split output has no explicit install_files boundary")
        for key in INSTALL_KEYS:
            for value in build.get(key, []):
                if not isinstance(value, str) or not rel_safe(value):
                    errors.append(f"{path}: invalid {key} path/pattern: {value!r}")
        for key in TRANSFORM_KEYS:
            entries = build.get(key, [])
            if not isinstance(entries, list):
                errors.append(f"{path}: build.{key} must be an array")
        for key in ("install_copies", "install_moves"):
            for entry in build.get(key, []):
                if not isinstance(entry, dict) or not rel_safe(entry.get("from", "")) or not rel_safe(entry.get("to", "")):
                    errors.append(f"{path}: invalid build.{key} entry: {entry!r}")
        for entry in build.get("install_generates", []):
            if not isinstance(entry, dict) or not rel_safe(entry.get("path", "")) or not isinstance(entry.get("content"), str):
                errors.append(f"{path}: invalid build.install_generates entry: {entry!r}")
        for entry in build.get("install_symlinks", []):
            if not isinstance(entry, dict) or not rel_safe(entry.get("path", "")):
                errors.append(f"{path}: invalid build.install_symlinks entry: {entry!r}")
            else:
                target = Path(entry.get("target", ""))
                resolved = (Path(entry["path"]).parent / target).as_posix().split("/")
                depth = 0
                escapes = False
                for component in resolved:
                    if component in ("", "."):
                        continue
                    if component == "..":
                        depth -= 1
                        if depth < 0:
                            escapes = True
                    else:
                        depth += 1
                if target.is_absolute() or escapes:
                    errors.append(f"{path}: symlink target escapes staging root: {entry!r}")
        source_entries = recipe.get("source", []) if isinstance(recipe.get("source"), list) else []
        extra_names = {
            Path(str(source.get("url", "")).split("?", 1)[0].split("#", 1)[0]).name
            for source in source_entries[1:]
            if isinstance(source, dict)
        }
        for patch in build.get("patches", []):
            if not isinstance(patch, str) or Path(patch).name != patch:
                errors.append(f"{path}: patch must be a distfiles basename: {patch!r}")
            elif not (path.parent / patch).exists() and patch not in extra_names:
                warnings.append(f"{path}: local patch attachment is absent: {patch}")
        for source in recipe.get("source", []) if isinstance(recipe.get("source"), list) else []:
            if isinstance(source, dict) and source.get("url", "").startswith("file:"):
                warnings.append(f"{path}: file source is intentionally builder-local: {source['url']}")
        if args.staging and path.parent == args.staging.parent:
            check_staging(recipe, args.staging, str(path), errors)

    if args.build:
        for path, recipe in parsed:
            if recipe.get("schema_version", 1) != 2:
                continue
            result = subprocess.run([args.sage, "build", str(path.parent)], check=False)
            if result.returncode:
                errors.append(f"{path}: Sage build failed with exit {result.returncode}")

    report = {"counts": counts, "errors": errors, "warnings": warnings}
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"amd64 recipes={counts['recipes']} v1={counts['v1']} v2={counts['v2']} v2_split={counts['v2_split']}")
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
