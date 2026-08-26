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
import re
import subprocess
import sys
import tomllib
from pathlib import Path


INSTALL_KEYS = ("install_files", "install_excludes")
TRANSFORM_KEYS = ("install_copies", "install_moves", "install_removes", "install_generates", "install_symlinks")
BUILD_SYSTEMS = {"autotools", "cmake", "meson", "xmake", "cargo", "make", "script"}
STEP_PHASES = {"prepare", "pre-build", "post-build", "pre-install", "install", "post-install"}
STEP_CWDS = {"source", "build", "package"}
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def rel_safe(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and not value.startswith("data/")


def payload_match(patterns: list[str], rel: str) -> bool:
    return any(fnmatch.fnmatchcase(rel, pattern) for pattern in patterns)


def pattern_covered(pattern: str, exclusions: list[str]) -> bool:
    # For the recipe glob vocabulary, matching the sibling's literal pattern
    # is a conservative overlap test. It catches exact paths, `*.so.*` style
    # families and recursive `/**` boundaries without pretending arbitrary
    # glob inclusion is a full SAT problem.
    return any(fnmatch.fnmatchcase(pattern, exclusion) for exclusion in exclusions)


def staged_files(staging: Path) -> list[str]:
    return sorted(
        p.relative_to(staging).as_posix()
        for p in staging.rglob("*")
        if p.is_file() or p.is_symlink()
    )


def source_entries(recipe: dict) -> list[dict]:
    raw = recipe.get("source", [])
    if isinstance(raw, dict):
        return [raw]
    return raw if isinstance(raw, list) else []


def check_backend_options(path: Path, system: str, build: dict, errors: list[str]) -> None:
    options = build.get("configure_options", [])
    if not isinstance(options, list) or not all(isinstance(item, str) for item in options):
        errors.append(f"{path}: build.configure_options must be an array of strings")
        return
    lowered = [item.lower() for item in options]
    forbidden: tuple[str, ...] = ()
    if system == "meson":
        forbidden = ("-dprefix", "-dlibdir", "-dbindir", "-dsbindir", "-dincludedir",
                     "-ddatadir", "-dsysconfdir", "-dlocalstatedir", "-dlocaledir",
                     "-dmandir", "-drunstatedir", "-dlibexecdir", "--native-file",
                     "--cross-file", "--backend", "--buildtype", "-dc_args=",
                     "-dcpp_args=", "-dc_link_args=", "-dcpp_link_args=")
    elif system == "cmake":
        forbidden = ("-dcmake_install_", "-dcmake_c_compiler", "-dcmake_cxx_compiler",
                     "-dcmake_linker", "-dcmake_toolchain_file", "-dcmake_c_flags",
                     "-dcmake_cxx_flags", "-dcmake_exe_linker_flags",
                     "-dcmake_shared_linker_flags", "-dcmake_prefix_path", "-g")
    elif system == "autotools":
        roots = {
            "--prefix": ("/usr",), "--exec-prefix": ("/usr",),
            "--bindir": ("/usr/bin",), "--sbindir": ("/usr/sbin", "/usr/bin"),
            "--libexecdir": ("/usr/libexec", "/usr/lib"), "--libdir": ("/usr/lib",),
            "--includedir": ("/usr/include",), "--oldincludedir": ("/usr/include",),
            "--datarootdir": ("/usr/share",), "--datadir": ("/usr/share",),
            "--infodir": ("/usr/share/info",), "--localedir": ("/usr/share/locale",),
            "--mandir": ("/usr/share/man",), "--docdir": ("/usr/share/doc",),
            "--htmldir": ("/usr/share/doc",), "--dvidir": ("/usr/share/doc",),
            "--pdfdir": ("/usr/share/doc",), "--psdir": ("/usr/share/doc",),
            "--sysconfdir": ("/etc",), "--sharedstatedir": ("/var/lib",),
            "--localstatedir": ("/var",), "--runstatedir": ("/run",),
        }
        for original, lower in zip(options, lowered):
            key, separator, value = original.partition("=")
            if key not in roots:
                continue
            candidate = Path(value) if separator else Path()
            good = (separator and candidate.is_absolute() and ".." not in candidate.parts
                    and any(candidate == Path(root)
                            or str(candidate).startswith(root.rstrip("/") + "/")
                            for root in roots[key]))
            if not good:
                errors.append(f"{path}: autotools installation directory is not canonical: {original}")
        return
    elif system == "xmake":
        forbidden = ("--cc", "--cxx", "--ld", "--toolchain", "--cflags", "--cxflags",
                     "--cxxflags", "--ldflags")
    for original, lower in zip(options, lowered):
        if any(lower == item or lower.startswith(item + "=") for item in forbidden):
            errors.append(f"{path}: {system} option is Sage-managed and cannot be overridden: {original}")


def check_steps(path: Path, system: str, build: dict, errors: list[str]) -> None:
    raw = build.get("steps", [])
    if not isinstance(raw, list):
        errors.append(f"{path}: build.steps must be an array")
        return
    names: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            errors.append(f"{path}: build.steps entries must be inline tables: {entry!r}")
            continue
        name, phase, cwd, command = (entry.get(key) for key in ("name", "phase", "cwd", "command"))
        if not all(isinstance(value, str) and value for value in (name, phase, command)):
            errors.append(f"{path}: build.steps entries require non-empty name/phase/command: {entry!r}")
            continue
        if cwd is None:
            cwd = "source"
        if phase not in STEP_PHASES:
            errors.append(f"{path}: unsupported build.steps phase: {phase}")
        if cwd not in STEP_CWDS:
            errors.append(f"{path}: unsupported build.steps cwd: {cwd}")
        if name in names:
            errors.append(f"{path}: duplicate build.steps name: {name}")
        names.add(name)
    if system == "script" and not raw:
        errors.append(f"{path}: script build requires at least one build.steps entry")


def check_sources(path: Path, recipe: dict, build: dict, errors: list[str], warnings: list[str]) -> set[str]:
    entries = source_entries(recipe)
    if recipe.get("source") not in (None, [], {}) and not entries:
        errors.append(f"{path}: source must be a table or array of tables")
    names: set[str] = set()
    for index, source in enumerate(entries):
        if not isinstance(source, dict):
            errors.append(f"{path}: source entry {index} must be a table")
            continue
        url, sha256 = source.get("url"), source.get("sha256")
        if not isinstance(url, str) or not url:
            errors.append(f"{path}: source entry {index} has no URL")
        if not isinstance(sha256, str) or not HASH_RE.fullmatch(sha256):
            errors.append(f"{path}: source entry {index} must contain a 64-hex SHA-256")
        if isinstance(url, str):
            name = Path(url.split("?", 1)[0].split("#", 1)[0]).name
            if name and index > 0:
                names.add(name)
            if url.startswith("file:"):
                warnings.append(f"{path}: file source is intentionally builder-local: {url}")
    for patch in build.get("patches", []) if isinstance(build.get("patches", []), list) else []:
        if not isinstance(patch, str) or Path(patch).name != patch:
            errors.append(f"{path}: patch must be a distfiles basename: {patch!r}")
        elif not ((path.parent / patch).exists() or (path.parent / "distfiles" / patch).exists()) and patch not in names:
            errors.append(f"{path}: local patch attachment is absent: {patch}")
    return names


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
    amd64_v2_by_name: dict[str, tuple[Path, dict]] = {}

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
            # v1 remains executable legacy input, but its source integrity and
            # package identity are still auditable even though its shell
            # phases are intentionally opaque to the v2 boundary checker.
            package = recipe.get("package", {})
            if not isinstance(package, dict) or not isinstance(package.get("name"), str):
                errors.append(f"{path}: v1 package.name must be a non-empty string")
            check_sources(path, recipe, {}, errors, warnings)
            continue
        if schema != 2:
            errors.append(f"{path}: unsupported schema_version {schema}")
            continue
        counts["v2"] += 1
        package = recipe.get("package", {})
        name = package.get("name", path.parent.name)
        if not isinstance(name, str) or not name:
            errors.append(f"{path}: package.name must be a non-empty string")
            name = path.parent.name
        amd64_v2_by_name[name] = (path, recipe)
        build = recipe.get("build")
        if not isinstance(build, dict):
            errors.append(f"{path}: v2 recipe has no [build] table")
            continue
        system = build.get("system")
        if system not in BUILD_SYSTEMS:
            errors.append(f"{path}: unsupported v2 build.system: {system!r}")
            continue
        check_backend_options(path, system, build, errors)
        check_steps(path, system, build, errors)
        outputs = build.get("outputs", [])
        if not isinstance(outputs, list):
            errors.append(f"{path}: build.outputs must be an array")
            outputs = []
        output_names: set[str] = set()
        for output in outputs:
            if not isinstance(output, dict) or not isinstance(output.get("name"), str):
                errors.append(f"{path}: build.outputs entries require a name and install_files: {output!r}")
                continue
            output_name = output["name"]
            if output_name in output_names or "/" in output_name or output_name in {".", ".."}:
                errors.append(f"{path}: invalid/duplicate output name: {output_name!r}")
            output_names.add(output_name)
            if not isinstance(output.get("install_files"), list) or not output.get("install_files"):
                errors.append(f"{path}: output '{output_name}' needs non-empty install_files")
            for key in ("install_files", "install_excludes"):
                for value in output.get(key, []):
                    if not isinstance(value, str) or not rel_safe(value):
                        errors.append(f"{path}: invalid outputs.{key} pattern: {value!r}")
        if outputs and (build.get("install_files") or build.get("install_excludes")):
            errors.append(f"{path}: outputs cannot be combined with top-level install_files/install_excludes")
        if system == "script" and not outputs and not build.get("install_files"):
            errors.append(f"{path}: script recipe needs an explicit install_files or outputs boundary")
        for key in INSTALL_KEYS:
            if not isinstance(build.get(key, []), list):
                errors.append(f"{path}: build.{key} must be an array")
        if name.endswith(("-libs", "-dev")):
            counts["v2_split"] += 1
            if not build.get("install_files") and not build.get("outputs"):
                errors.append(f"{path}: split output has no explicit install_files boundary")
        for key in INSTALL_KEYS:
            for value in build.get(key, []) if isinstance(build.get(key, []), list) else []:
                if not isinstance(value, str) or not rel_safe(value):
                    errors.append(f"{path}: invalid {key} path/pattern: {value!r}")
        for key in TRANSFORM_KEYS:
            entries = build.get(key, [])
            if not isinstance(entries, list):
                errors.append(f"{path}: build.{key} must be an array")
                continue
        for key in ("install_copies", "install_moves"):
            for entry in build.get(key, []) if isinstance(build.get(key, []), list) else []:
                if not isinstance(entry, dict) or not rel_safe(entry.get("from", "")) or not rel_safe(entry.get("to", "")):
                    errors.append(f"{path}: invalid build.{key} entry: {entry!r}")
        for entry in build.get("install_generates", []) if isinstance(build.get("install_generates", []), list) else []:
            if (not isinstance(entry, dict) or not rel_safe(entry.get("path", ""))
                    or not isinstance(entry.get("content"), str)
                    or not isinstance(entry.get("mode", 0o644), int)
                    or not 0 <= entry.get("mode", 0o644) <= 0o7777):
                errors.append(f"{path}: invalid build.install_generates entry: {entry!r}")
        for entry in build.get("install_symlinks", []) if isinstance(build.get("install_symlinks", []), list) else []:
            if (not isinstance(entry, dict) or not rel_safe(entry.get("path", ""))
                    or not isinstance(entry.get("target"), str) or not entry.get("target")):
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
        check_sources(path, recipe, build, errors, warnings)
        if args.staging and path.parent == args.staging.parent:
            check_staging(recipe, args.staging, str(path), errors)

    # A main package that has split siblings must explicitly exclude every
    # sibling boundary. Otherwise the backend's complete install tree would
    # silently duplicate foo-libs/foo-dev payloads and ownership would depend
    # on installation order.
    for name, (path, recipe) in amd64_v2_by_name.items():
        if name.endswith(("-libs", "-dev")):
            continue
        build = recipe.get("build", {})
        if not isinstance(build, dict):
            continue
        siblings = []
        for suffix in ("-libs", "-dev"):
            sibling = amd64_v2_by_name.get(name + suffix)
            if sibling:
                sibling_build = sibling[1].get("build", {})
                if isinstance(sibling_build, dict):
                    siblings.extend(sibling_build.get("install_files", []))
        if siblings:
            exclusions = build.get("install_excludes", [])
            missing = [pattern for pattern in siblings if not pattern_covered(pattern, exclusions)]
            if missing:
                errors.append(f"{path}: main package does not exclude split payload patterns: {missing}")

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
