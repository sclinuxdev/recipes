#!/usr/bin/env python3
"""Fail-closed static and staged-payload audit for recipe-v2 trees.

This intentionally does not pretend that TOML parsing proves a build.  The
normal CI job runs the static checks; a builder can pass --build to invoke Sage
for every recipe and --staging to additionally check an already produced pkg/
tree against the declared output boundary.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path


INSTALL_KEYS = ("install_files", "install_excludes")
TRANSFORM_KEYS = ("install_copies", "install_moves", "install_removes", "install_generates", "install_symlinks")
BUILD_SYSTEMS = {"autotools", "cmake", "meson", "xmake", "cargo", "go", "make", "script"}
STEP_PHASES = {"prepare", "pre-build", "post-build", "check", "pre-install", "install", "post-install"}
STEP_CWDS = {"source", "build", "package"}
SUPPORTED_ARCHES = {"amd64", "aarch64", "riscv64", "armv7", "any"}
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Keep the repository-side checker in lockstep with Sage's v2 parser.  A
# recipe that passes this script must not rely on a key that Sage silently
# ignores (the common source of accidental compiler/prefix or split-payload
# claims in the old tree).
ROOT_KEYS = {
    "schema_version", "package", "upstream", "source", "build",
    "capability_hooks", "triggers", "sysusers", "alternatives", "vendor",
}
PACKAGE_KEYS = {
    "name", "version", "release", "description", "license", "channel",
    "arch", "dependencies", "build_dependencies", "check_dependencies", "provides", "conflicts",
    "conffiles", "upstream", "upstream_regex",
}
UPSTREAM_KEYS = {"url", "version_regex"}
SOURCE_KEYS = {"url", "sha256"}
BUILD_KEYS = {
    "system", "payload", "kernel", "header_only", "source_subdir", "build_dir",
    "configure_options", "build_targets", "install_targets", "install_files",
    "install_excludes", "install_copies", "install_symlinks", "install_moves",
    "install_removes", "install_generates", "outputs", "steps", "patches",
    "patch_checksums", "patch_strip", "allowed_compilers", "allowed_linkers",
    "variables", "flag_env", "tool_env", "toolchain", "tools",
    "flag_policy", "content", "network",
    "cmake", "meson", "cargo", "autotools", "make", "xmake",
}
TOOLCHAIN_KEYS = {"compiler", "linker", "rust", "go"}
TOOL_KEYS = {"family", "package", "minimum_version"}
FLAG_ENV_KEYS = {"cflags", "cxxflags", "cppflags", "ldflags", "rustflags"}
TOOL_ENV_KEYS = {"cc", "cxx", "linker"}
FLAG_POLICY_KEYS = {"lto", "march", "as-needed"}
CONTENT_KEYS = {"strip", "man_compress", "shebangs", "locales"}
SYSUSER_KEYS = {"type", "name", "id", "description", "home", "shell", "group"}
ALTERNATIVE_KEYS = {"link", "target", "priority"}
TRANSFORM_ENTRY_KEYS = {
    "install_copies": {"from", "to"},
    "install_moves": {"from", "to"},
    "install_removes": {"path"},
    "install_symlinks": {"path", "target"},
    "install_generates": {"path", "content", "mode"},
}
BACKEND_FIELDS = {
    "cmake": {
        "definitions": "map", "features": "array",
        "build_type": "string", "raw_options": "array",
    },
    "meson": {
        "options": "map", "build_type": "string", "raw_options": "array",
    },
    "cargo": {
        "features": "array", "default_features": "bool",
        "locked": "bool", "raw_options": "array",
    },
    "autotools": {
        "enable": "array", "disable": "array", "with": "array",
        "without": "array", "raw_options": "array",
    },
    "make": {
        "targets": "array", "install_targets": "array",
        "variables": "map", "raw_options": "array",
    },
    "xmake": {
        "configs": "map", "mode": "string", "raw_options": "array",
    },
}
INSTALL_VARIABLES = {
    "prefix", "exec_prefix", "bindir", "sbindir", "libexecdir", "libdir",
    "includedir", "oldincludedir", "datarootdir", "datadir", "infodir",
    "localedir", "mandir", "docdir", "htmldir", "dvidir", "pdfdir", "psdir",
    "sysconfdir", "sharedstatedir", "localstatedir", "runstatedir", "DESTDIR",
}
MANAGED_VARIABLES = {
    "CC", "CXX", "LD", "CPPFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS",
    "RUSTFLAGS", "DESTDIR", "PREFIX", "MAKEFLAGS", "CARGO_BUILD_JOBS",
    "LC_ALL", "LANG", "TZ", "SOURCE_DATE_EPOCH", "FORCE_SOURCE_DATE",
    "PYTHONHASHSEED", "ARFLAGS", "ZERO_AR_DATE", "CARGO_INCREMENTAL",
    "CARGO_TERM_COLOR", "DEBUGINFOD_URLS", "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_GLOBAL", "HOME", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME",
    "XDG_CONFIG_HOME", "CHOST", "PKG_CONFIG_LIBDIR", "CCACHE_DIR",
    "CCACHE_COMPILERCHECK", "CCACHE_BASEDIR", "CCACHE_SLOPPINESS",
    "SCCACHE_DIR", "RUSTC", "GOFLAGS", "GOPROXY", "GOTOOLCHAIN", "GOBIN",
    "GOPATH", "GOCACHE", "GOMODCACHE", "LLVM", "KCFLAGS", "KCPPFLAGS",
    "KBUILD_LDFLAGS", "KRUSTFLAGS", "PATH",
}


def reject_unknown(mapping: object, allowed: set[str], path: Path,
                   scope: str, errors: list[str]) -> None:
    if not isinstance(mapping, dict):
        errors.append(f"{path}: {scope} must be a table")
        return
    for key in mapping:
        if key not in allowed:
            errors.append(f"{path}: unknown key {scope}.{key}")


def canonical_arch(arch: str) -> str:
    return {
        "x86_64": "amd64",
        "arm64": "aarch64",
        "arm": "armv7",
        "armhf": "armv7",
        "armv7l": "armv7",
    }.get(arch.strip(), arch.strip())

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
        forbidden = ("--prefix", "--bindir", "--sbindir", "--libexecdir", "--libdir", "--datadir",
                     "--includedir", "--infodir", "--localedir", "--mandir",
                     "--sysconfdir", "--localstatedir", "--sharedstatedir",
                     "-dprefix", "-dlibdir", "-dbindir", "-dsbindir", "-dincludedir",
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
        for original in options:
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
    if system in {"meson", "xmake"} and build.get("install_targets"):
        errors.append(f"{path}: {system} does not accept build.install_targets")
    if system in {"cargo", "go", "make"} and build.get("configure_options"):
        errors.append(f"{path}: {system} does not accept build.configure_options")
    if system == "script" and any(build.get(key) for key in
                                  ("configure_options", "build_targets", "install_targets")):
        errors.append(f"{path}: script recipes use build.steps instead of backend targets")


def check_backend_specs(path: Path, build: dict, errors: list[str]) -> None:
    for backend, fields in BACKEND_FIELDS.items():
        if backend not in build:
            continue
        spec = build[backend]
        if not isinstance(spec, dict):
            errors.append(f"{path}: build.{backend} must be a table")
            continue
        reject_unknown(spec, set(fields), path, f"build.{backend}", errors)
        for key, kind in fields.items():
            if key not in spec:
                continue
            value = spec[key]
            if kind == "array":
                if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                    errors.append(f"{path}: build.{backend}.{key} must be an array of strings")
            elif kind == "map":
                if not isinstance(value, dict) or any(
                    not isinstance(item, (str, bool, int)) for item in value.values()
                ):
                    errors.append(
                        f"{path}: build.{backend}.{key} must be a table of string, boolean, or integer values"
                    )
            elif kind == "string":
                if not isinstance(value, str) or not value:
                    errors.append(f"{path}: build.{backend}.{key} must be a non-empty string")
            elif kind == "bool" and not isinstance(value, bool):
                errors.append(f"{path}: build.{backend}.{key} must be boolean")


def check_managed_variables(path: Path, build: dict, errors: list[str]) -> None:
    mappings = [("build.variables", build.get("variables"))]
    make = build.get("make")
    if isinstance(make, dict):
        mappings.append(("build.make.variables", make.get("variables")))
    valid_name = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    for scope, mapping in mappings:
        if mapping is None:
            continue
        if not isinstance(mapping, dict):
            continue
        for name in mapping:
            if not isinstance(name, str) or not valid_name.fullmatch(name):
                errors.append(f"{path}: {scope} contains an invalid variable name: {name!r}")
            elif name in MANAGED_VARIABLES or name in INSTALL_VARIABLES:
                errors.append(f"{path}: {scope} cannot override Sage-managed variable: {name}")


def check_steps(path: Path, system: str, build: dict, errors: list[str]) -> bool:
    raw = build.get("steps", [])
    if not isinstance(raw, list):
        errors.append(f"{path}: build.steps must be an array")
        return False
    names: set[str] = set()
    has_check_phase = False
    for entry in raw:
        if not isinstance(entry, dict):
            errors.append(f"{path}: build.steps entries must be inline tables: {entry!r}")
            continue
        reject_unknown(entry, {"name", "phase", "cwd", "command", "unsafe_shell"}, path,
                       "build.steps[]", errors)
        name, phase, cwd, command = (
            entry.get(key) for key in ("name", "phase", "cwd", "command")
        )
        if not all(isinstance(value, str) and value for value in (name, phase, command)):
            errors.append(
                f"{path}: build.steps entries require non-empty name/phase/command: {entry!r}"
            )
            continue
        if cwd is None:
            cwd = "source"
        if phase not in STEP_PHASES:
            errors.append(f"{path}: unsupported build.steps phase: {phase}")
        if phase == "check":
            has_check_phase = True
        if cwd not in STEP_CWDS:
            errors.append(f"{path}: unsupported build.steps cwd: {cwd}")
        if name in names:
            errors.append(f"{path}: duplicate build.steps name: {name}")
        names.add(name)
        if "unsafe_shell" in entry and not isinstance(entry["unsafe_shell"], bool):
            errors.append(f"{path}: build.steps unsafe_shell must be boolean")
    if system == "script" and not raw:
        errors.append(f"{path}: script build requires at least one build.steps entry")
    return has_check_phase


def check_sources(
    path: Path,
    recipe: dict,
    build: dict,
    errors: list[str],
    warnings: list[str],
    *,
    strict: bool = False,
) -> set[str]:
    raw = recipe.get("source")
    entries = source_entries(recipe)
    if raw not in (None, [], {}) and not entries:
        errors.append(f"{path}: source must be a table or array of tables")
    names: set[str] = set()
    source_hashes: dict[str, str] = {}
    for index, source in enumerate(entries):
        if not isinstance(source, dict):
            errors.append(f"{path}: source entry {index} must be a table")
            continue
        if strict:
            reject_unknown(source, SOURCE_KEYS, path, f"source[{index}]", errors)
        url, sha256 = source.get("url"), source.get("sha256")
        if not isinstance(url, str) or not url:
            errors.append(f"{path}: source entry {index} has no URL")
        if not isinstance(sha256, str) or not HASH_RE.fullmatch(sha256):
            errors.append(f"{path}: source entry {index} must contain a 64-hex SHA-256")
        if isinstance(url, str):
            name = Path(url.split("?", 1)[0].split("#", 1)[0]).name
            if not name:
                errors.append(f"{path}: source entry {index} URL has no filename")
            elif name in names:
                errors.append(f"{path}: source URLs must have unique filenames: {name}")
            else:
                names.add(name)
                if isinstance(sha256, str) and HASH_RE.fullmatch(sha256):
                    source_hashes[name] = sha256.lower()
            if url.startswith("file:"):
                warnings.append(f"{path}: file source is intentionally builder-local: {url}")

    raw_patches = build.get("patches", [])
    if strict and not isinstance(raw_patches, list):
        errors.append(f"{path}: build.patches must be an array")
        raw_patches = []
    patches = raw_patches if isinstance(raw_patches, list) else []
    checksums = build.get("patch_checksums", {})
    if strict and not isinstance(checksums, dict):
        errors.append(f"{path}: build.patch_checksums must be a table")
        checksums = {}
    if not isinstance(checksums, dict):
        checksums = {}
    if strict:
        for patch_name, checksum in checksums.items():
            if not isinstance(patch_name, str) or Path(patch_name).name != patch_name:
                errors.append(
                    f"{path}: patch checksum key must be a basename: {patch_name!r}"
                )
            if not isinstance(checksum, str) or not HASH_RE.fullmatch(checksum):
                errors.append(
                    f"{path}: patch checksum must be a 64-hex SHA-256: {patch_name!r}"
                )

    declared_names: set[str] = set()
    for index, entry in enumerate(patches):
        declared_checksum: str | None = None
        if isinstance(entry, str):
            patch = entry
        elif isinstance(entry, dict):
            if strict:
                reject_unknown(
                    entry, {"file", "strip", "sha256"}, path,
                    f"build.patches[{index}]", errors
                )
            patch = entry.get("file")
            strip = entry.get("strip", build.get("patch_strip", 1))
            if (
                not isinstance(strip, int)
                or isinstance(strip, bool)
                or not 0 <= strip <= 9
            ):
                errors.append(
                    f"{path}: patch strip must be an integer from 0 to 9: {entry!r}"
                )
            if "sha256" in entry:
                declared_checksum = entry["sha256"]
                if (
                    not isinstance(declared_checksum, str)
                    or not HASH_RE.fullmatch(declared_checksum)
                ):
                    errors.append(
                        f"{path}: patch table sha256 must be a 64-hex SHA-256: {entry!r}"
                    )
                    declared_checksum = None
            elif strict:
                errors.append(f"{path}: structured patch entries require sha256")
        else:
            errors.append(
                f"{path}: patch must be a basename string or table: {entry!r}"
            )
            continue
        if not isinstance(patch, str) or not patch or Path(patch).name != patch:
            errors.append(f"{path}: patch must be a distfiles basename: {patch!r}")
            continue
        if patch in declared_names:
            errors.append(f"{path}: build.patches cannot declare the same file twice: {patch}")
            continue
        declared_names.add(patch)
        source_checksum = source_hashes.get(patch)
        legacy_checksum = checksums.get(patch)
        if isinstance(legacy_checksum, str) and HASH_RE.fullmatch(legacy_checksum):
            legacy_checksum = legacy_checksum.lower()
        else:
            legacy_checksum = None
        explicit_checksum = (
            declared_checksum.lower()
            if isinstance(declared_checksum, str)
            and HASH_RE.fullmatch(declared_checksum)
            else None
        )
        candidates = [
            checksum
            for checksum in (explicit_checksum, legacy_checksum, source_checksum)
            if checksum is not None
        ]
        if candidates and any(checksum != candidates[0] for checksum in candidates[1:]):
            errors.append(f"{path}: patch {patch} has conflicting SHA-256 declarations")
        checksum = candidates[0] if candidates else None
        local = path.parent / patch
        if not local.is_file():
            local = path.parent / "distfiles" / patch
        if strict and not checksum:
            errors.append(f"{path}: every patch needs a SHA-256 declaration: {patch}")
        if local.is_file() and not checksum:
            errors.append(f"{path}: local patch needs a SHA-256 declaration: {patch}")
        elif local.is_file() and checksum:
            actual = hashlib.sha256(local.read_bytes()).hexdigest()
            if actual != checksum:
                errors.append(
                    f"{path}: local patch SHA-256 mismatch for {patch}: "
                    f"declared {checksum}, actual {actual}"
                )
        elif strict and not local.is_file() and patch not in names:
            errors.append(f"{path}: patch attachment/source is absent: {patch}")
    if strict:
        for patch_name in checksums:
            if patch_name not in declared_names:
                errors.append(
                    f"{path}: patch checksum names an undeclared patch: {patch_name}"
                )
    return names
def check_vendors(path: Path, recipe: dict, errors: list[str]) -> None:
    raw = recipe.get("vendor")
    if raw is None:
        return
    entries = [raw] if isinstance(raw, dict) else raw if isinstance(raw, list) else None
    if entries is None:
        errors.append(f"{path}: vendor must be a table or array of tables")
        return
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"{path}: vendor entry {index} must be a table")
            continue
        reject_unknown(entry, {"url", "sha256", "target"}, path,
                       f"vendor[{index}]", errors)
        url = entry.get("url")
        sha256 = entry.get("sha256")
        target = entry.get("target", "vendor")
        if not isinstance(url, str) or not url:
            errors.append(f"{path}: vendor[{index}] requires a non-empty URL")
        if not isinstance(sha256, str) or not HASH_RE.fullmatch(sha256):
            errors.append(f"{path}: vendor[{index}] requires a 64-hex SHA-256")
        if (not isinstance(target, str) or not target
                or Path(target).is_absolute() or ".." in Path(target).parts):
            errors.append(f"{path}: vendor[{index}] target must be a relative path without '..'")

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


def check_v2_shape(path: Path, recipe: dict, package: dict, build: dict,
                   system: str, errors: list[str]) -> None:
    """Apply the same structural and boundary rules as Recipe::parse_toml."""
    reject_unknown(recipe, ROOT_KEYS, path, "recipe", errors)
    if not isinstance(package, dict):
        errors.append(f"{path}: package must be a table")
        package = {}
    reject_unknown(package, PACKAGE_KEYS, path, "package", errors)
    for key in ("name", "version", "license", "channel", "arch"):
        if not isinstance(package.get(key), str) or not package[key]:
            errors.append(f"{path}: package.{key} must be a non-empty string")
    declared_arch = canonical_arch(package.get("arch", ""))
    if declared_arch not in SUPPORTED_ARCHES:
        errors.append(f"{path}: unsupported package.arch: {package.get('arch')!r}")
    if any(ch in package.get("name", "") for ch in ("/", "\\")):
        errors.append(f"{path}: package.name must be a simple package name")
    for key in ("description", "upstream", "upstream_regex"):
        if key in package and not isinstance(package[key], str):
            errors.append(f"{path}: package.{key} must be a string")
    for key in ("dependencies", "conflicts", "build_dependencies", "check_dependencies",
                "provides", "conffiles"):
        if key in package and (not isinstance(package[key], list)
                               or not all(isinstance(item, str) and item for item in package[key])):
            errors.append(f"{path}: package.{key} must be an array of non-empty strings")
    # Versioned provides ("virtual/libc = 2.44") parse as `name <op> version`;
    # reject malformed entries before they reach the solver's provider index.
    for item in package.get("provides", []) if isinstance(package.get("provides"), list) else []:
        if not isinstance(item, str):
            errors.append(f"{path}: package.provides entries must be strings")
            continue
        name, _, _ = item.partition(" ")
        if not name or name in {".", ".."}:
            errors.append(f"{path}: invalid package.provides entry: {item!r}")
    if ("upstream" in package) != ("upstream_regex" in package):
        errors.append(f"{path}: package.upstream and package.upstream_regex must be provided together")
    if "upstream" in recipe:
        upstream = recipe["upstream"]
        reject_unknown(upstream, UPSTREAM_KEYS, path, "upstream", errors)
        if not isinstance(upstream, dict):
            return
        for key in ("url", "version_regex"):
            if key not in upstream or not isinstance(upstream[key], str) or not upstream[key]:
                errors.append(f"{path}: upstream requires non-empty {key}")
        if isinstance(upstream.get("version_regex"), str):
            try:
                re.compile(upstream["version_regex"])
            except re.error as exc:
                errors.append(f"{path}: invalid upstream.version_regex: {exc}")
    reject_unknown(build, BUILD_KEYS, path, "build", errors)
    check_backend_specs(path, build, errors)
    payload = build.get("payload")
    if payload not in {"all", "allowlist", "outputs"}:
        errors.append(f"{path}: build.payload must be all, allowlist, or outputs")
    if "kernel" in build and not isinstance(build["kernel"], bool):
        errors.append(f"{path}: build.kernel must be boolean")
    elif build.get("kernel") and system != "make":
        errors.append(f"{path}: build.kernel=true requires system=make")
    if "header_only" in build and not isinstance(build["header_only"], bool):
        errors.append(f"{path}: build.header_only must be boolean")
    for key in ("configure_options", "build_targets", "install_targets", "install_files",
                "install_excludes", "allowed_compilers", "allowed_linkers"):
        if key in build and (not isinstance(build[key], list)
                             or not all(isinstance(item, str) for item in build[key])):
            errors.append(f"{path}: build.{key} must be an array of strings")
    for key in ("source_subdir", "build_dir"):
        if key in build and not isinstance(build[key], str):
            errors.append(f"{path}: build.{key} must be a string")
    if "patch_strip" in build and (not isinstance(build["patch_strip"], int)
                                   or not 0 <= build["patch_strip"] <= 9):
        errors.append(f"{path}: build.patch_strip must be an integer from 0 to 9")
    if "tools" in build:
        if not isinstance(build["tools"], bool):
            errors.append(f"{path}: build.tools must be boolean")
        elif build["tools"] and system != "script":
            errors.append(f"{path}: build.tools=true is valid only for script recipes")
    if "network" in build and not isinstance(build["network"], bool):
        errors.append(f"{path}: build.network must be boolean")
    for nested, allowed in (("variables", None), ("flag_env", FLAG_ENV_KEYS),
                            ("tool_env", TOOL_ENV_KEYS), ("toolchain", TOOLCHAIN_KEYS),
                            ("flag_policy", FLAG_POLICY_KEYS), ("content", CONTENT_KEYS)):
        if nested not in build:
            continue
        value = build[nested]
        if not isinstance(value, dict):
            errors.append(f"{path}: build.{nested} must be a table")
            continue
        if allowed is not None:
            reject_unknown(value, allowed, path, f"build.{nested}", errors)
        if nested == "flag_policy":
            for key, item in value.items():
                if not isinstance(item, bool):
                    errors.append(f"{path}: build.flag_policy.{key} must be boolean")
                elif item:
                    errors.append(f"{path}: build.flag_policy.{key}=true is the default and "
                                  f"cannot weaken a recipe; flag_policy declares downgrades only")
        elif nested == "content":
            if "strip" in value and value["strip"] not in {"none", "unneeded", "debug"}:
                errors.append(f"{path}: build.content.strip must be none, unneeded, or debug")
            if "man_compress" in value and value["man_compress"] not in {"none", "gzip"}:
                errors.append(f"{path}: build.content.man_compress must be none or gzip")
            if "shebangs" in value and value["shebangs"] != "absolute":
                errors.append(f"{path}: build.content.shebangs must be \"absolute\"")
            if "locales" in value and not all(isinstance(item, str) and item
                                              and "/" not in item for item in value["locales"]):
                errors.append(f"{path}: build.content.locales must be an array of plain locale names")
        elif nested == "variables":
            for key, item in value.items():
                if not isinstance(key, str) or not isinstance(item, str):
                    errors.append(f"{path}: build.variables values must be strings")
        else:
            if nested == "toolchain":
                for role, tool in value.items():
                    reject_unknown(tool, TOOL_KEYS, path, f"build.toolchain.{role}", errors)
                    if not isinstance(tool, dict):
                        continue
                    for field in TOOL_KEYS:
                        if field in tool and not isinstance(tool[field], str):
                            errors.append(f"{path}: build.toolchain.{role}.{field} must be a string")
                    if role in {"compiler", "linker", "rust", "go"}:
                        for field in ("family", "package", "minimum_version"):
                            if field not in tool or not isinstance(tool[field], str) or not tool[field]:
                                errors.append(f"{path}: build.toolchain.{role} requires {field}")
                    if role == "rust" and system != "cargo":
                        errors.append(f"{path}: build.toolchain.rust is valid only for Cargo recipes")
                    if role == "go" and system != "go":
                        errors.append(f"{path}: build.toolchain.go is valid only for Go recipes")
    check_managed_variables(path, build, errors)
    for key, allowed in TRANSFORM_ENTRY_KEYS.items():
        values = build.get(key, [])
        if not isinstance(values, list):
            errors.append(f"{path}: build.{key} must be an array")
            continue
        for entry in values:
            if not isinstance(entry, dict):
                errors.append(f"{path}: build.{key} entries must be inline tables")
                continue
            reject_unknown(entry, allowed, path, f"build.{key}[]", errors)
            if key in {"install_copies", "install_moves"}:
                if not all(isinstance(entry.get(field), str) and rel_safe(entry[field])
                           for field in ("from", "to")):
                    errors.append(f"{path}: invalid build.{key} entry: {entry!r}")
            elif key == "install_removes":
                if not isinstance(entry.get("path"), str) or not rel_safe(entry["path"]):
                    errors.append(f"{path}: invalid build.install_removes entry: {entry!r}")
            elif key == "install_symlinks":
                if (not isinstance(entry.get("path"), str) or not rel_safe(entry["path"])
                        or not isinstance(entry.get("target"), str) or not entry["target"]):
                    errors.append(f"{path}: invalid build.install_symlinks entry: {entry!r}")
                else:
                    target = Path(entry["target"])
                    resolved = (Path(entry["path"]).parent / target).as_posix().split("/")
                    depth = 0
                    escapes = target.is_absolute()
                    for component in resolved:
                        if component in ("", "."):
                            continue
                        if component == "..":
                            depth -= 1
                            escapes |= depth < 0
                        else:
                            depth += 1
                    if escapes:
                        errors.append(f"{path}: symlink target escapes staging root: {entry!r}")
            else:
                if (not isinstance(entry.get("path"), str) or not rel_safe(entry["path"])
                        or not isinstance(entry.get("content"), str)
                        or not isinstance(entry.get("mode", 0o644), int)
                        or not 0 <= entry.get("mode", 0o644) <= 0o7777):
                    errors.append(f"{path}: invalid build.install_generates entry: {entry!r}")
    outputs = build.get("outputs", [])
    if not isinstance(outputs, list):
        return
    output_names: set[str] = set()
    for output in outputs:
        if not isinstance(output, dict):
            errors.append(f"{path}: build.outputs entries must be inline tables")
            continue
        reject_unknown(output, {"name", "description", "license", "version", "release",
                                "channel", "arch", "inherit", "dependencies",
                                "provides", "conflicts", "conffiles", "install_files",
                                "install_excludes", "optional_excludes", "install_copies",
                                "install_symlinks", "install_moves", "install_removes",
                                "install_generates", "file_permissions"},
                       path, "build.outputs[]", errors)
        name = output.get("name")
        if not isinstance(name, str) or not name or "/" in name or name in {".", ".."}:
            errors.append(f"{path}: invalid output name: {name!r}")
        elif name in output_names:
            errors.append(f"{path}: duplicate output name: {name}")
        output_names.add(name) if isinstance(name, str) else None
        for key in ("description", "license"):
            if key in output and not isinstance(output[key], str):
                errors.append(f"{path}: output {name!r}.{key} must be a string")
        for key in ("dependencies", "conflicts", "provides", "conffiles"):
            if key in output and (not isinstance(output[key], list)
                                  or not all(isinstance(item, str) and item for item in output[key])):
                errors.append(f"{path}: output {name!r}.{key} must be an array of non-empty strings")
        files = output.get("install_files")
        if not isinstance(files, list) or not files:
            errors.append(f"{path}: output {name!r} needs non-empty install_files")
        for key in ("install_files", "install_excludes"):
            for value in output.get(key, []) if isinstance(output.get(key, []), list) else []:
                if not isinstance(value, str) or not rel_safe(value):
                    errors.append(f"{path}: invalid outputs.{key} pattern: {value!r}")
    if outputs and (build.get("install_files") or build.get("install_excludes")):
        errors.append(f"{path}: outputs cannot be combined with top-level install_files/install_excludes")
    if payload == "all" and (build.get("install_files") or build.get("install_excludes") or outputs):
        errors.append(f"{path}: payload=all cannot have an allowlist or outputs")
    if payload == "allowlist" and not build.get("install_files"):
        errors.append(f"{path}: payload=allowlist requires non-empty install_files")
    if payload == "outputs" and not outputs:
        errors.append(f"{path}: payload=outputs requires outputs")
    if outputs and payload != "outputs":
        errors.append(f"{path}: outputs require payload=outputs")
    if system == "script" and (payload == "all" or (not outputs and not build.get("install_files"))):
        errors.append(f"{path}: script requires an explicit payload boundary")
    # Root [[sysusers]]: declarative system user/group requests.
    sysusers = recipe.get("sysusers")
    if sysusers is not None:
        if not isinstance(sysusers, list) or not all(isinstance(item, dict) for item in sysusers):
            errors.append(f"{path}: sysusers must be an array of tables")
        else:
            seen: set[str] = set()
            for entry in sysusers:
                reject_unknown(entry, SYSUSER_KEYS, path, "sysusers[]", errors)
                name = entry.get("name")
                if not isinstance(name, str) or not name or "/" in name or name in {".", ".."}:
                    errors.append(f"{path}: sysusers entries require a simple non-empty name")
                elif name in seen:
                    errors.append(f"{path}: duplicate sysusers name: {name}")
                seen.add(name) if isinstance(name, str) else None
                etype = entry.get("type")
                if etype not in {"user", "group"}:
                    errors.append(f"{path}: sysusers type must be user or group")
                if "id" in entry and (not isinstance(entry["id"], int) or not 0 < entry["id"] <= 0x7FFFFFFF):
                    errors.append(f"{path}: sysusers id must be a positive system uid/gid")
    # Root [[alternatives]]: cross-package symlink arbitration.
    alternatives = recipe.get("alternatives")
    if alternatives is not None:
        if not isinstance(alternatives, list) or not all(isinstance(item, dict) for item in alternatives):
            errors.append(f"{path}: alternatives must be an array of tables")
        else:
            links: set[str] = set()
            for entry in alternatives:
                reject_unknown(entry, ALTERNATIVE_KEYS, path, "alternatives[]", errors)
                link = entry.get("link")
                target = entry.get("target")
                if not isinstance(link, str) or not link or link.startswith("/") or not rel_safe(link):
                    errors.append(f"{path}: alternatives require a relative link path")
                elif link in links:
                    errors.append(f"{path}: duplicate alternative link: {link}")
                links.add(link) if isinstance(link, str) else None
                if not isinstance(target, str) or not target or target.startswith("/"):
                    errors.append(f"{path}: alternatives require a relative target")
                if "priority" in entry and (not isinstance(entry["priority"], int)
                                            or not 0 <= entry["priority"] <= 1000):
                    errors.append(f"{path}: alternatives priority must be between 0 and 1000")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=Path(__file__).resolve().parents[1], type=Path)
    parser.add_argument("--arch", action="append", dest="architectures",
                        help="validate only this architecture (repeatable; default: all)")
    parser.add_argument("--build", action="store_true", help="invoke Sage for every recipe (slow, networked)")
    parser.add_argument("--sage", default="sage", help="Sage executable used with --build")
    parser.add_argument("--staging", type=Path, help="audit one existing recipe pkg/ staging directory")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    requested_arches = {
        canonical_arch(arch) for arch in args.architectures
    } if args.architectures else SUPPORTED_ARCHES
    unknown_arches = requested_arches - SUPPORTED_ARCHES
    if unknown_arches:
        parser.error(f"unsupported architecture(s): {', '.join(sorted(unknown_arches))}")
    recipes = sorted(
        path for path in args.root.glob("**/*/*/*/recipe.toml")
        if len(path.relative_to(args.root).parts) >= 5
        and canonical_arch(path.relative_to(args.root).parts[-3]) in requested_arches
    )
    errors: list[str] = []
    warnings: list[str] = []
    counts = {"recipes": 0, "v1": 0, "v2": 0, "v2_split": 0}
    arch_counts = {arch: 0 for arch in sorted(requested_arches)}
    parsed: list[tuple[Path, dict]] = []
    v2_by_arch_name: dict[tuple[str, str], tuple[Path, dict]] = {}

    for path in recipes:
        relative_parts = path.relative_to(args.root).parts
        path_arch = canonical_arch(relative_parts[-3])
        arch_counts[path_arch] = arch_counts.get(path_arch, 0) + 1
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
        declared_arch = canonical_arch(package.get("arch", ""))
        if declared_arch not in SUPPORTED_ARCHES:
            errors.append(f"{path}: unsupported package.arch: {package.get('arch')!r}")
        elif declared_arch != path_arch:
            errors.append(
                f"{path}: package.arch {package.get('arch')!r} does not match path architecture {path_arch!r}"
            )
        v2_by_arch_name[(path_arch, name)] = (path, recipe)
        build = recipe.get("build")
        if not isinstance(build, dict):
            errors.append(f"{path}: v2 recipe has no [build] table")
            continue
        system = build.get("system")
        if system not in BUILD_SYSTEMS:
            errors.append(f"{path}: unsupported v2 build.system: {system!r}")
            continue
        check_v2_shape(path, recipe, package, build, system, errors)
        check_vendors(path, recipe, errors)
        check_backend_options(path, system, build, errors)
        has_check_phase = check_steps(path, system, build, errors)
        check_deps = package.get("check_dependencies", [])
        if check_deps and not has_check_phase:
            errors.append(
                f"{path}: package.check_dependencies require a build.steps phase='check'"
            )
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
        check_sources(path, recipe, build, errors, warnings, strict=True)
        if args.staging and path.parent == args.staging.parent:
            check_staging(recipe, args.staging, str(path), errors)

    # A main package that has split siblings must explicitly exclude every
    # sibling boundary. Otherwise the backend's complete install tree would
    # silently duplicate foo-libs/foo-dev payloads and ownership would depend
    # on installation order.
    for (arch, name), (path, recipe) in v2_by_arch_name.items():
        if name.endswith(("-libs", "-dev")):
            continue
        build = recipe.get("build", {})
        if not isinstance(build, dict) or build.get("payload") == "outputs":
            continue
        siblings = []
        for suffix in ("-libs", "-dev"):
            sibling = v2_by_arch_name.get((arch, name + suffix))
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

    report = {"counts": counts, "architectures": arch_counts,
              "errors": errors, "warnings": warnings}
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        by_arch = " ".join(f"{arch}={arch_counts[arch]}"
                           for arch in sorted(arch_counts))
        print(f"recipes={counts['recipes']} v1={counts['v1']} "
              f"v2={counts['v2']} v2_split={counts['v2_split']} {by_arch}")
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
