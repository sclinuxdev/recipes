#!/usr/bin/env python3
"""Validate the repository invariants that can be checked without building."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections import defaultdict
from pathlib import Path


CATEGORIES = {"devel", "lib", "net", "security", "system", "text", "tools", "utils"}
ARCHITECTURES = {"amd64", "aarch64", "any"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
REQUIRED_SEED_PACKAGES = {
    "seed-make": "make",
    "seed-pkgconf": "pkgconf",
    "seed-libc": "glibc",
    "seed-compiler": "gcc",
    "seed-python": "python",
}
EXTERNAL_SEED_STAGES = set(REQUIRED_SEED_PACKAGES) | {"seed-kernel-headers"}


class ValidationError(Exception):
    """A repository invariant is violated."""


def fail(path: Path, message: str) -> None:
    raise ValidationError(f"{path}: {message}")


def source_list(data: dict, path: Path) -> list[dict]:
    if "source" in data and "sources" in data:
        fail(path, "legacy [source] and [[sources]] are mutually exclusive")
    if "source" in data:
        return [data["source"]]
    return data.get("sources", [])


def validate_sources(data: dict, path: Path) -> None:
    for index, source in enumerate(source_list(data, path), start=1):
        if not isinstance(source, dict):
            fail(path, f"source {index} is not a table")
        kind = source.get("kind", "archive")
        if kind not in {"archive", "file", "git"}:
            fail(path, f"source {index} has unsupported kind {kind!r}")
        url = source.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            fail(path, f"source {index} must use an HTTP(S) URL")
        if kind == "git":
            commit = source.get("commit")
            if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
                fail(path, f"git source {index} must pin a 40- or 64-character commit")
        else:
            checksum = source.get("sha256")
            if not isinstance(checksum, str) or not SHA256.fullmatch(checksum):
                fail(path, f"source {index} must have a lowercase SHA-256 checksum")
        destination = source.get("destination")
        if destination is not None:
            destination_path = Path(destination)
            if destination_path.is_absolute() or ".." in destination_path.parts:
                fail(path, f"source {index} has an unsafe destination")


def validate_service(path: Path) -> None:
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    if data.get("schema_version") != 1:
        fail(path, "schema_version must be 1")
    services = []
    if "service" in data:
        services.append(data["service"])
    services.extend(data.get("services", []))
    if not services:
        fail(path, "service.toml must declare [service] or [[services]]")
    names = set()
    for service in services:
        name = service.get("name")
        if not isinstance(name, str) or not name or name in names:
            fail(path, f"service name is missing or duplicated: {name!r}")
        names.add(name)
        if service.get("type", "simple") not in {"simple", "forking", "notify", "oneshot"}:
            fail(path, f"service {name!r} has an unsupported type")
        command = service.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
            fail(path, f"service {name!r} must have a non-empty command array")


def validate_recipe(path: Path, root: Path, identities: dict[tuple, Path]) -> None:
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    if data.get("schema_version") != 1:
        fail(path, "schema_version must be 1")
    package = data.get("package")
    if not isinstance(package, dict):
        fail(path, "missing [package]")
    name = package.get("name")
    version = package.get("version")
    release = package.get("release")
    arch = package.get("arch")
    if not isinstance(name, str) or not name:
        fail(path, "package.name must be a non-empty string")
    if not isinstance(version, str) or not version:
        fail(path, "package.version must be a non-empty string")
    if release != 1:
        fail(path, "only the latest recipe release may be present and it must be 1")
    if arch not in ARCHITECTURES:
        fail(path, f"package.arch must be one of {sorted(ARCHITECTURES)}")

    relative = path.relative_to(root)
    if len(relative.parts) != 5 or relative.parts[0] not in CATEGORIES or relative.parts[2] != arch:
        fail(path, "recipe path must be <category>/<name>/<arch>/<name>-<version>-<release>/recipe.toml")
    if relative.parts[1] != name or relative.parts[3] != f"{name}-{version}-{release}":
        fail(path, "directory metadata does not match [package]")

    slot = package.get("slot", "0")
    identity = (package.get("channel", ""), name, version, arch, slot)
    if identity in identities:
        fail(path, f"duplicate recipe identity; older release is still present: {identities[identity]}")
    identities[identity] = path
    validate_sources(data, path)

    build = data.get("build", {})
    if "cargo" in build.get("inherit", []) and build.get("allow_network") is not True:
        fail(path, "Cargo recipes must explicitly set build.allow_network = true")

    subpackages = data.get("subpackages", [])
    subpackage_names = set()
    for subpackage in subpackages:
        subpackage_name = subpackage.get("name")
        if not isinstance(subpackage_name, str) or not subpackage_name or subpackage_name in subpackage_names:
            fail(path, f"subpackage name is missing or duplicated: {subpackage_name!r}")
        if subpackage_name == name:
            fail(path, "subpackage name duplicates the main package")
        subpackage_names.add(subpackage_name)


def dependency_symbols(raw: str, channel: str) -> list[tuple]:
    value = re.split(r"(?:>=|<=|=|>|<)", raw.split()[0], maxsplit=1)[0]
    if value.startswith(("virtual/", "so:")):
        return [("provide", value)]
    if "/" in value:
        dependency_channel, name = value.split("/", maxsplit=1)
    else:
        dependency_channel, name = channel, value
    if ":" in name:
        name, slot = name.rsplit(":", maxsplit=1)
    else:
        slot = "0"
    # Normal dependency names can resolve either to a package key or to a
    # compatibility alias declared in package.provides.
    return [
        ("package", dependency_channel, name, slot),
        ("provide", name),
    ]


def recipe_dependencies(
    path: Path, data: dict, classes: dict[str, dict]
) -> list[tuple[str, str]]:
    package = data["package"]
    channel = package["channel"]
    declarations: list[str] = []
    declarations.extend(package.get("dependencies", []))
    build = data.get("build", {})
    declarations.extend(build.get("dependencies", []))
    declarations.extend(build.get("target_dependencies", []))
    for subpackage in data.get("subpackages", []):
        declarations.extend(subpackage.get("dependencies", []))
    for feature in data.get("features", {}).values():
        if feature.get("default"):
            declarations.extend(feature.get("dependencies", []))
            declarations.extend(feature.get("build_dependencies", []))
            declarations.extend(feature.get("target_dependencies", []))
    for inherited in build.get("inherit", []):
        if inherited not in classes:
            fail(path, f"missing rclass {inherited!r}")
        declarations.extend(classes[inherited].get("implicit_build_dependencies", []))
    return [(declaration, channel) for declaration in declarations]


def validate_bootstrap(
    path: Path, root: Path, recipe_data: dict[str, dict]
) -> None:
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    if data.get("schema_version") != 1:
        fail(path, "schema_version must be 1")
    listed = []
    stages_by_name = {}
    for stage in data.get("stages", []):
        name = stage.get("name")
        if not isinstance(name, str) or not name:
            fail(path, "bootstrap stage must have a name")
        if name in stages_by_name:
            fail(path, f"bootstrap stage name is duplicated: {name!r}")
        recipes = stage.get("recipes", [])
        if not recipes:
            fail(path, f"bootstrap stage {name!r} is empty")
        stages_by_name[name] = stage
        listed.extend(recipes)
    if len(listed) != len(set(listed)):
        fail(path, "a recipe is listed in more than one bootstrap stage")
    recipe_paths = set(recipe_data)
    listed_set = set(listed)
    missing = recipe_paths - listed_set
    unknown = listed_set - recipe_paths
    if missing:
        fail(path, f"recipes missing from bootstrap: {sorted(missing)}")
    if unknown:
        fail(path, f"bootstrap references unknown recipes: {sorted(unknown)}")

    for stage_name, package_name in REQUIRED_SEED_PACKAGES.items():
        stage = stages_by_name.get(stage_name)
        if stage is None:
            fail(path, f"required external seed stage is missing: {stage_name}")
        recipes = stage["recipes"]
        if len(recipes) != 1:
            fail(path, f"external seed stage {stage_name!r} must contain exactly one recipe")
        seed_recipe = recipes[0]
        if recipe_data[seed_recipe]["package"]["name"] != package_name:
            fail(
                path,
                f"external seed stage {stage_name!r} must provide {package_name!r}",
            )

    stage_of = {
        recipe: index
        for index, stage in enumerate(data["stages"])
        for recipe in stage["recipes"]
    }
    stage_name_of = {
        recipe: stage["name"]
        for stage in data["stages"]
        for recipe in stage["recipes"]
    }
    classes = {}
    for class_path in sorted(root.glob("rclass/*.toml")):
        with class_path.open("rb") as stream:
            classes[class_path.stem] = tomllib.load(stream)
    owners: dict[tuple, set[str]] = defaultdict(set)
    for relative, recipe in recipe_data.items():
        package = recipe["package"]
        channel = package["channel"]
        slot = str(package.get("slot", "0"))
        owners[("package", channel, package["name"], slot)].add(relative)
        for provided in package.get("provides", []):
            owners[("provide", provided)].add(relative)
        for subpackage in recipe.get("subpackages", []):
            subpackage_channel = subpackage.get("channel", channel)
            subpackage_slot = str(subpackage.get("slot", slot))
            owners[("package", subpackage_channel, subpackage["name"], subpackage_slot)].add(relative)
            for provided in subpackage.get("provides", []):
                owners[("provide", provided)].add(relative)

    same_stage_edges: dict[int, set[tuple[str, str]]] = defaultdict(set)
    for relative, recipe in recipe_data.items():
        consumer_stage = stage_of[relative]
        for raw, channel in recipe_dependencies(root / relative, recipe, classes):
            producers = {
                producer
                for symbol in dependency_symbols(raw, channel)
                for producer in owners.get(symbol, set())
            }
            if not producers:
                fail(root / relative, f"dependency has no recipe provider: {raw}")
            for producer in producers:
                producer_stage = stage_of[producer]
                if (
                    stage_name_of[relative] not in EXTERNAL_SEED_STAGES
                    and stage_name_of[producer] not in REQUIRED_SEED_PACKAGES
                    and producer_stage > consumer_stage
                ):
                    fail(
                        root / relative,
                        f"dependency {raw!r} is produced by later bootstrap stage {producer_stage + 1}",
                    )
                if producer_stage == consumer_stage and producer != relative:
                    same_stage_edges[consumer_stage].add((producer, relative))

    for stage, edges in same_stage_edges.items():
        nodes = {node for edge in edges for node in edge}
        outgoing: dict[str, set[str]] = defaultdict(set)
        indegree = {node: 0 for node in nodes}
        for producer, consumer in edges:
            if consumer not in outgoing[producer]:
                outgoing[producer].add(consumer)
                indegree[consumer] += 1
        ready = [node for node, degree in indegree.items() if degree == 0]
        completed = 0
        while ready:
            producer = ready.pop()
            completed += 1
            for consumer in outgoing[producer]:
                indegree[consumer] -= 1
                if indegree[consumer] == 0:
                    ready.append(consumer)
        if completed != len(nodes):
            cycle = sorted(node for node, degree in indegree.items() if degree)
            fail(path, f"bootstrap stage {stage + 1} contains a dependency cycle: {cycle}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    identities: dict[tuple, Path] = {}
    recipe_data: dict[str, dict] = {}
    try:
        recipe_files = sorted(root.rglob("recipe.toml"))
        if not recipe_files:
            raise ValidationError("no recipe.toml files found")
        for path in recipe_files:
            validate_recipe(path, root, identities)
            with path.open("rb") as stream:
                recipe_data[path.relative_to(root).as_posix()] = tomllib.load(stream)
        service_files = sorted(root.rglob("service.toml"))
        for path in service_files:
            validate_service(path)
        bootstrap = root / "bootstrap.toml"
        if bootstrap.exists():
            validate_bootstrap(
                bootstrap,
                root,
                recipe_data,
            )
    except (OSError, tomllib.TOMLDecodeError, ValidationError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(recipe_files)} recipes, {len(service_files)} services, "
        f"{len(identities)} package version identities validated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
