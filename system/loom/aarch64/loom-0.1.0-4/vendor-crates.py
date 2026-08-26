#!/usr/bin/env python3
import hashlib
import json
import pathlib
import tarfile


root = pathlib.Path.cwd()
vendor = root / "vendor"
vendor.mkdir(exist_ok=True)

for archive in sorted((root / "distfiles").glob("*.crate")):
    package_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    with tarfile.open(archive, "r:gz") as source:
        source.extractall(vendor, filter="data")
    package_dir = vendor / archive.name.removesuffix(".crate")
    files = {}
    for path in sorted(package_dir.rglob("*")):
        if path.is_file() and path.name != ".cargo-checksum.json":
            files[path.relative_to(package_dir).as_posix()] = hashlib.sha256(
                path.read_bytes()).hexdigest()
    (package_dir / ".cargo-checksum.json").write_text(
        json.dumps({"files": files, "package": package_hash}, sort_keys=True))

config_dir = root / ".cargo"
config_dir.mkdir(exist_ok=True)
(config_dir / "config.toml").write_text(
    '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
    '[source.vendored-sources]\ndirectory = "vendor"\n\n'
    '[net]\noffline = true\n')
