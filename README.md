# Sage Official Recipe Repository

This repository contains the declarative package recipes (`recipe.toml` Schema v1) for Sage.

---

## 1. Directory Structure

```text
recipes/
├── <category>/                               # Standard category (8 primary categories)
│   └── <pkgname>/                            # Package name (e.g. gcc, binutils, zlib)
│       ├── amd64/                            # x86-64 architecture tree
│       │   └── <pkgname>-<version>-<release>/# Specific version directory (e.g. gcc-16.2.0-1)
│       │       ├── recipe.toml               # amd64 recipe specification
│       │       └── patches/                  # Optional architecture-specific patches
│       ├── aarch64/                          # ARM64 architecture tree
│       │   └── <pkgname>-<version>-<release>/
│       │       ├── recipe.toml
│       │       └── patches/
│       └── any/                              # Architecture-independent packages (noarch/pure Python/docs)
│           └── <pkgname>-<version>-<release>/
│               └── recipe.toml
```

---

## 2. Standard Taxonomy (Categories)

| Category | Description | Examples |
| :--- | :--- | :--- |
| **`devel`** | Compilers, linkers, interpreters, build systems, debuggers | `gcc`, `clang`, `llvm`, `cmake`, `ninja`, `python`, `binutils`, `m4` |
| **`lib`** | Core shared libraries, compression, FFI, runtime libs | `zlib`, `zstd`, `libarchive`, `libffi`, `libcap`, `ncurses`, `gmp` |
| **`net`** | Network stacks, clients, daemons, management utilities | `openssh`, `curl`, `dhcpcd`, `iproute2`, `wget`, `bind-utils` |
| **`security`** | Cryptography, authentication, credentials, access control | `openssl`, `ca-certificates`, `shadow`, `sudo`, `pam`, `libxcrypt` |
| **`system`** | Core OS foundations, Init systems, C runtime, device managers | `glibc`, `musl`, `systemd`, `loom`, `kmod`, `coreutils` |
| **`text`** | Text stream processors, line editors, parsers, doc tools | `gawk`, `sed`, `grep`, `diffutils`, `less`, `vim`, `ripgrep` |
| **`tools`** | Disk & filesystem utilities, hardware diagnostics, archivers | `e2fsprogs`, `btrfs-progs`, `tar`, `xz`, `gzip`, `pciutils` |
| **`utils`** | Process management, system monitors, terminal tools | `procps-ng`, `util-linux`, `findutils`, `which`, `psmisc` |

---

## 3. Core Guidelines

- **Strict Per-Architecture Independence**: Each architecture directory (`amd64`, `aarch64`, `any`) is self-contained with independent `release` revisions, compilation flags, and patches.
- **Latest Release Only**: Keep one recipe per package name/version/architecture/slot; the retained recipe and directory always use `release = 1`. Historical binary releases belong in the package channel/index.
- **Single-Recipe Multi-Subpackages**: Use `[[subpackages]]` with declarative Glob patterns to split `-libs`, `-dev`, and `-doc` from a single build without repeated compilation.
- **Pure Declarative Lifecycle**: Interactive lifecycle scripts (`preinst`, `postinst`, `prerm`, `postrm`) are forbidden. Use `[[sysusers]]`, `service.toml`, and `triggers.toml` instead.
- **Init-Agnostic Services**: Daemons declare their behavior in `service.toml`; `rclass/init-*.toml` files are system-side renderers used by `sage rebuild` for OpenRC, systemd, and Loom.
- **SPDX Metadata**: Every `license` field uses a strict SPDX expression accepted by Sage 0.4.0 and is validated before repository indexing or package publication.

Run the repository gate before publishing:

```sh
python3 tools/validate-recipes.py
sage --dry-run bootstrap bootstrap.toml --jobs 4
```

The first command checks schema/path/source/release/service invariants and
bootstrap coverage. The Sage command checks the resolved build graph; the
bootstrap file deliberately documents the five externally supplied seed
vertices required to start a new system.

Rust recipes that use Cargo explicitly opt into network access because their
locked dependency graphs are not vendored in this repository. The Sage recipe
also patches the runner to start Bubblewrap from a writable tmpfs root and
import only the configured system directories read-only, so a read-only host
sysroot no longer prevents creation of `/source`, `/build`, or `/dest`.

A real build still requires Bubblewrap user namespaces, tmpfs mounts, and
outbound HTTPS connectivity. Sage's downloader uses HTTP/1.1, bounded
timeouts, transient-failure retries, and verifies every final SHA-256; a
container that blocks user namespaces/mounts or has no usable HTTPS route must
be fixed at the container/runtime layer rather than in recipe dependencies.
Cargo builds also set a 16 MiB rustc worker stack to avoid the known SIGSEGV in
the container's Rust 1.96.1 compiler under its default 8 MiB thread stack.
