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
│       ├── riscv64/                          # RISC-V 64 architecture tree
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

- **Strict Per-Architecture Independence**: Each architecture directory (`amd64`, `aarch64`, `riscv64`, `any`) is self-contained with independent `release` revisions, compilation flags, and patches.
- **Single-Recipe Multi-Subpackages**: Use `[[subpackages]]` with declarative Glob patterns to split `-libs`, `-dev`, and `-doc` from a single build without repeated compilation.
- **Pure Declarative Lifecycle**: Interactive lifecycle scripts (`preinst`, `postinst`, `prerm`, `postrm`) are forbidden. Use `[[sysusers]]`, `service.toml`, and `triggers.toml` instead.
