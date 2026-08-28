# Sage Recipe Repository Guidelines & Agent Specification

Welcome to the **Sage Recipes Repository** developer and AI agent guidelines.
All package recipes and metadata in this repository conform to **Sage Schema Version `1`**.

---

## 1. Specification Documents Navigation (Mandatory Reading)

> [!IMPORTANT]
> **All AI Agents and Contributors MUST read the corresponding specification documents in `docs/specs/` before authoring, updating, or reviewing recipes and metadata.**

| Topic / Specification | Document Path | Key Contents & Responsibilities |
| :--- | :--- | :--- |
| **Package Recipe Format** | [recipe_spec.md](file:///home/ir/newworld/recipes/docs/specs/recipe_spec.md) | `recipe.toml` Schema v1, single-recipe multi-subpackage splitting (`[[subpackages]]`), payload carving, multi-source tarballs (`[[sources]]`), Git commits, `[features]`, and `$ORIGIN` RUNPATH rewriting |
| **Directory Tree & Taxonomy** | [recipe_tree_spec.md](file:///home/ir/newworld/recipes/docs/specs/recipe_tree_spec.md) | 8 standard categories (`devel`, `lib`, `net`, `security`, `system`, `text`, `tools`, `utils`), architecture directory layout (`amd64`, `aarch64`, `any`), and per-architecture isolation |
| **Service Definitions** | [service_spec.md](file:///home/ir/newworld/recipes/docs/specs/service_spec.md) | Declarative daemon service format (`service.toml`), init-agnostic schema, template variables, and multi-init engine rendering (`systemd`, `loom`, `openrc`) |
| **Triggers & Sysusers** | [triggers_spec.md](file:///home/ir/newworld/recipes/docs/specs/triggers_spec.md) | Post-transaction hooks (`triggers.toml`), declarative system users/groups (`[[sysusers]]`), dynamic command alternatives (`[[alternatives]]`), and trigger execution lifecycle |
| **Build Classes (rclass)** | [rclass_spec.md](file:///home/ir/newworld/recipes/docs/specs/rclass_spec.md) | Build toolchain classes (`cmake`, `meson`, `cargo`, `autotools`, `python`, `go`, `kmod`, etc.), implicit build dependencies, allowed compiler/linker verification, and init generator classes |

---

## 2. Directory Tree & Architecture Hierarchy

All recipes follow a strict category and architecture-isolated directory structure:

```text
recipes/<category>/<pkgname>/<arch>/<pkgname>-<version>-<release>/
├── recipe.toml                   # Primary declarative recipe (Schema v1)
├── patches/                      # Optional directory for patch files (*.patch)
├── service.toml                  # Optional daemon service specification
└── triggers.toml                 # Optional package-level transaction triggers
```

- **Standard Categories**: `devel`, `lib`, `net`, `security`, `system`, `text`, `tools`, `utils`.
- **Supported Architectures**:
  - `amd64`: x86-64 target architecture.
  - `aarch64`: ARM64 (AArch64) target architecture.
  - `any`: Architecture-independent packages (pure Python wheels, documentation, data files, fonts, shell scripts).

---

## 3. Versioning & Release Rules

1. **`release` Starts at `1` and Increments Continuously**:
   - When a new software `version` is packaged, its initial `release` **must start at `1`** (e.g., `zlib-1.3.1-1`).
   - When updating or modifying an existing version's recipe (e.g., patching, dependency adjustments, build flag changes), the `release` number **must increment strictly monotonically and continuously without gaps** (`1` -> `2` -> `3` -> ...).
   - **Never skip release numbers** (e.g., jumping directly from `1` to `3` is forbidden).
   - **Continuous existence**: Historical releases must be preserved in accordance with repository maintenance policies to prevent broken upgrade paths.
2. **Directory & Metadata Strict Consistency**:
   - The directory name `<pkgname>-<version>-<release>` **must exactly match** the fields in `recipe.toml`:
     - `package.name` == `<pkgname>`
     - `package.version` == `<version>`
     - `package.release` == `<release>`
     - `package.arch` == `<arch>`
3. **Per-Architecture Revision Independence**:
   - Revisions on one architecture (e.g., an `aarch64`-specific patch bumping `release` to `2`) do not require bumping `amd64` if `amd64` is unaffected.
   - Each architecture manages its own continuous release history.

---

## 4. Recipe Authoring Standards (Schema v1)

1. **Single-Recipe Multi-Subpackages (`[[subpackages]]`)**:
   - Do not create separate recipe folders to split binaries, runtime libraries, and development headers.
   - Compile once and declare `[[subpackages]]` using declarative Glob patterns in `[subpackages.payload]`.
   - File claims follow first-match ownership; unassigned files remain in the main package.
   - See [recipe_spec.md](file:///home/ir/newworld/recipes/docs/specs/recipe_spec.md) for full syntax and examples.
2. **Deterministic & Pure Declarative Lifecycle**:
   - **Strictly Forbidden**: Interactive shell lifecycle scripts (`preinst`, `postinst`, `prerm`, `postrm`) are prohibited and will be rejected by `sage-build`.
   - **System Accounts**: Declare with `[[sysusers]]` (emitted to `usr/lib/sysusers.d/<pkg>.conf`).
   - **Services**: Define using declarative `service.toml` beside `recipe.toml` (see [service_spec.md](file:///home/ir/newworld/recipes/docs/specs/service_spec.md)).
   - **Triggers**: Define post-transaction hooks using `triggers.toml` beside `recipe.toml` (see [triggers_spec.md](file:///home/ir/newworld/recipes/docs/specs/triggers_spec.md)).
3. **Sources & Checksums**:
   - Archive sources require a complete 64-character lowercase hexadecimal SHA-256 checksum (`sha256 = "..."`).
   - Git sources require an exact 40- or 64-character commit object ID (`commit = "..."`) and network URLs.
   - When multiple source tarballs are needed, use ordered tables (`[[sources]]`).
4. **Patches**:
   - Place patches under `<pkgname>-<version>-<release>/patches/`.
   - Patches are applied in bytewise filename order with `patch -p1` during `src_prepare`.

---

## 5. Git Commit & Message Rules

### 5.1 English Only
- All commit messages, commit descriptions, and code/recipe comments **must be written entirely in English**.

### 5.2 Conventional Commits Format
Every commit must adhere strictly to the Conventional Commits specification:

```text
<type>(<scope>): <short description in English>

[optional body in English]
```

### 5.3 Allowed Types
- `feat`: Adding a new package recipe or enabling a new feature.
- `fix`: Fixing a compilation error, bad checksum, incorrect payload glob, or missing dependency.
- `refactor`: Restructuring recipe files or cleaning build logic without functional package breakage.
- `chore`: Maintenance tasks, metadata updates, repository tooling, or `.gitignore` adjustments.
- `docs`: Updating documentation or guidelines.

### 5.4 Standard Scope Format
- For package changes, use `<category>/<pkgname>` or `<pkgname>` (e.g., `feat(devel/gcc): add 16.2.0-1 for amd64`).
- For global repository changes, use `repo`, `tools`, or `docs` (e.g., `docs: update AGENTS.md`).

---

## 6. Verification Gate

Before submitting recipe changes:
1. Verify `recipe.toml` syntax against Schema Version `1`.
2. Ensure all checksums (`sha256`) and commit hashes match upstream sources.
3. Validate that payload globs accurately capture package files without overlapping collisions.
