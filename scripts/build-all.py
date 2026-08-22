#!/usr/bin/env python3
"""Full-distro build orchestrator: build every recipe in dependency order.

Runs on the HOST and drives `sage build` inside the sclinux chroot, so the
chroot itself needs nothing beyond sage. For each recipe:

  1. build        -> arch-chroot <root> sage build /recipes/...
                     (log kept at <root>/logs/build/<archive>.log)
  2. publish      -> archive copied into <root>/var/cache/sage/repo and the
                     repo index.toml block for that package replaced in place
                     (`sage repo index` cannot be used: legacy archives in the
                     same directory predate the canonical usr/-path rule)
  3. install      -> only for INSTALL_FIRST packages (glibc must be live in
                     the root before anything else links against it)

Failures are recorded with the tail of the build log, dependents are
annotated, and failed packages get RETRY_ROUNDS extra passes at the end.
State lives in <root>/logs/build-all-state.json so reruns resume where the
previous run stopped; pass --force to redo finished packages.

Usage:
  python3 scripts/build-all.py                    # build/resume everything
  python3 scripts/build-all.py --dry-run          # print the ordered plan
  python3 scripts/build-all.py --only gcc,bash    # restrict to a subset
  python3 scripts/build-all.py --force bash       # rebuild even if done
"""

import argparse
import json
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path("/mnt")
RECIPES = Path("/home/ir/recipes")
LOGDIR = ROOT / "logs"
BUILD_LOGDIR = LOGDIR / "build"
REPO_DIR = ROOT / "var/cache/sage/repo"
STATE_FILE = LOGDIR / "build-all-state.json"

# Installed into the target root immediately after a successful build,
# before any other package compiles against the freshly built toolchain.
INSTALL_FIRST = {"glibc"}


def log(msg):
    print(msg, flush=True)


def sh(cmd, **kw):
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def chroot(script):
    return sh(["sudo", "arch-chroot", str(ROOT), "/bin/sh", "-lc", script])


def discover_recipes():
    """Return [{dir, meta}] for every recipes/**/recipe.toml."""
    out = []
    for rc in sorted(RECIPES.glob("*/*/*/recipe.toml")):
        try:
            doc = tomllib.load(open(rc, "rb"))
        except Exception as e:
            out.append({"dir": rc.parent, "meta": None, "error": str(e)})
            continue
        pkg = doc.get("package", {})
        out.append({
            "dir": rc.parent,
            "meta": {
                "name": pkg.get("name"),
                "version": pkg.get("version"),
                "release": pkg.get("release"),
                "deps": collect(doc, "dependencies") | collect(doc, "build_dependencies"),
                "provides": collect(doc, "provides"),
            },
            "error": None,
        })
    return out


def collect(doc, key):
    """Dependencies/provides live in the root, [package] and [source] scopes;
    [source] may also be a [[source]] array of tables."""
    found = set()
    scopes = [doc, doc.get("package", {})]
    src = doc.get("source", {})
    if isinstance(src, dict):
        scopes.append(src)
    elif isinstance(src, list):
        scopes.extend(el for el in src if isinstance(el, dict))
    for scope in scopes:
        v = scope.get(key)
        if isinstance(v, list):
            found.update(x for x in v if isinstance(x, str))
    return found


def dep_token(dep):
    """'binutils >= 2.47' -> 'binutils'; 'so:libc.so.6' -> 'so:libc.so.6'."""
    return dep.split()[0]


# Bootstrap exception: gcc needs the GMP family's headers to compile, while
# the family's runtime packages declare gcc-libs (built by gcc) as their
# provider -- a declaration cycle that only the build order can resolve.
# Sort the family first against the incumbent toolchain, then gcc itself.
BOOTSTRAP_EDGES = {
    "gcc": {"gmp", "gmp-dev", "mpfr", "mpfr-dev", "mpc", "mpc-dev",
            "isl", "isl-dev"},
}


def topo_sort(recipes):
    """Kahn's algorithm over name/provide edges; cycles broken alphabetically."""
    by_name = {}
    providers = {}  # token -> set of names
    for r in recipes:
        m = r["meta"]
        by_name[m["name"]] = r
        providers.setdefault(m["name"], set()).add(m["name"])
        for p in m["provides"]:
            providers.setdefault(p, set()).add(m["name"])

    deps_of = {}   # name -> set of provider-package names it needs
    for r in recipes:
        m = r["meta"]
        need = set()
        for d in m["deps"]:
            need |= providers.get(dep_token(d), set())
        need.discard(m["name"])
        need -= BOOTSTRAP_EDGES.get(m["name"], set())
        deps_of[m["name"]] = need

    order, emitted = [], set()
    pending = set(deps_of)
    while pending:
        ready = sorted(n for n in pending if deps_of[n] <= emitted)
        if not ready:  # cycle: emit alphabetically to make progress
            log("WARNING: dependency cycle among: " + ", ".join(sorted(pending)))
            ready = [sorted(pending)[0]]
        for n in ready:
            order.append(by_name[n])
            emitted.add(n)
            pending.discard(n)
    return order, deps_of


def archive_name(m):
    return f"{m['name']}-{m['version']}-{m['release']}-x86_64.pkg.tar.zst"


def find_repo_archive(m):
    """Existing repo archive for this name-version, any release: a rebuild
    auto-steps past the highest published release, so the artifact name
    leads whatever the recipe directory declares."""
    found = sorted(REPO_DIR.glob(f"{m['name']}-{m['version']}-*-x86_64.pkg.tar.zst"))
    return found[-1] if found else None


def find_fresh_archive(recipe_dir, m, not_before):
    """Newest archive in the recipe dir written during this build."""
    cands = [p for p in recipe_dir.glob(f"{m['name']}-{m['version']}-*-x86_64.pkg.tar.zst")
             if p.stat().st_mtime >= not_before]
    return max(cands, key=lambda p: p.stat().st_mtime) if cands else None


def emit_toml(v):
    import json as _j
    if isinstance(v, str):
        return _j.dumps(v)
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, list):
        if not v:
            return "[]"
        return "[\n" + ",\n".join("    " + emit_toml(x) for x in v) + ",\n]"
    return str(v)


USR_MERGE_TOPS = {"bin", "sbin", "lib", "lib64"}


def assert_usr_merged(archive_path, pkg_name):
    """Mirror sage's tape.cppm usr-merge rule: reject payloads with legacy
    top-level bin/sbin/lib/lib64 so violations surface at build time."""
    listing = sh(["tar", "--zstd", "-tf", str(archive_path)])
    if listing.returncode != 0:
        raise RuntimeError("cannot list archive: " + listing.stderr[:200])
    for line in listing.stdout.splitlines():
        if not line.startswith("data/") or line == "data/":
            continue
        top = line[5:].split("/", 1)[0]
        if top in USR_MERGE_TOPS and not (
            pkg_name == "base-files" and "/" not in line[5:]
        ):
            raise RuntimeError(
                f"usr-merge violation: payload contains '{line}' "
                f"(top-level '{top}/' is reserved)")


def repo_publish(archive_path, fname):
    """Copy archive into the repo and replace its index block atomically."""
    idx_path = REPO_DIR / "index.toml"
    manifest_raw = sh(["tar", "--zstd", "-xf", str(archive_path), "-O",
                       ".METADATA/manifest.toml"])
    if manifest_raw.returncode != 0:
        raise RuntimeError("cannot read manifest from " + str(archive_path))
    man = tomllib.loads(manifest_raw.stdout)["package"]

    fields = ["name", "version", "release", "description", "license",
              "channel", "arch", "dependencies", "provides",
              "build_compiler", "build_compiler_version", "build_cflags",
              "build_cxxflags", "build_ldflags"]
    new_pkg = {k: man[k] for k in fields if man.get(k) is not None}
    new_pkg["installed_size"] = man.get("installed_size", 0)
    new_pkg["file"] = fname

    text = idx_path.read_text()
    import tomllib as _t
    doc = _t.loads(text)
    pkgs = doc["packages"]
    replaced = False
    for i, p in enumerate(pkgs):
        if p.get("name") == new_pkg["name"]:
            pkgs[i] = new_pkg
            replaced = True
    if not replaced:
        pkgs.append(new_pkg)
    # drop stale archives of the same package with a different release
    for old in REPO_DIR.glob(f"{new_pkg['name']}-*.pkg.tar.zst"):
        if old.name != fname:
            old.unlink()
    out = text[:text.index("[[packages]]")] + "".join(
        "[[packages]]\n" + "\n".join(f"{k} = {emit_toml(p[k])}" for k in p) + "\n"
        for p in pkgs)
    _t.loads(out)
    tmp = idx_path.with_suffix(".toml.new")
    tmp.write_text(out)
    tmp.replace(idx_path)
    sh(["cp", str(archive_path), str(REPO_DIR / fname)])


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"built": {}, "failed": {}}


def save_state(st):
    tmp = STATE_FILE.with_suffix(".json.new")
    tmp.write_text(json.dumps(st, indent=1))
    tmp.replace(STATE_FILE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", help="comma-separated package names")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--retry-rounds", type=int, default=2)
    args = ap.parse_args()

    BUILD_LOGDIR.mkdir(parents=True, exist_ok=True)
    recipes = discover_recipes()
    bad = [r for r in recipes if r["meta"] is None]
    for r in bad:
        log(f"UNPARSEABLE recipe {r['dir']}: {r['error']}")
    recipes = [r for r in recipes if r["meta"]]

    order, deps_of = topo_sort(recipes)
    glibc = [r for r in order if r["meta"]["name"] == "glibc"]
    rest = [r for r in order if r["meta"]["name"] != "glibc"]
    order = glibc + rest  # glibc is always topologically first anyway

    if args.only:
        want = set(args.only.split(","))
        order = [r for r in order if r["meta"]["name"] in want]

    state = load_state()
    todo = []
    for r in order:
        m = r["meta"]
        if not args.force and m["name"] in state["built"]:
            log(f"  = {m['name']:<22} done in previous run, skipping")
            continue
        existing = find_repo_archive(m)
        if not args.force and existing:
            # An artifact only counts as done when its payload respects the
            # collapsed usr merge -- pre-merge archives rebuild regardless.
            try:
                assert_usr_merged(existing, m["name"])
            except Exception as e:
                log(f"  ! {m['name']:<22} {existing.name} predates the usr merge, rebuilding")
                log(f"      {e}")
            else:
                log(f"  = {m['name']:<22} artifact exists ({existing.name}), skipping")
                state["built"][m["name"]] = existing.name
                continue
        todo.append(r)

    log(f"\nPlan: {len(todo)} to build "
        f"({len(state['built'])} already done, first: "
        f"{todo[0]['meta']['name'] if todo else '-'})\n")
    if args.dry_run:
        for r in todo:
            m = r["meta"]
            log(f"  {m['name']:<24} {m['version']}-{m['release']}")
        return 0

    def build_one(r):
        m = r["meta"]
        aname = archive_name(m)
        rdir = "/recipes/" + r["dir"].relative_to(RECIPES).as_posix()
        # Two spellings of one log: the redirect happens inside the chroot,
        # whose root already *is* /mnt, so the leading component must go.
        blog = BUILD_LOGDIR / (aname + ".log")
        cblog = "/" + blog.relative_to(ROOT).as_posix()
        t0 = time.time()
        log(f"  > {m['name']:<22} building {m['version']}-{m['release']} ...")
        res = chroot(f"sage build {rdir} > {cblog} 2>&1; echo RC=$? >> {cblog}")
        tail = blog.read_text(errors="replace").strip().splitlines()[-6:] if blog.exists() else [f"(no log produced; arch-chroot rc={res.returncode}: {res.stderr[-200:]})"]
        ok = res.returncode == 0 and any(l.strip() == "RC=0" for l in tail)
        mins = (time.time() - t0) / 60
        if not ok:
            log(f"    FAIL after {mins:.1f}min — log: {blog}")
            for l in tail:
                log(f"      | {l[:140]}")
            return False
        # Archives land where the chroot wrote them: the /mnt recipes mirror,
        # not the host checkout this orchestrator iterates.
        art = find_fresh_archive(ROOT / "recipes" / r["dir"].relative_to(RECIPES), m, t0)
        if not art:
            log(f"    FAIL: RC=0 but no fresh artifact for {m['name']} in {r['dir']}")
            return False
        aname = art.name
        try:
            assert_usr_merged(art, m["name"])
        except Exception as e:
            log(f"    FAIL usr-merge check: {e}")
            return False
        try:
            repo_publish(art, aname)
        except Exception as e:
            log(f"    FAIL publishing: {e}")
            return False
        if m["name"] in INSTALL_FIRST:
            inst = chroot(f"sage install {m['name']} 2>&1 | tail -2")
            log(f"    install: {inst.stdout.strip().splitlines()[-1:] or ''}")
        log(f"    OK in {mins:.1f}min -> {aname}")
        return aname

    failures = []
    for r in todo:
        done = build_one(r)
        if done:
            state["built"][r["meta"]["name"]] = done
            state["failed"].pop(r["meta"]["name"], None)
        else:
            failures.append(r)
            state["failed"][r["meta"]["name"]] = time.strftime("%Y-%m-%dT%H:%M:%S")
        save_state(state)

    for rnd in range(1, args.retry_rounds + 1):
        if not failures:
            break
        log(f"\nRetry round {rnd}/{args.retry_rounds}: {len(failures)} package(s)")
        still = []
        for r in failures:
            done = build_one(r)
            if done:
                state["built"][r["meta"]["name"]] = done
                state["failed"].pop(r["meta"]["name"], None)
            else:
                still.append(r)
                state["failed"][r["meta"]["name"]] = time.strftime("%Y-%m-%dT%H:%M:%S")
            save_state(state)
        failures = still

    log(f"\nFinished: {len(state['built'])} built total, "
        f"{len(failures)} unresolved failure(s)")
    for r in failures:
        log(f"  FAILED: {r['meta']['name']}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
