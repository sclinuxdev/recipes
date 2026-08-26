#!/bin/sh
# Clang driver shim: bind to whatever GCC installation is installed RIGHT NOW,
# never to a version recorded at build time.
#
# Release 1 baked --gcc-install-dir=<build-time path> into <name>.cfg files;
# any gcc slot upgrade (15 -> 16) stranded those paths and every compile died
# with "'.../15.3.0' does not contain a GCC installation". This shim resolves
# the newest GCC installation across ALL channel slots at invocation time, so
# clang tracks gcc upgrades without recipe or cfg edits.

self=$(readlink -f -- "$0" 2>/dev/null) || self=$0
[ -n "$self" ] || self=$0
dir=$(dirname -- "$self")

# Newest GCC install dir wins: /opt/channels/gcc/<slot>/lib/gcc/<triplet>/<ver>
d=$(ls -dv /opt/channels/gcc/*/lib/gcc/*/*/ 2>/dev/null | tail -n1)
d=${d%/}

case $(basename -- "$0") in
c++|clang++) exec "$dir/../libexec/clang++" ${d:+"--gcc-install-dir=$d"} "$@" ;;
*)           exec "$dir/clang-22"       ${d:+"--gcc-install-dir=$d"} "$@" ;;
esac
