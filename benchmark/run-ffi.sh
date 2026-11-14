#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build="$root/build"

case "${1:-}" in
    --) shift ;;
    --*) ;;
    '') ;;
    *) build=$1; shift
       if [ "${1:-}" = "--" ]; then shift; fi ;;
esac

case "$build" in
    /*) ;;
    *) build="$root/$build" ;;
esac

runtime="$build/cjs"
compiler="$build/cjsc"
if [ ! -x "$runtime" ] && [ -x "$build/cjs.exe" ]; then
    runtime="$build/cjs.exe"
fi
if [ ! -x "$compiler" ] && [ -x "$build/cjsc.exe" ]; then
    compiler="$build/cjsc.exe"
fi

if [ ! -x "$runtime" ] || [ ! -x "$compiler" ]; then
    echo "Missing cjs/cjsc in $build; build the cjs-cli and cjsc targets first." >&2
    exit 1
fi

fixture=''
for candidate in \
    "$build/libffi_fixture.so" \
    "$build/libffi_fixture.dylib" \
    "$build/ffi_fixture.dll"
do
    if [ -f "$candidate" ]; then
        fixture=$candidate
        break
    fi
done
if [ -z "$fixture" ]; then
    echo "Missing ffi_fixture shared library in $build; build the ffi_fixture target first." >&2
    exit 1
fi

scratch=$(mktemp -d "${TMPDIR:-/tmp}/cjs-ffi-benchmark.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

program="$scratch/cjs-ffi-benchmark"
case "$runtime" in
    *.exe) program="$program.exe" ;;
esac

cp "$runtime" "$program"
cp "$fixture" "$scratch/$(basename "$fixture")"
(
    cd "$scratch"
    "$compiler" -m -o "$program" "$root/benchmark/ffi.js" >&2
)

"$program" "$@"
