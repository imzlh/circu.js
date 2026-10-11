#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
case "${1:?Usage: smoke-native.sh stage-directory}" in
    /*) stage=$1 ;;
    *) stage="$root/$1" ;;
esac
test -x "$stage/cjs"
test -x "$stage/cjsc"
test -f "$stage/types/engine.d.ts"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/cjs-smoke.XXXXXX")
cp "$stage/cjs" "$scratch/cjs-smoke"
# Standalone cjs is an executable template, not a source-file CLI. Exercise the
# actual distribution contract: cjsc attaches bytecode to a copy of the runtime.
(
    cd "$scratch"
    timeout --signal=KILL 180 "$stage/cjsc" -m -o cjs-smoke \
        "$root/scripts/ci/fixtures/smoke.mjs"
)
if timeout --signal=KILL 180 "$scratch/cjs-smoke" > "$scratch/output.log" 2>&1; then
    cat "$scratch/output.log"
else
    status=$?
    cat "$scratch/output.log"
    exit "$status"
fi
grep -q '^CJS_SMOKE_OK ' "$scratch/output.log"
