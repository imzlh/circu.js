#!/bin/sh

set -e

if [ "$1" != "${1#-}" ]; then
    # if the first argument is an option like `--help` or `-h`
    exec cjs "$@"
fi

case "$1" in
    run | eval | test | compile )
    # if the first argument is a known command
    exec cjs "$@";;
esac

exec "$@"
