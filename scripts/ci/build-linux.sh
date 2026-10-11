#!/bin/sh
set -eu

libc=${1:?Usage: build-linux.sh glibc\|musl target}
target=${2:?Missing target architecture}
case "$libc" in
    glibc)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            ca-certificates build-essential cmake ninja-build pkg-config \
            binutils coreutils file libcurl4-openssl-dev libltdl-dev \
            libffi-dev libsqlite3-dev libssl-dev zlib1g-dev libexpat1-dev libbrotli-dev
        archive="cjs-linux-$target"
        ;;
    musl)
        # samurai provides /usr/bin/ninja on Alpine. Static curl needs the
        # archives of its complete dependency closure, not only libcurl.a.
        apk add --no-cache ca-certificates build-base cmake samurai pkgconf \
            binutils coreutils file \
            sqlite-dev sqlite-static openssl-dev openssl-libs-static \
            zlib-dev zlib-static expat-dev expat-static libffi-dev libtool \
            curl-dev curl-static brotli-dev brotli-static \
            nghttp2-static zstd-static libpsl-static libidn2-static libunistring-static
        archive="cjs-linux-musl-$target"
        ;;
    *) printf 'Unsupported libc: %s\n' "$libc" >&2; exit 1 ;;
esac

case "$target" in
    x86_64) wamr=X86_64 ;;
    i386) wamr=X86_32 ;;
    arm64|aarch64) wamr=AARCH64 ;;
    armv7) wamr=ARMV7_VFP ;;
    armv6)
        if [ "$libc" = glibc ]; then wamr=ARMV6; else wamr=ARMV6_VFP; fi
        ;;
    *) printf 'Unsupported architecture: %s\n' "$target" >&2; exit 1 ;;
esac

set -- -S . -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="$PWD/build-linux/bin" \
    -DWAMR_BUILD_TARGET="$wamr"
case "$target" in
    i386|armv6|armv7)
        # QuickJS uses 64-bit C11 atomics even on 32-bit CPUs. Put libatomic
        # after all archives, and apply it to both cjsc and the final runtime.
        set -- "$@" -DCMAKE_C_STANDARD_LIBRARIES=-latomic
        ;;
esac
if [ "$target" = armv6 ] && [ "$libc" = glibc ]; then
    set -- "$@" '-DCMAKE_C_FLAGS=-march=armv6 -mfloat-abi=soft' \
        '-DCMAKE_ASM_FLAGS=-march=armv6 -mfloat-abi=soft'
fi
if [ "$libc" = musl ]; then
    set -- "$@" -DCMAKE_EXE_LINKER_FLAGS=-static \
        -DCMAKE_PROJECT_cjs_INCLUDE="$PWD/scripts/ci/static-linux.cmake"
fi
cmake "$@"
cmake --build build-linux --target cjs-cli cjsc --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-4}"
mkdir -p build-linux/stage
cp build-linux/bin/cjs build-linux/bin/cjsc build-linux/stage/
cp -R types build-linux/stage/types
strip build-linux/stage/cjs build-linux/stage/cjsc
file build-linux/stage/cjs build-linux/stage/cjsc
if [ "$libc" = musl ]; then
    # A static artifact must have neither an interpreter nor shared-library
    # dependencies. This catches accidental selection of a system .so.
    for binary in cjs cjsc; do
        readelf -l "build-linux/stage/$binary" > "build-linux/$binary-headers.txt"
        readelf -d "build-linux/stage/$binary" > "build-linux/$binary-dynamic.txt"
        if grep -q INTERP "build-linux/$binary-headers.txt" \
            || grep -q NEEDED "build-linux/$binary-dynamic.txt"; then
            printf 'The musl release binary is not fully static: %s\n' "$binary" >&2
            exit 1
        fi
    done
fi
sh scripts/ci/smoke-native.sh build-linux/stage
mkdir -p artifacts
tar -czf "artifacts/$archive.tar.gz" -C build-linux/stage cjs cjsc types
