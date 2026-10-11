#!/usr/bin/env bash
set -euo pipefail

target=${1:?usage: build-cross-linux.sh mips|mipsel|mips64|riscv64|armv5}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
case "$target" in
    mips) triple=mips-linux-musl; processor=mips; emulator=qemu-mips; wasm=OFF; wamr=MIPS; big_endian=1 ;;
    mipsel) triple=mipsel-linux-musl; processor=mips; emulator=qemu-mipsel; wasm=ON; wamr=MIPS; big_endian=0 ;;
    mips64) triple=mips64-linux-musl; processor=mips64; emulator=qemu-mips64; wasm=OFF; wamr=MIPS; big_endian=1 ;;
    riscv64) triple=riscv64-linux-musl; processor=riscv64; emulator=qemu-riscv64; wasm=ON; wamr=RISCV64; big_endian=0 ;;
    armv5) triple=armv5l-linux-musleabi; processor=armv5l; emulator=qemu-arm; wasm=ON; wamr=ARMV5; big_endian=0 ;;
    *) printf 'Unsupported cross target: %s\n' "$target" >&2; exit 2 ;;
esac
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
    printf 'musl.cc cross toolchains require an x86_64 Linux build host.\n' >&2
    exit 2
fi
for program in cmake ninja git curl tar sha512sum node timeout "$emulator"; do
    command -v "$program" >/dev/null
done

build="$root/build-cross-$target"
downloads="${RUNNER_TEMP:-$root/.tmp-cross}/cjs-toolchains"
archive="$triple-cross.tgz"
mkdir -p "$build/bin" "$downloads"
curl --fail --location --retry 3 "https://musl.cc/$archive" -o "$downloads/$archive"
checksum=$(awk -v archive="$archive" '$2 == archive { print $1 }' "$root/scripts/ci/musl-toolchains.sha512")
[[ ${#checksum} -eq 128 ]]
printf '%s  %s\n' "$checksum" "$downloads/$archive" | sha512sum --check --strict
tar -xzf "$downloads/$archive" -C "$downloads"

export CJS_CROSS_ROOT="$downloads/$triple-cross"
export CJS_CROSS_TRIPLE="$triple"
export CJS_CROSS_PROCESSOR="$processor"
export PATH="$CJS_CROSS_ROOT/bin:$PATH"
export CJS_CROSS_SYSROOT
CJS_CROSS_SYSROOT=$("$triple-gcc" -print-sysroot)
[[ -d "$CJS_CROSS_SYSROOT" && "$CJS_CROSS_SYSROOT" != / ]]
[[ $("$triple-gcc" -dumpmachine) == "$triple" ]]
"$triple-gcc" --version
if [[ $target == mipsel ]]; then
    # WAMR's MIPS native-call assembly requires the o32 hard-float ABI.
    printf '%s\n' \
        '#if !defined(__mips_hard_float) || _MIPS_SIM != _ABIO32' \
        '#error WAMR requires the MIPS o32 hard-float toolchain' \
        '#endif' | "$triple-gcc" -x c -E - >/dev/null
fi

# Use the same vcpkg revision as the manifest, including its port versions.
vcpkg_revision=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))["builtin-baseline"])' "$root/vcpkg.json")
vcpkg_root="$build/vcpkg"
if [[ ! -d "$vcpkg_root/.git" ]]; then
    git init "$vcpkg_root"
    git -C "$vcpkg_root" remote add origin https://github.com/microsoft/vcpkg.git
fi
git -C "$vcpkg_root" fetch --depth 1 origin "$vcpkg_revision"
git -C "$vcpkg_root" checkout --detach FETCH_HEAD
"$vcpkg_root/bootstrap-vcpkg.sh" -disableMetrics

cmake -S "$root" -B "$build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_TOOLCHAIN_FILE="$vcpkg_root/scripts/buildsystems/vcpkg.cmake" \
    -DVCPKG_TARGET_TRIPLET="$target-linux-musl" \
    -DVCPKG_HOST_TRIPLET=x64-linux \
    -DVCPKG_OVERLAY_TRIPLETS="$root/cmake/triplets" \
    -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE="$root/cmake/toolchains/musl-cross.cmake" \
    -DVCPKG_INSTALLED_DIR="$build/vcpkg_installed" \
    -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="$build/bin" \
    -DBUILD_WITH_WASM="$wasm" -DWAMR_BUILD_TARGET="$wamr"
cmake --build "$build" --target cjsc qjsc --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-4}"

if [[ $big_endian == 1 ]]; then
    # These generated QuickJS builtins are also bytecode. Rebuild them before
    # qjs and cjsc are relinked so no little-endian blobs reach a big-endian CPU.
    (
        cd "$root/deps/quickjs"
        for builtin in builtin-array-fromasync builtin-iterator-zip builtin-iterator-zip-keyed; do
            "$emulator" -L "$CJS_CROSS_SYSROOT" "$build/bin/qjsc" \
                -C -ss -o "$builtin.h" "$builtin.js"
        done
    )
    cmake --build "$build" --target cjsc --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-4}"
fi
cmake --build "$build" --target cjs-cli cjsc --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-4}"

mkdir -p "$build/stage"
cp "$build/bin/cjs" "$build/bin/cjsc" "$build/stage/"
cp -R "$root/types" "$build/stage/types"
for binary in cjs cjsc; do
    "$triple-strip" "$build/stage/$binary"
    "$triple-readelf" -h "$build/stage/$binary"
    "$triple-readelf" -l "$build/stage/$binary" > "$build/$binary-headers.txt"
    "$triple-readelf" -d "$build/stage/$binary" > "$build/$binary-dynamic.txt"
    if grep -q INTERP "$build/$binary-headers.txt" || grep -q NEEDED "$build/$binary-dynamic.txt"; then
        printf 'Expected a fully static musl executable: %s\n' "$binary" >&2
        exit 1
    fi
done
# Compile bytecode on the target CPU so endianness also matches for MIPS.
cp "$build/stage/cjs" "$build/cjs-smoke"
(
    cd "$build"
    timeout --kill-after=10s 180s "$emulator" -L "$CJS_CROSS_SYSROOT" \
        "$build/stage/cjsc" -m -o cjs-smoke "$root/scripts/ci/fixtures/smoke.mjs"
)
timeout --kill-after=10s 180s "$emulator" -L "$CJS_CROSS_SYSROOT" "$build/cjs-smoke" \
    | tee "$build/smoke.log"
grep -q '^CJS_SMOKE_OK ' "$build/smoke.log"

mkdir -p "$root/artifacts"
cat > "$build/stage/BUILD-INFO.txt" <<EOF
Target: linux-musl-$target
Linkage: static musl, including third-party native dependencies
WebAssembly: $wasm
Dynamic native library loading is unavailable in this static musl build.
Toolchain: https://musl.cc/$archive
Toolchain SHA512: $checksum
vcpkg revision: $vcpkg_revision
EOF
tar -czf "$root/artifacts/cjs-linux-musl-$target.tar.gz" -C "$build/stage" cjs cjsc types BUILD-INFO.txt
