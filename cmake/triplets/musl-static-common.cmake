set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
set(VCPKG_BUILD_TYPE release)
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/../toolchains/musl-cross.cmake")
set(VCPKG_ENV_PASSTHROUGH
    CJS_CROSS_ROOT CJS_CROSS_TRIPLE CJS_CROSS_PROCESSOR CJS_CROSS_SYSROOT)
# Autoconf must identify the target by its compiler triple, never by the runner.
set(VCPKG_MAKE_BUILD_TRIPLET "--host=$ENV{CJS_CROSS_TRIPLE}")
