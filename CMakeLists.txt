cmake_minimum_required(VERSION 3.14)

project(cjs LANGUAGES C)

include(ExternalProject)
include(GNUInstallDirs)

if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, default to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif()
message(STATUS "Building in ${CMAKE_BUILD_TYPE} mode")
message(STATUS "Building with ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION} on ${CMAKE_SYSTEM}")

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_C_STANDARD 11)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND cjs_cflags -Wall -g)
if (CMAKE_BUILD_TYPE MATCHES "Debug")
    list(APPEND cjs_cflags -ggdb -O0 -fno-omit-frame-pointer)
    add_compile_definitions(DEBUG)
endif()

set(TJS__VERSION_MAJOR 25)
set(TJS__VERSION_MINOR 0)
set(TJS__VERSION_PATCH 0)
set(TJS__VERSION_SUFFIX "")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h"
)

macro(cpr_option OPTION_NAME OPTION_TEXT OPTION_DEFAULT)
    option(${OPTION_NAME} ${OPTION_TEXT} ${OPTION_DEFAULT})
    if(DEFINED ENV{${OPTION_NAME}})
        # Allow setting the option through an environment variable
        set(${OPTION_NAME} $ENV{${OPTION_NAME}})
    endif()
    if(${OPTION_NAME})
        add_definitions(-D${OPTION_NAME})
    endif()
    message(STATUS "  ${OPTION_NAME}: ${${OPTION_NAME}}")
endmacro()

cpr_option(BUILD_WITH_MIMALLOC "If ON (default), build with mimalloc" ON)
cpr_option(USE_EXTERNAL_FFI "Specify to use external ffi dependency" ON)
cpr_option(BUILD_WITH_WASM "Enable WebAssembly support" OFF)

add_subdirectory(deps/quickjs EXCLUDE_FROM_ALL)

option(libuv_buildtests "" OFF)

if(BUILD_WITH_WASM)
    set(BUILD_WASI "simple" CACHE STRING "WASI implementation")
    add_subdirectory(deps/wasm3 EXCLUDE_FROM_ALL)
endif()

if(BUILD_WITH_MIMALLOC)
    option(MI_OVERRIDE "" OFF)
    option(MI_BUILD_SHARED "" OFF)
    option(MI_BUILD_STATIC "" ON)
    option(MI_BUILD_OBJECT "" OFF)
    option(MI_BUILD_TESTS "" OFF)
    add_subdirectory(deps/mimalloc EXCLUDE_FROM_ALL)
endif()

find_package(CURL REQUIRED)
find_package(llhttp REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB)

option(libuv_buildtests "" OFF)
add_subdirectory(deps/libuv EXCLUDE_FROM_ALL)

add_library(cjs
    src/curl-utils.c
    src/curl-websocket.c
    src/binary.c
    src/error.c
    src/mem.c
    src/modules.c
    src/signals.c
    src/timers.c
    src/utils.c
    src/version.c
    src/vm.c
    src/wasm.c
    src/worker.c
    src/ws.c
    src/xhr.c
    src/console.c
    src/sourcemap.c
    src/mod_algorithm.c
    src/mod_dns.c
    src/mod_engine.c
    src/mod_ffi.c
    src/mod_fs.c
    src/mod_asyncfs.c
    src/mod_fswatch.c
    src/mod_os.c
    src/mod_process.c
    src/mod_pty.c
    src/mod_server.c
    src/mod_sqlite3.c
    src/mod_streams.c
    src/mod_sys.c
    src/mod_udp.c
    src/mod_zlib.c
    deps/quickjs/cutils.c
)

if(UNIX)
    target_sources(cjs PUBLIC 
        src/mod_posix-socket.c
        src/mod_posix-ffi.c
    )
endif()

add_library(ffi-test SHARED
    tests/fixtures/ffi-test-lib.c
)

add_library(sqlite-test SHARED
    tests/fixtures/sqlite-test-ext.c
)

target_link_libraries(sqlite-test sqlite3)


# if(NOT USE_EXTERNAL_FFI AND NOT MINGW AND NOT APPLE)
#     set(LIBFFI_SRC "${CMAKE_CURRENT_SOURCE_DIR}/deps/libffi")
#     set(TMP_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/ffi_root")
#     if(MINGW)
#         set(LIBFFI_STATIC_PATH ${TMP_INSTALL_DIR}/usr/local/lib/libffi.dll.a)
#     else()
#         set(LIBFFI_STATIC_PATH ${TMP_INSTALL_DIR}/usr/local/lib/libffi.a)
#     endif()
#     ExternalProject_Add(
#         libffi
#         BUILD_IN_SOURCE 1
#         SOURCE_DIR "${LIBFFI_SRC}"
#         CONFIGURE_COMMAND ./autogen.sh COMMAND ./configure --enable-static=yes --disable-shared --disable-docs --disable-multi-os-directory
#         BUILD_COMMAND make
#         INSTALL_DIR ${TMP_INSTALL_DIR}
#         INSTALL_COMMAND make DESTDIR=${TMP_INSTALL_DIR} install
#         EXCLUDE_FROM_ALL TRUE
#         BUILD_BYPRODUCTS ${LIBFFI_STATIC_PATH}
#     )
#     add_dependencies(cjs libffi)
#     add_library(libffi_a STATIC IMPORTED)
#     set_target_properties(libffi_a PROPERTIES IMPORTED_LOCATION ${LIBFFI_STATIC_PATH})
#     target_include_directories(cjs PRIVATE ${TMP_INSTALL_DIR}/usr/local/include)
#     target_link_libraries(cjs libffi_a)
# else()
    find_library(FFI_LIB NAMES libffi ffi REQUIRED)
    find_path(FFI_INCLUDE_DIR NAMES ffi.h PATH_SUFFIXES ffi REQUIRED)
    target_include_directories(cjs PRIVATE ${FFI_INCLUDE_DIR})
    target_link_libraries(cjs ${FFI_LIB})
# endif()

set_target_properties(cjs PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
)

string(TOLOWER ${CMAKE_SYSTEM_NAME} cjs_PLATFORM)
target_compile_options(cjs PRIVATE ${cjs_cflags})
target_compile_definitions(cjs PRIVATE TJS__PLATFORM="${TJS_PLATFORM}")
target_include_directories(cjs PUBLIC src)
target_link_libraries(cjs qjs uv sqlite3 CURL::libcurl llhttp OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB)

if (BUILD_WITH_MIMALLOC)
    target_compile_definitions(cjs PRIVATE TJS__HAS_MIMALLOC)
    target_link_libraries(cjs mimalloc-static)
endif()

if (BUILD_WITH_WASM)
    target_compile_definitions(cjs PRIVATE TJS__HAS_WASM)
    target_link_libraries(cjs wasm3)
endif()

add_executable(cjs-cli
    src/cli.c
)
target_link_libraries(cjs-cli cjs)
set_target_properties(cjs-cli
    PROPERTIES OUTPUT_NAME cjs
)

add_executable(cjsc EXCLUDE_FROM_ALL
    src/binary.c
    src/qjsc.c
)
target_link_libraries(cjsc qjs)
