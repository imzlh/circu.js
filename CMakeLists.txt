cmake_minimum_required(VERSION 3.14)

cmake_policy(SET CMP0091 NEW)

project(cjs LANGUAGES C)

include(ExternalProject)
include(FetchContent)
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

# Release builds: minimize size across every target configured from here
# down (qjs, uv_a, vmlib, libcjs, cjs-cli) — dead-strip at the section
# level, strip symbols/debug info at link time, and enable LTO.
if(NOT MSVC AND NOT CMAKE_BUILD_TYPE MATCHES "Debug")
    add_compile_options(-Os -ffunction-sections -fdata-sections)
    add_link_options(-Wl,--gc-sections -s)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT _cjs_ipo_supported OUTPUT _cjs_ipo_error LANGUAGES C)
    if(_cjs_ipo_supported)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
        message(STATUS "LTO not supported, skipping: ${_cjs_ipo_error}")
    endif()
endif()

set(cjs_cflags "")
set(cjs_ldflags "")

# add_compile_definitions(CJS_DISABLE_DEBUG) # reverse the comment to disable debug

if(MSVC)
    list(APPEND cjs_cflags
        /std:c11 /experimental:c11atomics /W4 /Zi /WX /permissive- /utf-8
        /wd4100 /wd4996 /wd4127 /wd4244 /wd4267 /wd4152
        /wd4456 /wd4457 /wd4458 /wd4459 /wd4200 /wd4068 /wd4310 /wd4702
        /D_CRT_SECURE_NO_WARNINGS /D_CRT_DECLARE_NONSTDC_NAMES
    )
    list(APPEND cjs_ldflags /STACK:8388608 /WX /INCREMENTAL:NO /FORCE:MULTIPLE)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    if (CMAKE_BUILD_TYPE MATCHES "Debug")
        list(APPEND cjs_cflags /Od)
        add_compile_definitions(DEBUG)
    endif()
else()
    list(APPEND cjs_cflags -Wall -Wno-unknown-pragmas -Werror)
    list(APPEND cjs_ldflags -rdynamic)
    if (CMAKE_BUILD_TYPE MATCHES "Debug")
        list(APPEND cjs_cflags -g -ggdb -O0 -fno-omit-frame-pointer)
        add_compile_definitions(DEBUG)
    endif()
endif()

if(ENABLE_ASAN)
    if(MSVC)
        list(APPEND cjs_cflags /fsanitize=address)
        list(APPEND cjs_ldflags /DEBUG)
    else()
        list(APPEND cjs_cflags -fsanitize=address -fno-omit-frame-pointer)
        list(APPEND cjs_ldflags -fsanitize=address)
    endif()
    add_compile_definitions(CJS__ASAN)
    message(STATUS "AddressSanitizer enabled")
endif()

set(CJS__VERSION_MAJOR 1)
set(CJS__VERSION_MINOR 4)
set(CJS__VERSION_PATCH 0)
set(CJS__VERSION_SUFFIX "")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h"
)

macro(cpr_option OPTION_NAME OPTION_TEXT OPTION_DEFAULT)
    option(${OPTION_NAME} ${OPTION_TEXT} ${OPTION_DEFAULT})
    if(DEFINED ENV{${OPTION_NAME}})
        set(${OPTION_NAME} $ENV{${OPTION_NAME}})
    endif()
    if(${OPTION_NAME})
        add_definitions(-D${OPTION_NAME})
    endif()
    message(STATUS "  ${OPTION_NAME}: ${${OPTION_NAME}}")
endmacro()

cpr_option(BUILD_WITH_MIMALLOC "If ON (default), build with mimalloc" OFF)
cpr_option(USE_EXTERNAL_FFI "Specify to use external ffi dependency" ON)
cpr_option(BUILD_WITH_WASM "Enable WebAssembly support" ON)
cpr_option(CJS_USE_SYMBOL_INTERNAL "use symbol to pass through use fn instead of import.meta.use" OFF)

if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(_asan_default ON)
else()
    set(_asan_default OFF)
endif()
cpr_option(ENABLE_ASAN "Enable AddressSanitizer (ASan)" ${_asan_default})

if (WIN32)
    set(BUILD_SHARED_LIBS ON CACHE BOOL "Build shared library for QJS" FORCE)
endif()
set(QJS_ENABLE_ASAN ${ENABLE_ASAN} CACHE BOOL "Enable AddressSanitizer (ASan)" FORCE)
add_subdirectory(deps/quickjs EXCLUDE_FROM_ALL)
if(NOT WIN32)
    # qjs is linked statically into cjs-cli, but loadable native modules still
    # resolve JS_* from the host executable. Mark the QuickJS C API with default
    # visibility so ENABLE_EXPORTS/-rdynamic can place it in the dynamic table.
    target_compile_definitions(qjs PRIVATE BUILDING_QJS_SHARED)
endif()

if(BUILD_WITH_MIMALLOC)
    option(MI_OVERRIDE "" OFF)
    option(MI_BUILD_SHARED "" OFF)
    option(MI_BUILD_STATIC "" ON)
    option(MI_BUILD_OBJECT "" OFF)
    option(MI_BUILD_TESTS "" OFF)
    add_subdirectory(deps/mimalloc EXCLUDE_FROM_ALL)
endif()

# some old gcc don't have thread.h but have _Thread_local keyword
include(CheckIncludeFile)
check_include_file(threads.h HAVE_THREADS_H)
if(NOT HAVE_THREADS_H)
    add_compile_definitions(L_NO_THREADS_H)
    add_compile_definitions(thread_local=_Thread_local)
endif()

if (CJS_USE_SYMBOL_INTERNAL)
    add_compile_definitions(CJS__DISABLE_MODULE_USE)
endif()

find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

include(CheckCSourceCompiles)

set(CMAKE_REQUIRED_INCLUDES ${SQLite3_INCLUDE_DIRS})
set(CMAKE_REQUIRED_LIBRARIES ${SQLite3_LIBRARIES})
check_c_source_compiles("
    #include <sqlite3.h>
    int main() {
        sqlite3 *db;
        sqlite3_load_extension(db, \"test\", 0, 0);
        return 0;
    }
" SQLITE_HAS_LOAD_EXTENSION)

if(NOT SQLITE_HAS_LOAD_EXTENSION)
    message(WARNING "SQLite3 does not support extension loading. Some features may be disabled.")
endif()

find_package(ZLIB REQUIRED)
find_package(EXPAT REQUIRED)
find_package(Iconv REQUIRED)
find_package(CURL REQUIRED)
find_package(llhttp)

# Optional Brotli (system libbrotlienc/dec) for one-shot brotliCompress/brotliDecompress
find_path(BROTLI_INCLUDE_DIR brotli/encode.h)
find_library(BROTLIENC_LIBRARY NAMES brotlienc)
find_library(BROTLIDEC_LIBRARY NAMES brotlidec)
if(BROTLI_INCLUDE_DIR AND BROTLIENC_LIBRARY AND BROTLIDEC_LIBRARY)
    set(CJS_HAVE_BROTLI ON)
    message(STATUS "Brotli found: ${BROTLIENC_LIBRARY} ${BROTLIDEC_LIBRARY}")
else()
    set(CJS_HAVE_BROTLI OFF)
    message(STATUS "Brotli not found — brotliCompress/brotliDecompress unavailable")
endif()

if(EXPAT_FOUND)
    set(CMAKE_REQUIRED_INCLUDES ${EXPAT_INCLUDE_DIRS})
    set(CMAKE_REQUIRED_LIBRARIES ${EXPAT_LIBRARIES})
    check_c_source_compiles("
        #include <expat.h>
        int main() {
            const char* v = XML_ExpatVersion();
            (void)v;
            return 0;
        }
    " HAVE_XML_EXPAT_VERSION)

    if(NOT HAVE_XML_EXPAT_VERSION)
        message(STATUS "Old expat detected - using version macros instead of XML_ExpatVersion()")
        add_compile_definitions(CJS__NO_XML_EXPAT_VERSION)
    endif()
endif()

option(libuv_buildtests "" OFF)
add_subdirectory(deps/libuv EXCLUDE_FROM_ALL)

add_library(libcjs STATIC
    src/binary.c
    src/mod_error.c
    src/mem.c
    src/modules.c
    src/mod_signals.c
    src/mod_timers.c
    src/utils.c
    src/version.c
    src/vm.c
    src/mod_worker.c
    src/console.c
    src/sourcemap.c
    src/mod_algorithm.c
    src/mod_bjson.c
    src/mod_dns.c
    src/mod_engine.c
    src/mod_ffi.c
    src/mod_fs.c
    src/mod_asyncfs.c
    src/mod_fswatch.c
    src/mod_os.c
    src/mod_process.c
    src/mod_sqlite3.c
    src/mod_streams.c
    src/mod_udp.c
    src/mod_zlib.c
    src/mod_brotli.c
    src/mod_ssl.c
    src/mod_xml.c
    src/mod_crypto.c
    src/mod_http.c
    src/mod_socket.c
    src/mod_curl.c
    src/mod_debug.c
    src/mod_nodeapi.c
)

if(CJS_EXTRA_MODULE_NAMES)
    list(LENGTH CJS_EXTRA_MODULE_NAMES _cjs_extra_name_count)
    list(LENGTH CJS_EXTRA_MODULE_INITS _cjs_extra_init_count)
    list(LENGTH CJS_EXTRA_MODULE_WORKER_SAFE _cjs_extra_safe_count)
    if(NOT _cjs_extra_name_count EQUAL _cjs_extra_init_count OR
       NOT _cjs_extra_name_count EQUAL _cjs_extra_safe_count)
        message(FATAL_ERROR "CJS_EXTRA_MODULE_NAMES, CJS_EXTRA_MODULE_INITS, and CJS_EXTRA_MODULE_WORKER_SAFE must have the same length")
    endif()

    set(_cjs_extra_externs "")
    set(_cjs_extra_entries "")
    math(EXPR _cjs_extra_last "${_cjs_extra_name_count} - 1")
    foreach(_i RANGE 0 ${_cjs_extra_last})
        list(GET CJS_EXTRA_MODULE_NAMES ${_i} _cjs_extra_name)
        list(GET CJS_EXTRA_MODULE_INITS ${_i} _cjs_extra_init)
        list(GET CJS_EXTRA_MODULE_WORKER_SAFE ${_i} _cjs_extra_safe)
        string(APPEND _cjs_extra_externs "void ${_cjs_extra_init}(JSContext *ctx, JSValue ns);\n")
        string(APPEND _cjs_extra_entries "    { \"${_cjs_extra_name}\", ${_cjs_extra_init}, ${_cjs_extra_safe} },\n")
    endforeach()

    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/extra_externs.h" "${_cjs_extra_externs}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/extra_entries.h" "${_cjs_extra_entries}")

    target_compile_definitions(libcjs PRIVATE CJS_HAS_EXTRA_MODULES ${CJS_EXTRA_DEFINES})
    target_include_directories(libcjs PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${CJS_EXTRA_INCLUDE_DIRS})
    target_sources(libcjs PRIVATE ${CJS_EXTRA_SOURCES})
    target_link_libraries(libcjs PRIVATE ${CJS_EXTRA_LIBS})
endif()

if (WIN32)
    target_sources(libcjs PRIVATE src/mod_win32.c)
endif()

if(llhttp_FOUND)
    target_link_libraries(libcjs PRIVATE llhttp)
else()
    message(NOTICE "build with llhttp github repo")
    FetchContent_Declare(llhttp
        URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.3.0.tar.gz")

    set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
    set(BUILD_STATIC_LIBS ON CACHE INTERNAL "")
    FetchContent_MakeAvailable(llhttp)

    target_link_libraries(libcjs PRIVATE llhttp::llhttp)
endif()

if (Iconv_FOUND)
    add_compile_definitions(CJS__HAS_ICONV)
    target_sources(libcjs PRIVATE src/mod_text.c)
    target_link_libraries(libcjs PRIVATE Iconv::Iconv)
else()
    message(NOTICE "build without iconv")
endif()

if (BUILD_WITH_WASM)
    add_compile_definitions(CJS__HAS_WASM)
    target_sources(libcjs PRIVATE src/mod_wasm.c)

    set(WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/wamr)

    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(WAMR_BUILD_PLATFORM "darwin")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set(WAMR_BUILD_PLATFORM "windows")
    else()
        set(WAMR_BUILD_PLATFORM "linux")
    endif()

    set(WAMR_BUILD_INTERP 1)
    set(WAMR_BUILD_FAST_INTERP 1)
    set(WAMR_BUILD_AOT 0)
    set(WAMR_BUILD_JIT 0)
    set(WAMR_BUILD_LIBC_BUILTIN 1)
    set(WAMR_BUILD_LIBC_WASI 1)
    set(WAMR_BUILD_MULTI_MODULE 1)
    set(WAMR_BUILD_SIMD 0)
    set(WAMR_BUILD_REF_TYPES 1)
    set(WAMR_BUILD_BULK_MEMORY 1)
    set(WAMR_BUILD_LIB_PTHREAD 0)
    set(WAMR_BUILD_MINI_LOADER 0)
    set(WAMR_BUILD_LOAD_CUSTOM_SECTION 1)
    set(WAMR_DISABLE_HW_BOUND_CHECK 1)
    set(WAMR_DISABLE_STACK_HW_BOUND_CHECK 1)
    # Apple Clang doesn't support the assembly version of invokeNative
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(WAMR_BUILD_INVOKE_NATIVE_GENERAL 1)
    endif()

    include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

    add_library(vmlib STATIC ${WAMR_RUNTIME_LIB_SOURCE})
    target_include_directories(vmlib PUBLIC ${WAMR_ROOT_DIR}/core/iwasm/include)
    if(WIN32)
        target_link_libraries(vmlib PUBLIC ntdll)
    endif()
    target_include_directories(libcjs PRIVATE ${WAMR_ROOT_DIR}/core/iwasm/include)
    target_link_libraries(libcjs PRIVATE vmlib)
endif()

find_library(FFI_LIB NAMES libffi ffi REQUIRED)
find_path(FFI_INCLUDE_DIR NAMES ffi.h PATH_SUFFIXES ffi REQUIRED)
target_include_directories(libcjs PRIVATE ${FFI_INCLUDE_DIR})
target_link_libraries(libcjs PRIVATE ${FFI_LIB})

file(READ "${FFI_INCLUDE_DIR}/ffi.h" FFI_HEADER)
string(FIND "${FFI_HEADER}" "FFI_BAD_ARGTYPE" FFI_HAS_BAD_ARGTYPE)
if(FFI_HAS_BAD_ARGTYPE EQUAL -1)
    add_definitions(-DFFI_BAD_ARGTYPE=3)
endif()

if (BUILD_WITH_MIMALLOC)
    target_compile_definitions(libcjs PRIVATE CJS__HAS_MIMALLOC)
    target_link_libraries(libcjs PRIVATE mimalloc-static)
endif()

set_target_properties(libcjs PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
)

string(TOLOWER ${CMAKE_SYSTEM_NAME} TJS_PLATFORM)
target_compile_options(libcjs PRIVATE ${cjs_cflags})
target_link_options(libcjs PRIVATE ${cjs_ldflags})
target_compile_definitions(libcjs PRIVATE TJS__PLATFORM="${TJS_PLATFORM}")
target_include_directories(libcjs PUBLIC src)
target_include_directories(libcjs PRIVATE deps/nodeapi)
# qjs is PRIVATE so USING_QJS_SHARED doesn't propagate automatically on Windows
if(WIN32)
    target_compile_definitions(libcjs PRIVATE USING_QJS_SHARED)
endif()
target_link_libraries(libcjs PRIVATE qjs uv_a OpenSSL::SSL OpenSSL::Crypto CURL::libcurl ZLIB::ZLIB EXPAT::EXPAT)
if(CJS_HAVE_BROTLI)
    target_compile_definitions(libcjs PRIVATE CJS_HAVE_BROTLI)
    target_include_directories(libcjs PRIVATE ${BROTLI_INCLUDE_DIR})
    target_link_libraries(libcjs PRIVATE ${BROTLIENC_LIBRARY} ${BROTLIDEC_LIBRARY})
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(libcjs PRIVATE util ${CMAKE_DL_LIBS})
endif()
if(TARGET SQLite3::SQLite3)
    target_link_libraries(libcjs PRIVATE SQLite3::SQLite3)
elseif(TARGET SQLite::SQLite3)
    target_link_libraries(libcjs PRIVATE SQLite::SQLite3)
else()
    target_link_libraries(libcjs PRIVATE sqlite3)
endif()

add_executable(cjs-cli
    src/cli.c
)
target_link_libraries(cjs-cli PRIVATE libcjs uv_a)
target_link_options(cjs-cli PRIVATE ${cjs_ldflags})
set_target_properties(cjs-cli
    PROPERTIES OUTPUT_NAME cjs
               ENABLE_EXPORTS ON
)
# cjs-cli includes tjs.h which needs uv.h and iconv.h
if(Iconv_FOUND)
    target_include_directories(cjs-cli PRIVATE ${Iconv_INCLUDE_DIR})
    target_link_libraries(cjs-cli PRIVATE Iconv::Iconv)
endif()

if(CJS_BLOB_C)
    target_compile_definitions(libcjs PRIVATE CJS_BLOB_EMBEDDED)
    target_include_directories(libcjs PRIVATE "${CMAKE_BINARY_DIR}")
    target_sources(libcjs PRIVATE "${CJS_BLOB_C}")
    set_source_files_properties("${CJS_BLOB_C}" PROPERTIES GENERATED TRUE)
    message(STATUS "Embedding blob: ${CJS_BLOB_C}")
endif()

if(WIN32)
    add_executable(align_binary EXCLUDE_FROM_ALL cmake/align_binary.c)
    add_custom_command(TARGET cjs-cli POST_BUILD
        COMMAND $<TARGET_FILE:align_binary> "$<TARGET_FILE:cjs-cli>" 64
    )
endif()

add_executable(cjsc EXCLUDE_FROM_ALL
    src/binary.c
    src/qjsc.c
)
target_link_libraries(cjsc qjs)
target_link_options(cjsc PRIVATE ${cjs_ldflags})

if (WIN32)
    add_custom_command(TARGET cjs-cli POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:qjs>
            $<TARGET_FILE_DIR:cjs-cli>/qjs.dll
        COMMENT "Copying qjs.dll to cjs-cli output directory"
    )
    add_custom_command(TARGET cjsc POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:qjs>
            $<TARGET_FILE_DIR:cjsc>/qjs.dll
        COMMENT "Copying qjs.dll to cjsc output directory"
    )
endif()
