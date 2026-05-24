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

# Initialize flag lists
set(cjs_cflags "")
set(cjs_ldflags "")

# Set compiler flags based on compiler type
if(MSVC)
    # MSVC compiler flags
    list(APPEND cjs_cflags /std:c11 /experimental:c11atomics /W4 /Zi)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    if (CMAKE_BUILD_TYPE MATCHES "Debug")
        list(APPEND cjs_cflags /Od)
        add_compile_definitions(DEBUG)
    endif()
else()
    # GCC/Clang compiler flags
    list(APPEND cjs_cflags -Wall -g -Wno-unknown-pragmas -Werror)
    if (CMAKE_BUILD_TYPE MATCHES "Debug")
        list(APPEND cjs_cflags -ggdb -O0 -fno-omit-frame-pointer)
        add_compile_definitions(DEBUG)
    endif()
endif()

# AddressSanitizer support
if(ENABLE_ASAN)
    if(MSVC)
        list(APPEND cjs_cflags /fsanitize=address)
    else()
        list(APPEND cjs_cflags -fsanitize=address -fno-omit-frame-pointer)
        list(APPEND cjs_ldflags -fsanitize=address)
    endif()
    add_compile_definitions(CJS__ASAN)
    message(STATUS "AddressSanitizer enabled")
endif()

set(CJS__VERSION_MAJOR 1)
set(CJS__VERSION_MINOR 0)
set(CJS__VERSION_PATCH 0)
set(CJS__VERSION_SUFFIX "")
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

cpr_option(BUILD_WITH_MIMALLOC "If ON (default), build with mimalloc" OFF)
cpr_option(USE_EXTERNAL_FFI "Specify to use external ffi dependency" ON)
cpr_option(BUILD_WITH_WASM "Enable WebAssembly support" ON)
cpr_option(BUILD_WITH_CURL "Enable cURL support" ON)
# we recommend to enable to make attached binary smaller
cpr_option(CJS_USE_SYMBOL_INTERNAL "use symbol to pass through use fn instead of import.meta.use" OFF)
# ASan is enabled by default in Debug builds, disabled in Release
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(_asan_default ON)
else()
    set(_asan_default OFF)
endif()
cpr_option(ENABLE_ASAN "Enable AddressSanitizer (ASan)" ${_asan_default})

add_subdirectory(deps/quickjs EXCLUDE_FROM_ALL)

option(libuv_buildtests "" OFF)

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

# use symbol instead of import.meta.use
if (CJS_USE_SYMBOL_INTERNAL)
    add_compile_definitions(CJS__DISABLE_MODULE_USE)
endif()

find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

# Check if SQLite3 supports extension loading
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
find_package(llhttp) # optional

# Check expat version for XML_ExpatVersion function availability
if(EXPAT_FOUND)
    include(CheckCSourceCompiles)
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
        add_compile_definitions(HAVE_XML_EXPAT_VERSION)
    endif()
endif()

if (BUILD_WITH_CURL)
    find_package(CURL REQUIRED)
endif()

option(libuv_buildtests "" OFF)
add_subdirectory(deps/libuv EXCLUDE_FROM_ALL)

add_library(libcjs
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
    src/mod_sys.c
    src/mod_udp.c
    src/mod_zlib.c
    src/mod_ssl.c
    src/mod_xml.c
    src/mod_crypto.c
    src/mod_http.c
    src/mod_socket.c
)

if (WIN32)
    target_sources(libcjs PRIVATE src/mod_win32.c)
endif()

if(llhttp_FOUND)
    # System-installed llhttp may not provide CMake targets
    # Use the traditional variables instead
    target_link_libraries(libcjs llhttp)
else()
    message(NOTICE "build with llhttp github repo")
    FetchContent_Declare(llhttp
        URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.3.0.tar.gz")

    set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
    set(BUILD_STATIC_LIBS ON CACHE INTERNAL "")
    FetchContent_MakeAvailable(llhttp)

    # Link with the llhttp::llhttp alias (points to llhttp_static when BUILD_STATIC_LIBS=ON)
    target_link_libraries(libcjs llhttp::llhttp)
endif()

if (Iconv_FOUND)
    add_compile_definitions(CJS__HAS_ICONV)
    target_sources(libcjs PUBLIC src/mod_text.c)
    target_link_libraries(libcjs Iconv::Iconv)
else()
    message(NOTICE "build without iconv")
endif()

if (BUILD_WITH_CURL AND CURL_FOUND)
    add_compile_definitions(CJS__HAS_CURL)
    target_sources(libcjs PUBLIC src/mod_curl.c)
    target_link_libraries(libcjs CURL::libcurl)
endif()

if (BUILD_WITH_WASM)
    add_compile_definitions(CJS__HAS_WASM)
    target_sources(libcjs PUBLIC src/mod_wasm.c)

    # WAMR Configuration (interpreter only for maximum portability)
    set(WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/wamr)

    # Detect platform for WAMR
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(WAMR_BUILD_PLATFORM "darwin")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set(WAMR_BUILD_PLATFORM "windows")
    else()
        set(WAMR_BUILD_PLATFORM "linux")
    endif()

    # Configure WAMR build options
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
    # Use C version of invokeNative on macOS to avoid Apple Clang assembly issues
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(WAMR_BUILD_INVOKE_NATIVE_GENERAL 1)
    endif()

    # Include WAMR build scripts
    include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

    add_library(vmlib STATIC ${WAMR_RUNTIME_LIB_SOURCE})
    target_include_directories(vmlib PUBLIC ${WAMR_ROOT_DIR}/core/iwasm/include)
    if(WIN32)
        target_link_libraries(vmlib PUBLIC ntdll)
    endif()
    target_include_directories(libcjs PRIVATE ${WAMR_ROOT_DIR}/core/iwasm/include)
    target_link_libraries(libcjs vmlib)
endif()

# add_library(ffi-test SHARED
#     tests/fixtures/ffi-test-lib.c
# )

# add_library(sqlite-test SHARED
#     tests/fixtures/sqlite-test-ext.c
# )

# target_link_libraries(sqlite-test sqlite3)


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
    target_include_directories(libcjs PRIVATE ${FFI_INCLUDE_DIR})
    target_link_libraries(libcjs ${FFI_LIB})

    file(READ "${FFI_INCLUDE_DIR}/ffi.h" FFI_HEADER)
    string(FIND "${FFI_HEADER}" "FFI_BAD_ARGTYPE" FFI_HAS_BAD_ARGTYPE)

    # old versions of libffi don't have FFI_BAD_ARGTYPE
    if(FFI_HAS_BAD_ARGTYPE EQUAL -1)
        add_definitions(-DFFI_BAD_ARGTYPE=3)
    endif()
# endif()

if (BUILD_WITH_MIMALLOC)
    target_compile_definitions(libcjs PRIVATE CJS__HAS_MIMALLOC)
    target_link_libraries(libcjs mimalloc-static)
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
# libutil is required for openpty
target_link_libraries(libcjs qjs uv_a OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB EXPAT::EXPAT)
if(TARGET SQLite3::SQLite3)
    target_link_libraries(libcjs SQLite3::SQLite3)
elseif(TARGET SQLite::SQLite3)
    target_link_libraries(libcjs SQLite::SQLite3)
else()
    target_link_libraries(libcjs sqlite3)
endif()

add_executable(cjs-cli
    src/cli.c
)
target_link_libraries(cjs-cli libcjs)
target_link_options(cjs-cli PRIVATE ${cjs_ldflags})
set_target_properties(cjs-cli
    PROPERTIES OUTPUT_NAME cjs
)

# Increase stack size for MSVC (default 1MB is too small for deep recursion
# in the TypeScript compiler when parsing large files like repl.ts)
if(MSVC)
    target_link_options(cjs-cli PRIVATE "/STACK:8388608")
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
if(MSVC)
    target_link_options(cjsc PRIVATE "/STACK:8388608")
endif()
