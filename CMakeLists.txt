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

# disable #pragma region warning for GCC
list(APPEND cjs_cflags -Wall -g -Wno-unknown-pragmas -Werror)
if (CMAKE_BUILD_TYPE MATCHES "Debug")
    list(APPEND cjs_cflags -ggdb -O0 -fno-omit-frame-pointer)
    add_compile_definitions(DEBUG)
endif()

set(CJS__VERSION_MAJOR 25)
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
cpr_option(CJS_USE_SYMBOL_INTERNAL "use symbol to pass through use fn instead of import.meta.use" OFF)

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
find_package(ZLIB REQUIRED)
find_package(EXPAT REQUIRED)
find_package(Iconv)  # optional
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
if (BUILD_WITH_WASM)
    find_package(iwasm REQUIRED)
endif()

option(libuv_buildtests "" OFF)
add_subdirectory(deps/libuv EXCLUDE_FROM_ALL)

add_library(cjs
    src/binary.c
    src/error.c
    src/mem.c
    src/modules.c
    src/signals.c
    src/timers.c
    src/utils.c
    src/version.c
    src/vm.c
    src/worker.c
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
    src/mod_sqlite3.c
    src/mod_streams.c
    src/mod_sys.c
    src/mod_udp.c
    src/mod_zlib.c
    src/mod_ssl.c
    src/mod_xml.c
    src/mod_crypto.c
    src/mod_http.c
)

if(UNIX)
    target_sources(cjs PUBLIC 
        src/mod_posix-socket.c
    )
endif()

if(llhttp_FOUND)
    target_link_libraries(cjs llhttp)
else()
    message(NOTICE "build with llhttp github repo")
    FetchContent_Declare(llhttp
        URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.3.0.tar.gz")

    set(LLHTTP_BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
    set(LLHTTP_BUILD_STATIC_LIBS ON CACHE INTERNAL "")
    FetchContent_MakeAvailable(llhttp)

    # Link with the llhttp_static target
    target_link_libraries(${EXAMPLE_PROJECT_NAME} ${PROJECT_LIBRARIES} llhttp_static ${PROJECT_NAME})
endif()

if (Iconv_FOUND)
    add_compile_definitions(CJS__HAS_ICONV)
    target_sources(cjs PUBLIC src/mod_text.c)
    target_link_libraries(cjs Iconv::Iconv)
else()
    message(NOTICE "build without iconv")
endif()

if (BUILD_WITH_CURL AND CURL_FOUND)
    add_compile_definitions(CJS__HAS_CURL)
    target_sources(cjs PUBLIC src/mod_curl.c)
    target_link_libraries(cjs CURL::libcurl)
endif()

if (BUILD_WITH_WASM)
    add_compile_definitions(CJS__HAS_WASM)
    target_sources(cjs PUBLIC src/mod_wasm.c)
    target_link_libraries(cjs iwasm)
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
    target_include_directories(cjs PRIVATE ${FFI_INCLUDE_DIR})
    target_link_libraries(cjs ${FFI_LIB})

    file(READ "${FFI_INCLUDE_DIR}/ffi.h" FFI_HEADER)
    string(FIND "${FFI_HEADER}" "FFI_BAD_ARGTYPE" FFI_HAS_BAD_ARGTYPE)

    # old versions of libffi don't have FFI_BAD_ARGTYPE
    if(FFI_HAS_BAD_ARGTYPE EQUAL -1)
        add_definitions(-DFFI_BAD_ARGTYPE=3)
    endif()
# endif()

if (BUILD_WITH_MIMALLOC)
    target_compile_definitions(cjs PRIVATE CJS__HAS_MIMALLOC)
    target_link_libraries(cjs mimalloc-static)
endif()

set_target_properties(cjs PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
)

string(TOLOWER ${CMAKE_SYSTEM_NAME} TJS_PLATFORM)
target_compile_options(cjs PRIVATE ${cjs_cflags})
target_compile_definitions(cjs PRIVATE TJS__PLATFORM="${TJS_PLATFORM}")
target_include_directories(cjs PUBLIC src)
# libutil is required for openpty
target_link_libraries(cjs qjs uv sqlite3 OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB EXPAT::EXPAT util)

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
