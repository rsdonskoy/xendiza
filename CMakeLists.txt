cmake_minimum_required(VERSION 4.2)
project(xendiza)

set(CMAKE_CXX_STANDARD 20)

option(XENDIZA_BENCH_WITH_CAPSTONE "Build benchmark with Capstone comparison" OFF)
option(XENDIZA_BENCH_WITH_ZYDIS "Build benchmark with Zydis comparison" OFF)

add_library(xendiza STATIC
    src/xendiza.cpp
    src/xendiza_x64.cpp
    src/xendiza_x86.cpp
)

target_include_directories(xendiza
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# gsl::span appears in the public headers, so consumers inherit the dependency.
find_package(Microsoft.GSL CONFIG REQUIRED)
target_link_libraries(xendiza PUBLIC Microsoft.GSL::GSL)

if(MSVC)
    target_compile_options(xendiza PRIVATE /Zc:preprocessor)
endif()

# Tests
enable_testing()

find_package(GTest CONFIG REQUIRED)

add_executable(xendiza_tests
    test/test_basic_instructions.cpp
    test/test_x86_basic.cpp
    test/test_2byte_opcodes.cpp
    test/test_x86_2byte_opcodes.cpp
    test/test_opcode_extensions.cpp
    test/test_x87_opcodes.cpp
    test/test_public_api.cpp
    test/test_no_operands.cpp
    test/test_system_opcodes.cpp
    test/test_x86_opcode_extensions.cpp
    test/test_x86_x87_opcodes.cpp
    test/test_x86_prefixes.cpp
    test/test_x86_addr16.cpp
    test/test_x64_prefixes.cpp
    test/test_sse_m1.cpp
    test/test_sse_m2.cpp
    test/test_sse_m3.cpp
    test/test_sse_m4.cpp
    test/test_x86_x64_0f38_0f3a.cpp
    test/test_perf_regression.cpp
)

target_link_libraries(xendiza_tests PRIVATE xendiza GTest::gtest GTest::gtest_main)

if(MSVC)
    target_compile_options(xendiza_tests PRIVATE /Zc:preprocessor)
endif()

include(GoogleTest)
gtest_discover_tests(xendiza_tests)

# Example
add_executable(xendiza_example
    example/example.cpp
)

target_link_libraries(xendiza_example PRIVATE xendiza)

if(MSVC)
    target_compile_options(xendiza_example PRIVATE /Zc:preprocessor)
endif()

# Benchmark
add_executable(xendiza_bench
    bench/bench_disasm.cpp
)

target_link_libraries(xendiza_bench PRIVATE xendiza)

if(MSVC)
    target_compile_options(xendiza_bench PRIVATE /Zc:preprocessor)
endif()

if(XENDIZA_BENCH_WITH_CAPSTONE)
    find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)
    find_library(CAPSTONE_LIBRARY NAMES capstone)
    if(CAPSTONE_INCLUDE_DIR AND CAPSTONE_LIBRARY)
        target_compile_definitions(xendiza_bench PRIVATE XENDIZA_BENCH_WITH_CAPSTONE=1)
        target_include_directories(xendiza_bench PRIVATE ${CAPSTONE_INCLUDE_DIR})
        target_link_libraries(xendiza_bench PRIVATE ${CAPSTONE_LIBRARY})
    else()
        message(WARNING "Capstone requested but not found; benchmark will build without Capstone")
    endif()
endif()

if(XENDIZA_BENCH_WITH_ZYDIS)
    find_package(Zydis CONFIG QUIET)
    if(TARGET Zydis::Zydis)
        target_compile_definitions(xendiza_bench PRIVATE XENDIZA_BENCH_WITH_ZYDIS=1)
        target_link_libraries(xendiza_bench PRIVATE Zydis::Zydis)
        # Zydis' installed cmake target exports /WX /W4 as INTERFACE_COMPILE_OPTIONS,
        # which would force treat-warnings-as-error on the benchmark (and fail the
        # build on benign unused-parameter warnings in xendiza's own headers).
        # Strip those propagated flags so the benchmark uses our own warning policy.
        get_target_property(_zydis_iface_opts Zydis::Zydis INTERFACE_COMPILE_OPTIONS)
        if(_zydis_iface_opts)
            list(REMOVE_ITEM _zydis_iface_opts "/WX" "/W4" "/wd4201")
            set_target_properties(Zydis::Zydis PROPERTIES INTERFACE_COMPILE_OPTIONS "${_zydis_iface_opts}")
        endif()
    else()
        message(WARNING "Zydis requested but not found; benchmark will build without Zydis")
    endif()
endif()

# Install
include(GNUInstallDirs)
install(TARGETS xendiza
    EXPORT xendizaTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT xendizaTargets
    FILE xendizaTargets.cmake
    NAMESPACE xendiza::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/xendiza
)
