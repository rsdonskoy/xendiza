cmake_minimum_required(VERSION 4.2)
project(xendiza)

set(CMAKE_CXX_STANDARD 20)

option(XENDIZA_BENCH_WITH_CAPSTONE "Build benchmark with Capstone comparison" OFF)
option(XENDIZA_BENCH_WITH_ZYDIS "Build benchmark with Zydis comparison" OFF)

add_library(xendiza STATIC
    src/xendiza.cpp
    src/xendiza_x64.cpp
    src/xendiza_x86.cpp
    src/vex.cpp
    src/vex_decode.cpp
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
    test/test_perf_avx_a0.cpp
    test/test_perf_avx_a1.cpp
    test/test_perf_avx_a2a.cpp
    test/test_perf_avx_a2b.cpp
    test/test_perf_avx_a3.cpp
    test/test_abi_baseline.cpp
    test/test_vex_avx_a0.cpp
    test/test_vex_avx_a1.cpp
    test/test_vex_avx_a2a.cpp
    test/test_vex_avx_a2b.cpp
    test/test_vex_avx_a3.cpp
    test/test_vex_avx_forms.cpp
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

# AVX/AVX2 benchmark: deterministic corpora + xendiza vs Zydis comparison.
find_package(Python3 COMPONENTS Interpreter REQUIRED)
set(AVX_CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/bench/corpus_avx.bin")
set(AVX2_CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/bench/corpus_avx2.bin")
add_custom_command(
    OUTPUT ${AVX_CORPUS} ${AVX2_CORPUS}
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/bench/gen_avx_corpora.py" --isa avx --size 8388608 --output ${AVX_CORPUS}
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/bench/gen_avx_corpora.py" --isa avx2 --size 8388608 --output ${AVX2_CORPUS}
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test/data/vex_avx_inventory.csv"
            "${CMAKE_CURRENT_SOURCE_DIR}/bench/gen_avx_corpora.py"
    COMMENT "Generating AVX/AVX2 benchmark corpora"
)
add_custom_target(avx_corpora DEPENDS ${AVX_CORPUS} ${AVX2_CORPUS})

add_executable(xendiza_bench_avx
    bench/bench_avx.cpp
)

target_link_libraries(xendiza_bench_avx PRIVATE xendiza)
add_dependencies(xendiza_bench_avx avx_corpora)

if(MSVC)
    target_compile_options(xendiza_bench_avx PRIVATE /Zc:preprocessor)
endif()

if(XENDIZA_BENCH_WITH_ZYDIS)
    if(TARGET Zydis::Zydis)
        target_compile_definitions(xendiza_bench_avx PRIVATE XENDIZA_BENCH_WITH_ZYDIS=1)
        target_link_libraries(xendiza_bench_avx PRIVATE Zydis::Zydis)
    endif()
endif()

# Strict inventory differential harness (public C/C++ API entry points).
add_executable(xendiza_diff_harness
    test/diff/harness.cpp
)
target_link_libraries(xendiza_diff_harness PRIVATE xendiza)
if(MSVC)
    target_compile_options(xendiza_diff_harness PRIVATE /Zc:preprocessor)
endif()

# Deterministic smoke test for the AVX/AVX2 benchmark (requires Zydis).
add_test(NAME xendiza_bench_avx_smoke
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/test/diff/test_bench_avx.py" $<TARGET_FILE:xendiza_bench_avx>
)
set_tests_properties(xendiza_bench_avx_smoke PROPERTIES
    DEPENDS "xendiza_bench_avx;avx_corpora"
)

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
