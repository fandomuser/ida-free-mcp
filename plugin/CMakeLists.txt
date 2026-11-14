cmake_minimum_required(VERSION 3.25)

# IDASDK must point at the official SDK checkout (the directory containing src/).
# scripts/build.ps1 sets it to third_party/ida-sdk.
if(NOT DEFINED ENV{IDASDK})
    message(FATAL_ERROR "Set IDASDK to the IDA SDK checkout (e.g. third_party/ida-sdk); see scripts/build.ps1")
endif()
include("$ENV{IDASDK}/src/cmake/idasdk_init.cmake")

project(idamcp_bridge CXX)
find_package(idasdk REQUIRED)

ida_add_plugin(idamcp
    SOURCES
        src/plugin.cpp
        src/handlers.cpp
        src/common.cpp
        src/types.cpp
        src/frames.cpp
        src/ui.cpp
        src/edit.cpp
        src/search.cpp
        src/analysis.cpp
        src/json.cpp
        src/transport.cpp
        src/platform.cpp
)
target_link_libraries(idamcp PRIVATE ws2_32 bcrypt shell32 ole32)

# ---- Standalone unit tests (no IDA kernel required) -------------------------
enable_testing()
add_executable(idamcp_unit_tests
    tests/unit_tests.cpp
    src/json.cpp
    src/transport.cpp
    src/platform.cpp
)
target_compile_features(idamcp_unit_tests PRIVATE cxx_std_17)
target_include_directories(idamcp_unit_tests PRIVATE src)
target_link_libraries(idamcp_unit_tests PRIVATE ws2_32 bcrypt shell32 ole32)
set_target_properties(idamcp_unit_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
add_test(NAME idamcp_unit_tests COMMAND idamcp_unit_tests)
