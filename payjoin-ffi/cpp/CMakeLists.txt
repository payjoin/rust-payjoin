cmake_minimum_required(VERSION 3.24)
project(payjoin_cpp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Generated bindings (run scripts/generate_bindings.sh first).
file(GLOB PAYJOIN_GENERATED_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
if(NOT PAYJOIN_GENERATED_SOURCES)
    message(FATAL_ERROR "No generated sources in src/. Run scripts/generate_bindings.sh first.")
endif()

# Consumable library target wrapping the payjoin_ffi cdylib.
add_library(payjoin_cpp ${PAYJOIN_GENERATED_SOURCES})
target_include_directories(payjoin_cpp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

find_library(PAYJOIN_FFI_LIB
    NAMES payjoin_ffi
    PATHS ${CMAKE_CURRENT_SOURCE_DIR}/lib
    NO_DEFAULT_PATH
    REQUIRED)
target_link_libraries(payjoin_cpp PUBLIC ${PAYJOIN_FFI_LIB})

# Let test binaries locate the cdylib without LD_LIBRARY_PATH.
set(CMAKE_BUILD_RPATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)

enable_testing()

add_executable(unit_tests tests/unit_tests.cpp)
target_link_libraries(unit_tests PRIVATE payjoin_cpp)
add_test(NAME unit_tests COMMAND unit_tests)

find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)
add_executable(integration_tests tests/integration_tests.cpp)
target_link_libraries(integration_tests PRIVATE payjoin_cpp CURL::libcurl nlohmann_json::nlohmann_json)
add_test(NAME integration_tests COMMAND integration_tests)
set_tests_properties(integration_tests PROPERTIES TIMEOUT 600)
