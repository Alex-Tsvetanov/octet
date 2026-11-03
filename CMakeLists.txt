cmake_minimum_required(VERSION 3.25)
project(octet VERSION 0.1.0 DESCRIPTION "TLS and cleartext HTTP on one listening socket, chosen by the first octet"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

add_library(octet_core STATIC
    src/net.cpp
    src/http.cpp
    src/tls.cpp
    src/pki.cpp
    src/server.cpp)
target_include_directories(octet_core PUBLIC include)
target_link_libraries(octet_core PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
if(WIN32)
    target_link_libraries(octet_core PUBLIC ws2_32)
    # OpenSSL includes windows.h, whose min and max macros break std::min and std::max.
    target_compile_definitions(octet_core PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

if(MSVC)
    target_compile_options(octet_core PUBLIC /W4 /permissive- /utf-8 /EHsc)
else()
    target_compile_options(octet_core PUBLIC -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

add_executable(octet src/main.cpp)
target_link_libraries(octet PRIVATE octet_core)

add_executable(octet-mkcert tools/mkcert.cpp)
target_link_libraries(octet-mkcert PRIVATE octet_core)

add_executable(octet-micro bench/micro.cpp)
target_link_libraries(octet-micro PRIVATE octet_core)

enable_testing()

foreach(name classify replay http tls)
    add_executable(test_${name} tests/test_${name}.cpp)
    target_link_libraries(test_${name} PRIVATE octet_core)
    target_include_directories(test_${name} PRIVATE tests)
    add_test(NAME unit_${name} COMMAND test_${name})
endforeach()

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME integration_server
             COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/test_server.py
                     --server $<TARGET_FILE:octet>
                     --mkcert $<TARGET_FILE:octet-mkcert>
                     --workdir ${CMAKE_CURRENT_BINARY_DIR}/integration)
    set_tests_properties(integration_server PROPERTIES TIMEOUT 120)
endif()
