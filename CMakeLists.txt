cmake_minimum_required(VERSION 3.9)

project(boringtunjs)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if (WIN32)
    # For (Debug, Release, etc.) output to the same directory.
    foreach (OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
        string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG_UPPER)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_BINARY_DIR}/lib)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_BINARY_DIR}/lib)
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_BINARY_DIR}/lib)
    endforeach (OUTPUTCONFIG CMAKE_CONFIGURATION_TYPES)
endif ()

if ($ENV{CLION_IDE})
    exec_program(npx ${CMAKE_CURRENT_SOURCE_DIR}
            ARGS cmake-js print-cmakejs-include -l error
            OUTPUT_VARIABLE CMAKE_JS_INC
    )
endif ()

include_directories(${CMAKE_JS_INC})

file(GLOB SOURCE_FILES "lib/*.cpp" "lib/*.h" boringtun/boringtun/src/wireguard_ffi.h)

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES}
        lib/wireguard_tunnel.h
        lib/wireguard_tunnel_wrapper.cpp
        lib/wireguard_tunnel_wrapper.h
        lib/utils.h
        lib/reference_singleton.cpp
        lib/reference_singleton.h
        lib/wireguard_global_wrapper.cpp
        lib/wireguard_global_wrapper.h
        lib/wireguard_tunnel.cpp)
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})

if (WIN32)
    set(BORINGTUN_LIB_NAME "boringtun.lib")
    target_link_libraries(${PROJECT_NAME} wsock32 WS2_32 Bcrypt Ntdll Userenv)
else ()
    set(BORINGTUN_LIB_NAME "libboringtun.a")
endif ()

target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB} ${CMAKE_CURRENT_SOURCE_DIR}/boringtun/target/release/${BORINGTUN_LIB_NAME})
