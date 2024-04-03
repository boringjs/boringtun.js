cmake_minimum_required(VERSION 3.9)

project(boringtunjs)

set(CMAKE_CXX_STANDARD 17)

if (DEFINED ENV{BUILD_DIR})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY $ENV{BUILD_DIR})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY $ENV{BUILD_DIR})
else ()
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif ()

if ($ENV{CLION_IDE})
    exec_program(npx ${CMAKE_CURRENT_SOURCE_DIR}
            ARGS cmake-js print-cmakejs-include -l error
            OUTPUT_VARIABLE CMAKE_JS_INC
    )
endif ()

include_directories(${CMAKE_JS_INC})

file(GLOB SOURCE_FILES "lib/*.cpp" "boringtun/boringtun/src/wireguard_ffi.h")

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})

if(WIN32)
    set(BORINGTUN_LIB_NAME "boringtun.lib")
    target_link_libraries(your_target PRIVATE Ws2_32)
else()
    set(BORINGTUN_LIB_NAME "libboringtun.a")
endif()

target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB} ${CMAKE_CURRENT_SOURCE_DIR}/boringtun/target/release/${BORINGTUN_LIB_NAME})
