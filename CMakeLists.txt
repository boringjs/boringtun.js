cmake_minimum_required(VERSION 3.9)

project(boringtunjs)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_JS_INC})

file(GLOB SOURCE_FILES "lib/*.cpp" "boringtun/boringtun/src/wireguard_ffi.h")
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})

find_library(BORINGTUN_LIB NAMES boringtun PATHS "boringtun/target/release")
target_link_libraries(${PROJECT_NAME} ${BORINGTUN_LIB})
