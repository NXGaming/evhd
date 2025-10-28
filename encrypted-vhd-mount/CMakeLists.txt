cmake_minimum_required(VERSION 3.10)
project(encrypted-vhd-mount)

set (CMAKE_CXX_STANDARD 17)

set(SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/src")
set(DOKAN_ROOT "${CMAKE_CURRENT_LIST_DIR}/../third_party/Dokan")

include_directories("${DOKAN_ROOT}/include")

add_executable(encrypted-vhd-mount
    "${SOURCE_ROOT}/main.cc"
    "${SOURCE_ROOT}/crypto.cc"
    "${SOURCE_ROOT}/evhd.cc"
    "${SOURCE_ROOT}/vfs_evhd.cc"
    "${SOURCE_ROOT}/crypto.h"
    "${SOURCE_ROOT}/evhd.h"
    "${SOURCE_ROOT}/vfs_evhd.h"
)

target_link_libraries(encrypted-vhd-mount
    "${DOKAN_ROOT}/lib/dokan2.lib"
    bcrypt
)