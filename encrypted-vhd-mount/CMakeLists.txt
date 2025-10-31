cmake_minimum_required(VERSION 3.15)
project(encrypted-vhd-mount)

set (CMAKE_CXX_STANDARD 17)

# 启用 MSVC 运行库新策略并默认使用静态运行库
if (MSVC)
  cmake_policy(SET CMP0091 NEW)
  # Release 使用 /MT，Debug 使用 /MTd
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

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

# 目标级运行库属性（确保使用静态运行库）
if (MSVC)
  set_property(TARGET encrypted-vhd-mount PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

target_link_libraries(encrypted-vhd-mount
    "${DOKAN_ROOT}/lib/dokan2.lib"
    bcrypt
)

# 为 Dokan 采用延迟加载，避免进程入口前加载失败导致静默退出
if (MSVC)
  target_link_options(encrypted-vhd-mount PRIVATE /DELAYLOAD:dokan2.dll)
  target_link_libraries(encrypted-vhd-mount delayimp)
endif()

# Lightweight bench target for Container I/O without Dokan
add_executable(evhd-bench
    "${SOURCE_ROOT}/bench.cc"
    "${SOURCE_ROOT}/crypto.cc"
    "${SOURCE_ROOT}/evhd.cc"
    "${SOURCE_ROOT}/crypto.h"
    "${SOURCE_ROOT}/evhd.h"
)
target_link_libraries(evhd-bench bcrypt)