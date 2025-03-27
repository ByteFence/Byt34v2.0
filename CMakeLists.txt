cmake_minimum_required(VERSION 3.14)
project(ByteAV)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 🔧 Force static runtime (/MT instead of /MD)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")  # /MTd in Debug, /MT in Release

# Use vcpkg toolchain if not already set
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# ✅ Force static OpenSSL
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_ROOT_DIR "C:/vcpkg/installed/x64-windows-static")

# 📦 Find OpenSSL
find_package(OpenSSL REQUIRED)

# 🔍 Manually find YARA headers + libs (static)
find_path(YARA_INCLUDE_DIRS
    NAMES yara.h
    PATHS "C:/vcpkg/installed/x64-windows-static/include"
)

find_library(YARA_LIBRARIES
    NAMES yara
    PATHS "C:/vcpkg/installed/x64-windows-static/lib"
)

if(NOT YARA_INCLUDE_DIRS OR NOT YARA_LIBRARIES)
    message(FATAL_ERROR "YARA not found. Please install with vcpkg.")
endif()

# 🔨 Build ByteAV
add_executable(ByteAV ByteAV.cpp)

# ✅ Link OpenSSL + YARA statically
target_include_directories(ByteAV PRIVATE ${YARA_INCLUDE_DIRS})
target_link_libraries(ByteAV PRIVATE OpenSSL::SSL OpenSSL::Crypto ${YARA_LIBRARIES})
