cmake_minimum_required(VERSION 3.14)
project(ByteAV)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Use vcpkg for OpenSSL
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_ROOT_DIR "C:/vcpkg/installed/x64-windows-static")

find_package(OpenSSL REQUIRED)

# Manually find YARA
find_path(YARA_INCLUDE_DIRS
    NAMES yara.h
    HINTS "C:/vcpkg/installed/x64-windows/include"
)

find_library(YARA_LIBRARIES
    NAMES yara
    HINTS "C:/vcpkg/installed/x64-windows/lib"
)

if(NOT YARA_INCLUDE_DIRS OR NOT YARA_LIBRARIES)
    message(FATAL_ERROR "Could NOT find YARA. Please install via vcpkg or set paths manually.")
endif()

add_executable(ByteAV ByteAV.cpp)

# Link OpenSSL
target_link_libraries(ByteAV PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Link YARA
target_include_directories(ByteAV PRIVATE ${YARA_INCLUDE_DIRS})
target_link_libraries(ByteAV PRIVATE ${YARA_LIBRARIES})

# If you want: message(STATUS "YARA include dir: ${YARA_INCLUDE_DIRS}")
#             message(STATUS "YARA lib: ${YARA_LIBRARIES}")
