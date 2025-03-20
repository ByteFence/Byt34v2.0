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

add_executable(ByteAV ByteAV.cpp)
target_link_libraries(ByteAV PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(ByteAV PRIVATE ${OPENSSL_INCLUDE_DIR})
