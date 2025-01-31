cmake_minimum_required(VERSION 3.14)
project(ByteAV)

# Enable C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Use vcpkg for package management
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# Option to choose static or dynamic linking
option(USE_STATIC_OPENSSL "Build with static OpenSSL" OFF)

if(USE_STATIC_OPENSSL)
    message(STATUS "Building with Static OpenSSL")
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(OPENSSL_ROOT_DIR "C:/vcpkg/installed/x64-windows-static")
else()
    message(STATUS "Building with Dynamic OpenSSL")
    set(OPENSSL_USE_STATIC_LIBS FALSE)
    set(OPENSSL_ROOT_DIR "C:/vcpkg/installed/x64-windows")
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the source file
add_executable(ByteAV file-scan.cpp)

# Link OpenSSL libraries
target_link_libraries(ByteAV PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Include OpenSSL headers
target_include_directories(ByteAV PRIVATE ${OPENSSL_INCLUDE_DIR})
