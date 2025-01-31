cmake_minimum_required(VERSION 3.14)
project(MyAntivirus)


# Enable C++17 (or later if needed)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Use vcpkg for package management
if(CMAKE_TOOLCHAIN_FILE STREQUAL "")
    set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# Find OpenSSL (CMake will locate it)
find_package(OpenSSL REQUIRED)

# Add the source file
add_executable(Antivirus file-scan.cpp)

# Link OpenSSL libraries
target_link_libraries(Antivirus PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Include OpenSSL headers
target_include_directories(Antivirus PRIVATE ${OPENSSL_INCLUDE_DIR})
