cmake_minimum_required(VERSION 3.14)
project(ByteAV)

# Enable C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Use vcpkg for package management
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# Option for static or dynamic OpenSSL
option(USE_STATIC_OPENSSL "Build with static OpenSSL" ON)

if(USE_STATIC_OPENSSL)
    message(STATUS "Forcing Static OpenSSL linking...")
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(OPENSSL_ROOT_DIR "C:/vcpkg/installed/x64-windows-static")

    # Ensure OpenSSL links statically
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
else()
    message(STATUS "Using Dynamic OpenSSL linking...")
    set(OPENSSL_USE_STATIC_LIBS FALSE)
    set(OPENSSL_ROOT_DIR "C:/vcpkg/installed/x64-windows")
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the source file
add_executable(ByteAV file-scan.cpp)

# Force OpenSSL static linking explicitly
target_link_libraries(ByteAV PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Include OpenSSL headers
target_include_directories(ByteAV PRIVATE ${OPENSSL_INCLUDE_DIR})
