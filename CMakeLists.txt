cmake_minimum_required(VERSION 3.14)
project(ByteAV)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# vcpkg toolchain
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# Dependencies
find_package(OpenSSL REQUIRED)
find_package(glfw3   REQUIRED)
find_package(OpenGL  REQUIRED)

# YARA headers + lib
find_path(YARA_INCLUDE_DIR NAMES yara.h PATHS "C:/vcpkg/installed/x64-windows-static/include/yara")
find_library(YARA_LIB NAMES yara PATHS "C:/vcpkg/installed/x64-windows-static/lib")

if(NOT YARA_INCLUDE_DIR OR NOT YARA_LIB)
  message(FATAL_ERROR "YARA library not found. Check include dir: ${YARA_INCLUDE_DIR} and lib: ${YARA_LIB}")
endif()

# ImGui sources
file(GLOB IMGUI_SRC
    imgui/*.cpp
    imgui/backends/imgui_impl_glfw.cpp
    imgui/backends/imgui_impl_opengl3.cpp
)

# Main target
add_executable(ByteAV main.cpp ByteAV.cpp ${IMGUI_SRC})

# Include directories
target_include_directories(ByteAV PRIVATE
    imgui
    imgui/backends
    ${YARA_INCLUDE_DIR}
)
get_target_property(OSSL_INC OpenSSL::Crypto INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(ByteAV PRIVATE ${OSSL_INC})

# Link libraries
target_link_libraries(ByteAV PRIVATE
    glfw
    OpenGL::GL
    OpenSSL::SSL
    OpenSSL::Crypto
    ${YARA_LIB}
)
