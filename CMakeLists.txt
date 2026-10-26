cmake_minimum_required(VERSION 3.23)

project(passwordmanager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(passwordmanager)
target_sources(passwordmanager
    PRIVATE
        src/main.cpp
        src/crypto.cpp
        src/storage.cpp
        src/vault.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
target_link_libraries(passwordmanager PRIVATE PkgConfig::SODIUM)

target_compile_options(passwordmanager PRIVATE -Wall -Wextra)