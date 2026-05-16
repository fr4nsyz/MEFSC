cmake_minimum_required(VERSION 3.14)

project(MFSC LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(SQLite3 REQUIRED)
find_package(Sodium REQUIRED)

# --- FTXUI (TUI library for the client) ---
include(FetchContent)
FetchContent_Declare(ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG v6.1.9
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(ftxui)

add_library(common_lib STATIC
    src/encryption_utils/SessionEnc.cpp
    src/encryption_utils/encryption_utils.cpp
)

target_include_directories(common_lib PUBLIC 
    include/common
    ${sodium_INCLUDE_DIR}
)

target_link_libraries(common_lib PRIVATE sodium)

add_executable(server 
    src/server/server.cpp 
    src/server/auth.cpp 
    src/server/read_write_handlers.cpp
    src/server/server_logger.cpp
)

target_include_directories(server PUBLIC include)

target_link_libraries(server PRIVATE
    common_lib
    SQLite::SQLite3
)


add_executable(client 
    src/client/client.cpp 
    src/client/authed_entry.cpp
    src/client/tui_menu.cpp
)

set_target_properties(client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/client_fs"
)

target_include_directories(client PUBLIC include)

target_link_libraries(client PRIVATE
    common_lib
    ftxui::screen
    ftxui::dom
    ftxui::component
)

option(BUILD_TESTS "Build unit and integration tests" OFF)
if(BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  enable_testing()
  add_subdirectory(tests)
endif()
