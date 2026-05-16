# Password hash generator (INTERACTIVE — fast)
add_executable(gen_hash gen_hash.cpp)
target_link_libraries(gen_hash PRIVATE sodium)

# --- Unit tests ---

add_executable(test_common
  test_session_enc.cpp
  test_encryption_utils.cpp
  test_fs_operator.cpp
  ${CMAKE_SOURCE_DIR}/src/server/read_write_handlers.cpp
)
target_include_directories(test_common PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/include/common
  ${sodium_INCLUDE_DIR}
)
target_link_libraries(test_common PRIVATE
  common_lib
  gtest
  gtest_main
)
add_test(NAME test_common COMMAND test_common)

# --- Integration test ---

# Template: create a test DB, start server, run client with canned input,
# compare output. Each integration variant re-uses the same binary.
#
# The integ binary is a single gtest file that parameterizes over scenario.
# It spawns the server and client as subprocesses, feeding test input and
# asserting on client stdout.

add_executable(integ_all
  integ_all.cpp
)
target_include_directories(integ_all PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/include/common
  ${sodium_INCLUDE_DIR}
  ${SQLite3_INCLUDE_DIR}
)
target_link_libraries(integ_all PRIVATE
  gtest
  gtest_main
  SQLite::SQLite3
)

# Register each scenario as a separate ctest test so they can run in parallel
add_test(NAME integ_upload   COMMAND integ_all --gtest_filter=*Upload*)
#add_test(NAME integ_download COMMAND integ_all --gtest_filter=*Download*)
add_test(NAME integ_list     COMMAND integ_all --gtest_filter=*ListFiles*)
add_test(NAME integ_delete   COMMAND integ_all --gtest_filter=*DeleteFile*)
add_test(NAME integ_bad_auth COMMAND integ_all --gtest_filter=*BadAuth*)

# Integ tests need to find server + client binaries at CMAKE_BINARY_DIR
set_tests_properties(integ_upload integ_list integ_delete integ_bad_auth
    PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
