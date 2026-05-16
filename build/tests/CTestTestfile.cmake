# CMake generated Testfile for 
# Source directory: /home/fr4nsyz/vault/L_CACHES/mefsc/tests
# Build directory: /home/fr4nsyz/vault/L_CACHES/mefsc/build/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_common "/home/fr4nsyz/vault/L_CACHES/mefsc/build/tests/test_common")
set_tests_properties(test_common PROPERTIES  _BACKTRACE_TRIPLES "/home/fr4nsyz/vault/L_CACHES/mefsc/tests/CMakeLists.txt;23;add_test;/home/fr4nsyz/vault/L_CACHES/mefsc/tests/CMakeLists.txt;0;")
add_test(integ_upload "/home/fr4nsyz/vault/L_CACHES/mefsc/build/tests/integ_all" "--gtest_filter=*Upload*")
set_tests_properties(integ_upload PROPERTIES  WORKING_DIRECTORY "/home/fr4nsyz/vault/L_CACHES/mefsc/build" _BACKTRACE_TRIPLES "/home/fr4nsyz/vault/L_CACHES/mefsc/tests/CMakeLists.txt;50;add_test;/home/fr4nsyz/vault/L_CACHES/mefsc/tests/CMakeLists.txt;0;")
add_test(integ_list "/home/fr4nsyz/vault/L_CACHES/mefsc/build/tests/integ_all" "--gtest_filter=*ListFiles*")
set_tests_properties(integ_list PROPERTIES  WORKING_DIRECTORY "/home/fr4nsyz/vault/L_CACHES/mefsc/build" _BACKTRACE_TRIPLES "/home/fr4nsyz/vault/L_CACHES/mefsc/tests/CMakeLists.txt;52;add_test;/home/fr4nsyz/vault/L_CACHES/mefsc/tests/CMakeLists.txt;0;")
add_test(integ_delete "/home/fr4nsyz/vault/L_CACHES/mefsc/build/tests/integ_all" "--gtest_filter=*DeleteFile*")
set_tests_properties(integ_delete PROPERTIES  WORKING_DIRECTORY "/home/fr4nsyz/vault/L_CACHES/mefsc/build" _BACKTRACE_TRIPLES "/home/fr4nsyz/vault/L_CACHES/mefsc/tests/CMakeLists.txt;53;add_test;/home/fr4nsyz/vault/L_CACHES/mefsc/tests/CMakeLists.txt;0;")
add_test(integ_bad_auth "/home/fr4nsyz/vault/L_CACHES/mefsc/build/tests/integ_all" "--gtest_filter=*BadAuth*")
set_tests_properties(integ_bad_auth PROPERTIES  WORKING_DIRECTORY "/home/fr4nsyz/vault/L_CACHES/mefsc/build" _BACKTRACE_TRIPLES "/home/fr4nsyz/vault/L_CACHES/mefsc/tests/CMakeLists.txt;54;add_test;/home/fr4nsyz/vault/L_CACHES/mefsc/tests/CMakeLists.txt;0;")
