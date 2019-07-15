cmake_minimum_required(VERSION 3.1)

set(
   CMAKE_CXX_FLAGS
   ${CMAKE_CXX_FLAGS}
   "-Wall -pedantic -std=gnu++14 -pthread"
)

find_package(GTest)
set(GTEST "gtest")

# Locate pthreads, which c++11 relies on for thread impl on Linux
# GTest depends on this too
find_package (Threads)

# Locate LibSSH
#find_library (LIBSSH
#   NAMES
#      ssh
#      libssh
#   PATHS
#      /usr/lib
#      /usr/local/lib
#      /opt/local/lib
#      /sw/lib
#      ${CMAKE_LIBRARY_PATH}
#      ${CMAKE_INSTALL_PREFIX}/lib
#)

#if(NOT LIBSSH)
#   message(FATAL_ERROR "libssh library not found")
#endif()

set(OPENSSL "OpenSSL::Crypto") 
find_package(OpenSSL REQUIRED)

# Locate JsonCpp
find_library (JSONCPP
   NAMES
      jsoncpp
      libjsoncpp
   PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
)

if(NOT JSONCPP)
   message(FATAL_ERROR "jsoncpp library not found")
endif()


include_directories(${PROJECT_SOURCE_DIR}/src/agent)
include_directories(${PROJECT_SOURCE_DIR}/src/crypt)
include_directories(${PROJECT_SOURCE_DIR}/src/keys)
include_directories(${PROJECT_SOURCE_DIR}/src/tools)

# keymaster unit tests

#file(
#   COPY
#   ${PROJECT_SOURCE_DIR}/test/keys/testkey
#   DESTINATION
#   ${CMAKE_CURRENT_BINARY_DIR}
#)

set(
   SRCS
   #${PROJECT_SOURCE_DIR}/src/tools/keymaster_config.cpp
   #${PROJECT_SOURCE_DIR}/src/keys/private_key.cpp
   #${PROJECT_SOURCE_DIR}/src/agent/ssh_agent.cpp
   #${PROJECT_SOURCE_DIR}/src/agent/agent_mgr.cpp
   ${PROJECT_SOURCE_DIR}/src/crypt/app_crypt.cpp
   #keymaster_config.t.cpp
   #private_key.t.cpp
   #ssh_agent.t.cpp
   #agent_mgr.t.cpp
   #keymaster_test_utils.cpp
   #keymaster_test_main.cpp
   main.cpp
)

set(TARGET_NAME ignisshin_test)

add_executable(${TARGET_NAME} ${SRCS})
target_link_libraries(
   ${TARGET_NAME}
   ${CMAKE_THREAD_LIBS_INIT}
   ${GTEST}
   ${OPENSSL} 
   ${JSONCPP})

#target_link_libraries(${TARGET_NAME} pam_bbgftp_sl)
