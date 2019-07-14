cmake_minimum_required(VERSION 2.8)

set(
   CMAKE_CXX_FLAGS
   ${CMAKE_CXX_FLAGS}
   "-Wall -pedantic -std=gnu++11 -pthread"
)

# Locate pthreads, which c++11 relies on for thread impl on Linux
find_package (Threads)

# Locate LibSSH
find_library (LIBSSH
   NAMES
      ssh
      libssh
   PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
)

if(NOT LIBSSH)
   message(FATAL_ERROR "libssh library not found")
endif()

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
include_directories(${PROJECT_SOURCE_DIR}/src/keys)
include_directories(${PROJECT_SOURCE_DIR}/src/tools)

# keymaster unit tests

file(
   COPY
   ${PROJECT_SOURCE_DIR}/test/keys/testkey
   DESTINATION
   ${CMAKE_CURRENT_BINARY_DIR}
)

file(
   COPY
   ${PROJECT_SOURCE_DIR}/test/keys/testkey.pub
   DESTINATION
   ${CMAKE_CURRENT_BINARY_DIR}
)

file(
   COPY
   ${PROJECT_SOURCE_DIR}/test/kmconfig.json
   DESTINATION
   ${CMAKE_CURRENT_BINARY_DIR}
)


set(
   SRCS
   ${PROJECT_SOURCE_DIR}/src/tools/keymaster_config.cpp
   ${PROJECT_SOURCE_DIR}/src/keys/private_key.cpp
   ${PROJECT_SOURCE_DIR}/src/agent/ssh_agent.cpp
   ${PROJECT_SOURCE_DIR}/src/agent/agent_mgr.cpp
   keymaster_config.t.cpp
   private_key.t.cpp
   ssh_agent.t.cpp
   agent_mgr.t.cpp
   keymaster_test_utils.cpp
   keymaster_test_main.cpp
)

set(TARGET_NAME keymaster_test)

add_executable(${TARGET_NAME} ${SRCS})
target_link_libraries(
   ${TARGET_NAME}
   ${CMAKE_THREAD_LIBS_INIT}
   ${LIBSSH}
   ${JSONCPP} sftplogging)


#target_link_libraries(${TARGET_NAME} pam_bbgftp_sl)
