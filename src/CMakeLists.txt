cmake_minimum_required(VERSION 3.1)

set(
   CMAKE_CXX_FLAGS
   ${CMAKE_CXX_FLAGS}
   "-Wall -pedantic -std=gnu++14 -pthread"
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

set(OPENSSL "OpenSSL::Crypto") 
find_package(OpenSSL REQUIRED)

message(${PROJECT_SOURCE_DIR})

include_directories(${PROJECT_SOURCE_DIR}/src/agent)
include_directories(${PROJECT_SOURCE_DIR}/src/keys)
include_directories(${PROJECT_SOURCE_DIR}/src/tools)

set(SOURCES)
set(INCLUDES)

set(
	SOURCES
   ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
)

add_subdirectory(./agent)
add_subdirectory(./keys)
add_subdirectory(./tools)

message("libssh => ${LIBSSH}")
message("SOURCES => ${SOURCES}")
message("INCLUDES => ${INCLUDES}")

set(EXENAME ${PROJECT_NAME})

add_executable(${EXENAME} ${SOURCES} ${INCLUDES})
target_link_libraries(
   ${EXENAME}
   ${CMAKE_THREAD_LIBS_INIT}
   ${LIBSSH}
   ${JSONCPP}
   ${OPENSSL} 
   )

#file(
#   COPY
#   ${PROJECT_SOURCE_DIR}/src/kmconfig.json
#   DESTINATION
#   ${CMAKE_CURRENT_BINARY_DIR}
#)


### install ###
#install(TARGETS ${LIBNAME_S} ${LIBNAME} DESTINATION dist)
#install(DIRECTORY "${CMAKE_SOURCE_DIR}/" DESTINATION dist/includes FILES_MATCHING PATTERN "*.h")
