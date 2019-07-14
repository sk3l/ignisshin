cmake_minimum_required(VERSION 3.1)

set(
   CMAKE_CXX_FLAGS
   ${CMAKE_CXX_FLAGS}
   "-Wall -pedantic -std=gnu++14 -pthread"
)

set(OPENSSL "OpenSSL::Crypto") 
find_package(OpenSSL REQUIRED)

message(${PROJECT_SOURCE_DIR})

include_directories(${PROJECT_SOURCE_DIR}/src/crypt)
#include_directories(${PROJECT_SOURCE_DIR}/src/tools)

set(
   SOURCES
   ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
   ${PROJECT_SOURCE_DIR}/src/crypt/app_crypt.cpp
)

set(EXENAME "test_crypto")

add_executable(${EXENAME} ${SOURCES})
target_link_libraries(
   ${EXENAME}
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
