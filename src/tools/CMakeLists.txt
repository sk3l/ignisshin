cmake_minimum_required(VERSION 2.8)

set(
   CMAKE_CXX_FLAGS 
   ${CMAKE_CXX_FLAGS} 
   "-Wall -pedantic -std=gnu++11 -pthread"
)

set(
   INCLUDES
   ${INCLUDES}
   ${CMAKE_CURRENT_SOURCE_DIR}/app_config.h
   PARENT_SCOPE
)

set(
	SOURCES
   ${SOURCES}
   ${CMAKE_CURRENT_SOURCE_DIR}/app_config.cpp
   PARENT_SCOPE
)

message("libssh => ${LIBSSH}")
message("SOURCES => ${SOURCES}")
message("INCLUDES => ${INCLUDES}")

### install ###
#install(TARGETS ${LIBNAME_S} ${LIBNAME} DESTINATION dist)
#install(DIRECTORY "${CMAKE_SOURCE_DIR}/" DESTINATION dist/includes FILES_MATCHING PATTERN "*.h")
