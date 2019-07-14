cmake_minimum_required(VERSION 2.8)

set(
	SOURCES
   ${SOURCES}
   ${CMAKE_CURRENT_SOURCE_DIR}/app_crypt.cpp
   PARENT_SCOPE)

set(
   INCLUDES
   ${INCLUDES}
	${CMAKE_CURRENT_SOURCE_DIR}/app_crypt.h
	${CMAKE_CURRENT_SOURCE_DIR}/crypt_util.h
   PARENT_SCOPE)

message("SOURCES => ${SOURCES}")
message("INCLUDES => ${INCLUDES}")
