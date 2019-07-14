cmake_minimum_required(VERSION 2.8)

set(
	SOURCES
   ${SOURCES}
   ${CMAKE_CURRENT_SOURCE_DIR}/private_key.cpp
   PARENT_SCOPE)

set(
   INCLUDES
   ${INCLUDES}
	${CMAKE_CURRENT_SOURCE_DIR}/private_key.h
   PARENT_SCOPE)

message("SOURCES => ${SOURCES}")
message("INCLUDES => ${INCLUDES}")
