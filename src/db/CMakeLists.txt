cmake_minimum_required(VERSION 3.1)

message("DB CMAKE_CXX_FLAGS => ${CMAKE_CXX_FLAGS}")

set(
	SOURCES
   ${SOURCES}
   ${CMAKE_CURRENT_SOURCE_DIR}/app_db.cpp
   PARENT_SCOPE)

set(
   INCLUDES
   ${INCLUDES}
	${CMAKE_CURRENT_SOURCE_DIR}/app_db.h
   PARENT_SCOPE)

message("SOURCES => ${SOURCES}")
message("INCLUDES => ${INCLUDES}")
