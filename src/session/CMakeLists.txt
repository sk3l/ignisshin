cmake_minimum_required(VERSION 2.8)

set(
	SOURCES
   ${SOURCES}
	${CMAKE_CURRENT_SOURCE_DIR}/ssh_agent.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/agent_mgr.cpp
   PARENT_SCOPE)

set(
   INCLUDES
   ${INCLUDES}
	${CMAKE_CURRENT_SOURCE_DIR}/ssh_agent.h
	${CMAKE_CURRENT_SOURCE_DIR}/agent_mgr.h
   PARENT_SCOPE)

message("SOURCES => ${SOURCES}")
message("INCLUDES => ${INCLUDES}")
