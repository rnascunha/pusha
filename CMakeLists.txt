cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
project(pusha)

#find_package(OpenSSL 1.1.0 REQUIRED)

add_subdirectory(third/ecec)

set(SRC_DIR	src)
set(SRCS	${SRC_DIR}/vapid.c
			${SRC_DIR}/web_push.c
			${SRC_DIR}/ec_keys.c
			${SRC_DIR}/http.c
			${SRC_DIR}/debug.c
			${SRC_DIR}/helper.c
			${SRC_DIR}/pusha.c
			)

add_library(${PROJECT_NAME} ${SRCS})
target_include_directories(${PROJECT_NAME}
  PUBLIC third/ecec/include
  PUBLIC include
)

target_link_libraries(${PROJECT_NAME} PUBLIC ece)
#
# TOOLS
#
if(DEFINED WITH_TOOLS)
	if(${WITH_TOOLS} EQUAL 1)
		set(TOOLS_DIR	tools)
		add_executable(genkey ${TOOLS_DIR}/genkey.c)
		target_link_libraries(genkey PUBLIC ${PROJECT_NAME})
		
		add_executable(push ${TOOLS_DIR}/push.c)
		target_link_libraries(push PUBLIC ${PROJECT_NAME})
	endif()
endif()

#
#EXAMPLES
#
if(DEFINED WITH_EXAMPLES)
	if(${WITH_EXAMPLES} EQUAL 1)
		set(EXAMPLES_DIR examples)
		
		add_executable(web_push_example ${EXAMPLES_DIR}/web_push.c)
		target_link_libraries(web_push_example PUBLIC ${PROJECT_NAME})
		
		add_executable(web_push_http_example ${EXAMPLES_DIR}/web_push_http.c)
		target_link_libraries(web_push_http_example PUBLIC ${PROJECT_NAME})
	endif()
endif()