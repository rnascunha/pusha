cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
project(pusha)

#find_package(OpenSSL 1.1.0 REQUIRED)

add_subdirectory(third/ecec)

if(MSVC)
	message(STATUS "MSVC build")
	set(CMAKE_CXX_FLAGS "/W4 /std:c++17 /EHsc")
	set(CMAKE_CXX_FLAGS_RELEASE "/O2")
else()
	message(STATUS "NO MSVC build")
	set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-unused-parameter -std=c++17")	#-fmax-errors=5 
	set(CMAKE_CXX_FLAGS_DEBUG "-g")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3")
endif()

set(SRC_DIR	src)
set(SRCS	${SRC_DIR}/vapid.c
			${SRC_DIR}/web_push.c
			${SRC_DIR}/ec_keys.c
			${SRC_DIR}/http.c
			${SRC_DIR}/debug.c
			${SRC_DIR}/helper.c
			${SRC_DIR}/pusha.c)
			
set(SRC_CPP_DIR	src_cpp)
set(SRCS_CPP	${SRC_CPP_DIR}/error.cpp
				${SRC_CPP_DIR}/ec_keys.cpp
				${SRC_CPP_DIR}/notify.cpp)

add_library(${PROJECT_NAME} ${SRCS} ${SRCS_CPP})
target_include_directories(${PROJECT_NAME}
	PUBLIC third/ecec/include
  	PUBLIC include
	PUBLIC include_cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC ece)
#
# TOOLS
#
if(DEFINED WITH_TOOLS)
	if(${WITH_TOOLS} EQUAL 1)
		set(TOOLS_DIR	tools)
		add_executable(genkey ${TOOLS_DIR}/genkey.c)
		target_link_libraries(genkey PUBLIC ${PROJECT_NAME})
		
		add_executable(${PROJECT_NAME}-bin ${TOOLS_DIR}/pusha.c)
		target_link_libraries(${PROJECT_NAME}-bin PUBLIC ${PROJECT_NAME})
		# Setting name
		set_target_properties(${PROJECT_NAME}-bin
        	PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
        	
        add_executable(export_key ${TOOLS_DIR}/export_key.c)
		target_link_libraries(export_key PUBLIC ${PROJECT_NAME})
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
		
		add_executable(genkey_cpp ${EXAMPLES_DIR}/genkey_cpp.cpp)
		target_link_libraries(genkey_cpp PUBLIC ${PROJECT_NAME})
			
		add_executable(notify_cpp ${EXAMPLES_DIR}/notify_cpp.cpp)
		target_link_libraries(notify_cpp PUBLIC ${PROJECT_NAME})
	endif()
endif()

#add_executable(test examples/test.cpp)
#target_link_libraries(test PUBLIC ${PROJECT_NAME})
