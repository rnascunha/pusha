cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
project(pusha LANGUAGES C CXX VERSION 0.1)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

option(WITH_TOOLS "compile tools" FALSE)
option(WITH_EXAMPLES "compile examples" FALSE)

add_subdirectory(third/ecec)

if(MSVC)
	set(CMAKE_CXX_FLAGS "/W4 /EHa")
	set(CMAKE_CXX_FLAGS_RELEASE "/O2")
else()
	set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-unused-parameter -pedantic")# -fno-exceptions -fno-rtti")
	set(CMAKE_CXX_FLAGS_DEBUG "-g")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3")
endif()

include(files.cmake)

add_library(${PROJECT_NAME} ${SRCS} ${SRCS_CPP})
add_library(${PRJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_include_directories(${PROJECT_NAME}
	PRIVATE third/ecec/include
  	PUBLIC include
	PUBLIC include_cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC ece)

if(WIN32 OR ${CMAKE_SYSTEM} MATCHES "^MINGW")
	target_link_libraries(${PROJECT_NAME} PUBLIC ws2_32 wsock32)
endif()

#
# TOOLS
#
if(${WITH_TOOLS})
	include(tools/tools.cmake)
endif()

#
#EXAMPLES
#
if(${WITH_EXAMPLES})
	include(examples/examples.cmake)
endif()

########################################
# Installing
########################################
install(TARGETS ${PROJECT_NAME} DESTINATION lib)
install(DIRECTORY "include/"
        		DESTINATION "include")
install(DIRECTORY "include_cpp/"
        		DESTINATION "include")
if(${WITH_TOOLS})
	install(TARGETS genkey pusha export_key 
		DESTINATION bin) 
endif()
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/README.md" 
				"${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
				"${CMAKE_CURRENT_SOURCE_DIR}/URL.txt"
			DESTINATION doc)

#########################################
# Packing // https://cmake.org/cmake/help/latest/module/CPack.html
#########################################
if(NOT WIN32)
	include(InstallRequiredSystemLibraries)
	set(CPACK_PACKAGE_VENDOR		"xeds corp")
	set(CPACK_PACKAGE_DESCRIPTION	"C/C++ Web Push Notification library")
	set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "C/C++ Web Push Notification")
	set(CPACK_RESOURCE_FILE_README 	"${CMAKE_CURRENT_SOURCE_DIR}/README.md")
	set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
	include(CPack)
endif()
