cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
project(pusha)

#find_package(OpenSSL 1.1.0 REQUIRED)

add_subdirectory(third/ecec)

set(SRC_DIR	src)
set(SRCS	${SRC_DIR}/vapid.c
			${SRC_DIR}/web_push.c)

add_library(${PROJECT_NAME} ${SRCS})
target_include_directories(${PROJECT_NAME}
  PUBLIC third/ecec/include
#  PUBLIC ${OPENSSL_INCLUDE_DIR}
)
#target_link_directories(${PROJECT_NAME} PUBLIC ecec/build)
target_link_libraries(${PROJECT_NAME}
	PUBLIC ece
##  PUBLIC ${OPENSSL_LIBRARIES}
)


#
# EXAMPLES
#
set(EXAMPLES_DIR examples)

add_executable(curl_pusha ${EXAMPLES_DIR}/main.c)
target_link_libraries(curl_pusha PUBLIC ${PROJECT_NAME})
target_include_directories(curl_pusha PUBLIC ${SRC_DIR})