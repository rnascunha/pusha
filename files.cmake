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