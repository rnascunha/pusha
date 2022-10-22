set(EXAMPLES_DIR examples)
set(EXAMPLES_C web_push_example web_push_http_example)
set(EXAMPLES_CPP genkey_cpp notify_cpp)
set(OUTPUT_EXAMPLE  examples)

foreach(example ${EXAMPLES_C})
    add_executable(${example} ${EXAMPLES_DIR}/${example}.c)
    target_link_libraries(${example} PUBLIC ${PROJECT_NAME})
    set_target_properties(${example} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_EXAMPLE}
    )    
endforeach()

foreach(example ${EXAMPLES_CPP})
    add_executable(${example} ${EXAMPLES_DIR}/${example}.cpp)
    target_link_libraries(${example} PUBLIC ${PROJECT_NAME})
    set_target_properties(${example} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_EXAMPLE}
    )    
endforeach()