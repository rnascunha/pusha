set(TOOLS_DIR	tools)
set(TOOLS genkey export_key)
set(OUTPUT_TOOL tools)

foreach(tool ${TOOLS})
    add_executable(${tool} ${TOOLS_DIR}/${tool}.c)
    target_link_libraries(${tool} PUBLIC ${PROJECT_NAME})    
    set_target_properties(${tool} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_TOOL}
    ) 
endforeach()

# pusha special care
add_executable(${PROJECT_NAME}-bin ${TOOLS_DIR}/pusha.c)
target_link_libraries(${PROJECT_NAME}-bin PUBLIC ${PROJECT_NAME})
set_target_properties(${PROJECT_NAME}-bin
    PROPERTIES OUTPUT_NAME ${PROJECT_NAME}
    RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_TOOL})