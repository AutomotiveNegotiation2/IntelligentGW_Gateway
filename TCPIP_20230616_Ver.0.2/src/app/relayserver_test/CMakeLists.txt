SET(TARGET_APP relay_test_app)
SET(TARGET_ROOT ${CMAKE_CURRENT_LIST_DIR})

add_executable(${TARGET_APP})

target_compile_options(${TARGET_APP} PRIVATE -Wall -Werror)
target_include_directories(${TARGET_APP} PRIVATE ${PROJECT_ROOT}/src/lib/include/)

target_link_libraries(${TARGET_APP} PRIVATE pthread curl memory_allocation relayserver)

target_sources(${TARGET_APP} PRIVATE
                src/relay_test_app.c
               )


set(OUTPUT_DIR ${PROJECT_ROOT}/output/bin/)
add_custom_command(TARGET ${TARGET_APP} PRE_BUILD COMMAND ${CMAKE_COMMAND} -E remove ${OUTPUT_DIR}/${TARGET_APP})
add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_APP} ${OUTPUT_DIR}/${TARGET_APP})
               
set(OUTPUT_INCLUDE_DIR ${PROJECT_ROOT}/output/include/)
set(TARGET_HEADER relay_test_app*.*)
add_custom_command(TARGET ${TARGET_APP} PRE_BUILD COMMAND ${CMAKE_COMMAND} -E remove ${PROJECT_ROOT}/src/lib/include/${TARGET_HEADER})
add_custom_command(TARGET ${TARGET_APP} PRE_BUILD COMMAND ${CMAKE_COMMAND} -E remove ${OUTPUT_INCLUDE_DIR}/${TARGET_HEADER})
add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_ROOT}/src/${TARGET_HEADER} ${PROJECT_ROOT}/src/lib/include/)
add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_ROOT}/src/${TARGET_HEADER} ${OUTPUT_INCLUDE_DIR}/)
                  