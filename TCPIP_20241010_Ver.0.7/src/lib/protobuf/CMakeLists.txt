
# Protobuf 패키지 찾기
find_package(PkgConfig REQUIRED)
pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c)

SET(TARGET_LIB protobufabs)
SET(TARGET_ROOT ${CMAKE_CURRENT_LIST_DIR})

# proto 파일의 경로
set(PROTO_FILE ${TARGET_ROOT}/src/protobuf.proto)

# proto 파일을 컴파일해서 C++ 파일 생성
set(GENERATED_PROTO_DIR ${TARGET_ROOT})

add_custom_command(
    OUTPUT ./protobuf.pb-c.c ./protobuf.pb-c.h
    COMMAND protoc-c --c_out=${PROJECT_ROOT} -I ${CMAKE_SOURCE_DIR} ${PROTO_FILE}
    DEPENDS ${PROTO_FILE}
    COMMENT "Running protoc-c on ${PROTO_FILE}"
)


# 생성된 파일을 소스로 추가
include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT})
include_directories(${TARGET_LIB} PRIVATE ${TARGET_ROOT}/src)
add_library(${TARGET_LIB} SHARED 
                                src/protobuf.pb-c.c
                                src/protobufabs.c
)
target_link_libraries(${TARGET_LIB} PRIVATE ${PROTOBUF_C_LIBRARIES})

set(OUTPUT_DIR ${PROJECT_ROOT}/output/lib)
add_custom_command(TARGET ${TARGET_LIB} PRE_BUILD COMMAND ${CMAKE_COMMAND} -E remove ${OUTPUT_DIR}/lib${TARGET_LIB}.*)
add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy lib${TARGET_LIB}.* ${OUTPUT_DIR}/ )

set(OUTPUT_INCLUDE_DIR ${PROJECT_ROOT}/output/include/)
set(TARGET_HEADER *.h)
add_custom_command(TARGET ${TARGET_LIB} PRE_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_ROOT}/src/${TARGET_HEADER} ${PROJECT_ROOT}/src/lib/include/)
add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_ROOT}/src/${TARGET_HEADER} ${OUTPUT_INCLUDE_DIR}/)
                  