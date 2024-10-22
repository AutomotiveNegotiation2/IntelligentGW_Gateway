
# Protobuf 패키지 찾기
find_package(Protobuf REQUIRED)

SET(TARGET_LIB protobufabs)
SET(TARGET_ROOT ${CMAKE_CURRENT_LIST_DIR})
MESSAGE("TARGET_ROOT")
MESSAGE(${TARGET_ROOT})
# proto 파일의 경로
set(PROTO_FILE ${TARGET_ROOT}/src/protobuf.proto)
MESSAGE("PROTO_FILE")
MESSAGE(${PROTO_FILE})
# proto 파일을 컴파일해서 C++ 파일 생성
set(GENERATED_PROTO_DIR ${TARGET_ROOT})
MESSAGE("GENERATED_PROTO_DIR")
MESSAGE(${GENERATED_PROTO_DIR})

add_custom_command(
    OUTPUT ./protobuf.pb.cc ./protobuf.pb.h
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
    ARGS --cpp_out=${PROJECT_ROOT} -I ${CMAKE_SOURCE_DIR} ${PROTO_FILE}
    DEPENDS ${PROTO_FILE}
    COMMENT "Running protoc on ${PROTO_FILE}"
)

# 생성된 파일을 소스로 추가
include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT})
include_directories(${TARGET_LIB} PRIVATE ${TARGET_ROOT}/src)

add_library(${TARGET_LIB} SHARED 
                                src/protobuf.pb.cc
                                src/protobuf_wrapper.cpp
)


set(OUTPUT_DIR ${PROJECT_ROOT}/output/lib)
add_custom_command(TARGET ${TARGET_LIB} PRE_BUILD COMMAND ${CMAKE_COMMAND} -E remove ${OUTPUT_DIR}/lib${TARGET_LIB}.*)
add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy lib${TARGET_LIB}.* ${OUTPUT_DIR}/ )

set(OUTPUT_INCLUDE_DIR ${PROJECT_ROOT}/output/include/)
set(TARGET_HEADER *.h)
add_custom_command(TARGET ${TARGET_LIB} PRE_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_ROOT}/src/${TARGET_HEADER} ${PROJECT_ROOT}/src/lib/include/)
add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_ROOT}/src/${TARGET_HEADER} ${OUTPUT_INCLUDE_DIR}/)
                  