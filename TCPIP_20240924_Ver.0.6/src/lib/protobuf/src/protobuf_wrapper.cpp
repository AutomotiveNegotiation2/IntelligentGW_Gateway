#include "protobuf.pb.h"
#include "protobuf_wrapper.h"
#include <string.h>
#include <iostream>

extern "C" FileData* protobuf_create() {
    return new FileData();
}

// 바이너리 데이터를 설정하는 함수 (C 인터페이스)
extern "C" void filedata_set_content_1(FileData* file_data, const char* data, size_t length) {
    file_data->set_content_1(data, length);
}

extern "C" void filedata_set_content_2(FileData* file_data, const char* data, size_t length) {
    file_data->set_content_2(data, length);
}

extern "C" void filedata_set_content_3(FileData* file_data, const char* data, size_t length) {
    file_data->set_content_3(data, length);
}

extern "C" void filedata_set_content_4(FileData* file_data, const char* data, size_t length) {
    file_data->set_content_4(data, length);
}

extern "C" void filedata_set_content_5(FileData* file_data, const char* data, size_t length) {
    file_data->set_content_5(data, length);
}
