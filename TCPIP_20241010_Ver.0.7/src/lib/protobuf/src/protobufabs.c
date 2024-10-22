#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <protobuf-c/protobuf-c.h>
#include "protobuf.pb-c.h"

#define _DEBUG_LOG printf("[DEBUG][%s][%d]\n", __func__, __LINE__);


// 바이너리 데이터를 설정하는 함수 (C 인터페이스)
/* extern "C" */
void protobuf_filedata_set_content_1(FileData* file_data, const char* data, size_t length) {
    file_data->content_1.data = data;
    file_data->content_1.len = length;
}
/* extern "C" */
void protobuf_filedata_set_content_2(FileData* file_data, const char* data, size_t length) {
    file_data->content_2.data = data;
    file_data->content_2.len = length;
}

/* extern "C" */
void protobuf_savetofile(const char* filename, FileData* file_data) 
{
    size_t size = file_data__get_packed_size(file_data);_DEBUG_LOG
    printf("file_data_size:%d\n", size);
    uint8_t* buffer = malloc(size);_DEBUG_LOG

    file_data__pack(file_data, buffer);_DEBUG_LOG

    FILE* file = fopen(filename, "wb+");_DEBUG_LOG
    if (file != NULL) {
        fwrite(buffer, size, 1, file);_DEBUG_LOG
        fclose(file);_DEBUG_LOG
        printf("Data saved to file: %s\n", filename);_DEBUG_LOG
    } else {
        printf("Failed to open file for writing.\n");_DEBUG_LOG
    }
    free(buffer);  // 메모리 해제
}