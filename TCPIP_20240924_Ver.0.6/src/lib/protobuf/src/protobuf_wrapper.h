#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

// FileData 구조체를 C++의 FileData 객체로 사용
typedef struct FileData FileData;

// 함수 프로토타입 정의
FileData* filedata_create();

void filedata_set_content_1(FileData* file_data, const char* data, size_t length);
void filedata_set_content_2(FileData* file_data, const char* data, size_t length);
void filedata_set_content_3(FileData* file_data, const char* data, size_t length);
void filedata_set_content_4(FileData* file_data, const char* data, size_t length);
void filedata_set_content_5(FileData* file_data, const char* data, size_t length);

#ifdef __cplusplus
}
#endif