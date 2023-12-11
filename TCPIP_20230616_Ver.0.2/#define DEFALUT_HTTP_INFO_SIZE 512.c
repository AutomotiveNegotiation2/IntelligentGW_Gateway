#define DEFALUT_HTTP_INFO_SIZE 512
#define DEFALUT_HTTP_METHOD "POST"
#define DEFALUT_HTTP_SERVER_URL "http://192.168.0.250/download/program/"
#define DEFALUT_HTTP_VERSION "1.1"
#define DEFALUT_HTTP_ACCEPT "*/*"
#define DEFALUT_HTTP_CONTENT_TYPE "Application/octet-stream"

#define HTTP_BUFFER_SIZE 10240
#define HTTP_SOCKET_TIMEOUT 1000L //ms


struct http_request_line{
    char *Method;
    char *To;
    char *What;
    char *Version;
};
struct http_info_t
{
    struct http_request_line Request_Line
    char *HOST;
    char *PORT;
    char *ACCEPT;
    char *CONTENT_TYPE;
};

int f_i_RelayServer_HTTP_Initial(uint8_t *G_HTTP_Request_Info, struct http_info_t *http_info);
size_t f_i_RelayServer_HTTP_Payload(uint8_t *Body, size_t Body_Size, uint8_t *Http_Request);

int f_i_RelayServer_HTTP_Task_Run();

void *th_RelayServer_HTTP_Task_Receive(void *data);

uint8_t *G_HTTP_Request_Info_Program;
uint8_t *G_HTTP_Request_Info_Fireware;

int f_i_RelayServer_HTTP_Initial(uint8_t *G_HTTP_Request_Info, struct http_info_t *http_info)
{
    G_HTTP_Request_Info = malloc(sizeof(uint8_t) * DEFALUT_HTTP_INFO_SIZE)
    uint8_t *request = G_HTTP_Request_Info;
    int request_len;
    if(http_info)
    {
        sprintf(request, "%s %s %s/%s\r\n", http_info->Request_Line.Method, http_info->Request_Line.To, http_info->Request_Line.What, http_info->Request_Line.Version);
        if(HOST){
            sprintf(request, "%s%s: %s:%s\r\n", request , "Host", http_info->HOST, http_info->PORT);
        }else{
            sprintf(request, "%s%s: %s:%s\r\n", request , "Host", DEFALUT_HTTP_SERVER_URL, "80");
        }
        if(ACCEPT){
            sprintf(request, "%s%s: %s\r\n", request , "Accept", http_info->ACCEPT);
        }else{
            sprintf(request, "%s%s: %s\r\n", request , "Accept", DEFALUT_HTTP_ACCEPT);
        }
        if(CONTENT_TYPE){
            sprintf(request, "%s%s: %s\r\n", request , "Content-Type", http_info->CONTENT_TYPE);
        }else{
            sprintf(request, "%s%s: %s\r\n", request , "Content-Type", DEFALUT_HTTP_CONTENT_TYPE);
        }

    }else
    {
        sprintf(request, "%s %s %s/%s\r\n", DEFALUT_HTTP_METHOD, DEFALUT_HTTP_SERVER_URL, "HTTP", DEFALUT_HTTP_VERSION);
        sprintf(request, "%s%s: %s\r\n", request , "Host", DEFALUT_HTTP_HOST);
        sprintf(request, "%s%s: %s\r\n", request , "Accept", DEFALUT_HTTP_ACCEPT);
        sprintf(request, "%s%s: %s\r\n", request , "Content-Type", DEFALUT_HTTP_CONTENT_TYPE);
    }
    sprintf(request, "%s\r\n", request);
}

size_t f_i_RelayServer_HTTP_Payload(uint8_t *G_HTTP_Request_Info, uint8_t *Body, size_t Body_Size, uint8_t *Http_Request)
{
    if(G_HTTP_Request_Info){
        uint8_t *request = G_HTTP_Request_Info;
    }else{
        return -1;
    }
    if(Body)
    {
        if(Body_Size > 0)
        {
            sprintf(request, "%s%s: %d\r\n", request , "Content-Length", Body_Size);
        }
        sprintf(request, "%s\r\n", request);
        size_t request_len = strlen(request) + Body_Size;
        memcpy(request + strlen(request), Body, Body_Size);
        Http_Request = malloc(sizeof(uint8_t) * request_len);
    }else {
        return -1;
    }
    return request_len;
}

struct curl_info_t{
    CURL *curl;
    curl_socket_t socket;
    uint8_t *request;
    size_t request_len;

    struct data_header_info_t *Now_Hader; 
    struct Memory_Used_Data_Info_t *Data_Info;

    pthread_t Task_ID;
    int Timer;
}

int f_i_RelayServer_HTTP_Task_Run(struct curl_info_t *curl_info)
{

    
    curl_info->curl = curl_easy_init();
    CURLcode res;
    
    curl_easy_setopt(curl_info->curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl_info->curl, CURLOPT_CONNECT_ONLY, 1L);
    res = curl_easy_perform(curl_info->curl);
    if(res != CURLE_OK) {
        F_RealyServer_Print_Debug(0, "[Error][%s]: %s\n", __func__, curl_easy_strerror(res));
        return -1;
    }

    res = curl_easy_getinfo(curl_info->curl, CURLINFO_ACTIVESOCKET, &curl_info->socket);
    if(res != CURLE_OK) {
        F_RealyServer_Print_Debug(0, "[Error][%s]: %s\n", __func__, curl_easy_strerror(res));
        return -1;
    }

    size_t nsent_total = 0;
    do 
    {
        size_t nsent;
        do {
            nsent = 0;
            res = curl_easy_send(curl_info->curl, Http_Request + nsent_total, Http_Request_Size - nsent_total, &nsent);
            nsent_total += nsent;

            if(res == CURLE_AGAIN && !wait_on_socket(curl_info->socket, 0, HTTP_SOCKET_TIMEOUT)) 
            {
                F_RealyServer_Print_Debug(0, "[Error][%s]: timeout.\n", __func__);
                return -1;
            }
        } while(res == CURLE_AGAIN);

        if(res != CURLE_OK) 
        {
            F_RealyServer_Print_Debug(0, "[Error][%s]: %s\n", __func__, curl_easy_strerror(res));
            return -1;
        }
    } while(nsent_total < Http_Request_Size);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    curl_info->Timer = 1000; //ms
    pthread_create(&curl_info->Task_ID, &attr, th_RelayServer_HTTP_Task_Receive, (void*)curl_info);
    //pthread_datech(curl_info->Task_ID);

    return 0;
}

void *th_RelayServer_HTTP_Task_Receive(void *data)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    struct curl_info_t *curl_info = (struct curl_info_t*)data;
    uint32_t Timer_Init = G_TickTimer.G_10ms_Tick;
    CURLcode res;
    size_t buf_len = 0;
    for(;;) 
    {
        if(Timer_Init + curl_info->Timer/10  < G_TickTimer.G_10ms_Tick)
        {
            pthread_cancle(curl_info->Task_ID);
        }

        char buf[HTTP_BUFFER_SIZE];
        size_t nread;
        
        do {
            nread = 0;
            res = curl_easy_recv(curl_info->curl, buf, sizeof(buf), &nread);
            buf_len += nread;
            if(res == CURLE_AGAIN && !wait_on_socket(curl_info->socket, 1, HTTP_SOCKET_TIMEOUT)) 
            {
                F_RealyServer_Print_Debug(0, "[Error][%s]: timeout.\n", __func__);
                return 1;
            }
        } while(res == CURLE_AGAIN);

        if(res != CURLE_OK) 
        {
            buf_len = 0;
            F_RealyServer_Print_Debug(0, "[Error][%s]: %s\n", __func__, curl_easy_strerror(res));
            break;
           
        }
    
        if(nread == 0) {
            break;
        }
    }

    if(buf_len > 0)
    {
        uint8_t *Http_Recv_data = malloc(sizeof(uint8_t) * (buf_len + HEADER_SIZE));
        struct data_header_info_t *Now_Hader = curl_info->Now_Hader;
        switch(Now_Hader->Job_State)
        {
            case FirmwareInfoRequest:
                Now_Hader->Job_State = 4;
                sprintf(Http_Recv_data, "%01X%01X%02X%02X%02X", 0x4, 0x1, Now_Hader->Client_fd, Now_Hader->Message_seq, buf_len);
                break;
            case ProgramInfoRequest:
                Now_Hader->Job_State = 9;
                sprintf(Http_Recv_data, "%01X%01X%02X%02X%02X", 0x9, 0x1, Now_Hader->Client_fd, Now_Hader->Message_seq, buf_len);
                break;
            default:
                F_RealyServer_Print_Debug(0, "[Error][%s][Job_State:%d]\n", __func__, Now_Hader->Job_State);
                return -1;
        }   
        memcpy(Http_Recv_data + HEADER_SIZE, buf, buf_len);
        F_i_Memory_Data_Push(curl_info->Data_Info, data, (buf_len + HEADER_SIZE));
        F_RealyServer_Print_Debug(4,"[%s][Free:10, Address:%p]\n", __func__, *Http_Recv_data);
        free(Http_Recv_data);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
    return NULL;
}
