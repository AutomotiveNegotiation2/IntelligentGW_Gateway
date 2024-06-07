#include <librelayserver.h>

enum debug_lever_e G_Debug_Level;
struct ticktimer_t G_TickTimer;
struct clients_info_t G_Clients_Info;

struct Memory_Used_Info_t G_Memory_Used_Info;
struct Memory_Used_Data_Info_t G_Data_Info;

uint8_t *G_HTTP_Request_Info_Program;
uint8_t *G_HTTP_Request_Info_Fireware;

int main()
{
    int ret_err;
    G_Clients_Info.connected_client_num = malloc(sizeof(int));
    G_Memory_Used_Info = F_s_Memory_Initial(1024 * 10);
    G_Data_Info = F_s_Memory_Data_Distributtion(G_Memory_Used_Info, 1024 * 7, &ret_err);
    G_Data_Info.type = OCTET_STRING;

    pthread_create(&(G_TickTimer.Th_TickTimer), NULL, Th_i_RelayServer_TickTimer, NULL);
    pthread_detach(G_TickTimer.Th_TickTimer);

    struct http_info_t http_info;
    http_info.Request_Line.Method = "POST";
    http_info.Request_Line.To = DEFALUT_HTTP_SERVER_PROGRAM_URL;
    http_info.Request_Line.What = "HTTP";
    http_info.Request_Line.Version = "1.0";
    http_info.HOST = "192.168.0.250/";
    http_info.PORT = "80";
    http_info.ACCEPT = "*/*";
    http_info.CONTENT_TYPE = "Application/octet-stream";

    G_HTTP_Request_Info_Program = malloc(sizeof(uint8_t) * DEFALUT_HTTP_INFO_SIZE);
    G_HTTP_Request_Info_Fireware = malloc(sizeof(uint8_t) * DEFALUT_HTTP_INFO_SIZE);

    F_i_RelayServer_HTTP_Initial(G_HTTP_Request_Info_Program, &http_info);
    http_info.Request_Line.To = DEFALUT_HTTP_SERVER_PROGRAM_URL;
    F_i_RelayServer_HTTP_Initial(G_HTTP_Request_Info_Fireware, &http_info);

    int port = 8800;
    struct socket_info_t Server_Info = F_s_RelayServer_TcpIp_Initial_Server(NULL, &port, &ret_err);
    printf("%s, %d\n", __func__, Server_Info.Socket);
    F_i_RelayServer_TcpIp_Task_Run(&Server_Info);

    pthread_t Task_ID_Job;
    pthread_create(&Task_ID_Job, NULL, Th_RelayServer_Job_Task, (void*)&G_Data_Info);
    pthread_detach(Task_ID_Job);
struct timespec tv;
    while(1)
    {
         //clock_gettime(CLOCK_MONOTONIC, &tv); 
          //printf("DEBUG - %d.%d - %d\n", tv.tv_sec, (int)(tv.tv_nsec/1e6), G_TickTimer.G_100ms_Tick);
        sleep(1);
    }


    return 0;
}
