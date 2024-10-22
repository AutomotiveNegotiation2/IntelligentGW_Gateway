/* Base Include */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>

  /* Epoll */
  #include <poll.h>
  #include <sys/epoll.h>
  /* Timer with timerfd */
  #include <sys/timerfd.h>

/* Util DebugPrintf */
#include <sys/time.h>
#include <stdarg.h>

/* Util IPV4_Task */
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <./memory_allocation_include.h>
#include <./memory_allocation_api.h>
#include <./memory_allocation_param.h>

#include <./parson.h>

#include <curl/curl.h>

#define NOT_CODE_FINISH 0

#define MAX_CLIENT_SIZE 128
#define SOCKET_TIMER 50 // 100ms
#define DeviceName "eth0"

#define HEADER_SIZE 16
#define HEADER_PAD "%01X%01X%08X%02X%04X"
#define TCP_RECV_BUFFER_SIZE 1024

enum debug_lever_e{
    ERROR,
    LEVEL_1,
    LEVEL_2,
};

// Job Source Code
enum payload_type_e{
    Fireware,
    Program,
};

struct client_data_info_t 
{
    uint8_t ID[8];
    uint8_t Division[1];
    uint8_t Version[8];
    enum payload_type_e Payload_Type;
    //size_t Payload_Size;
};

struct data_header_info_t
{
    uint8_t Job_State;
    uint8_t Protocol_Type;
    uint32_t Client_fd;
    uint16_t Message_seq;
    uint16_t Message_size;
};

enum job_type_e{
    Initial,
    Finish,

    FirmwareInfoReport,
    FirmwareInfoRequest,
    FirmwareInfoResponse,
    FirmwareInfoIndication,
    FirmwareInfoResponseIndication,

    ProgramInfoReport,
    ProgramInfoRequest,
    ProgramInfoResponse,
    ProgramInfoIndication,
    ProgramInfoResponseIndication,

    HandOverReminingData
};

enum socket_type_e{
    SERVER_SOCKET,
    CLIENT_SOCKET,
    HTTP,
};

struct socket_info_t
{
    //Sokket_Info
    enum socket_type_e Socket_Type;
    int Socket;
    char *Device_Name;
    char Device_IPv4_Address[40];
    int Port;
    struct sockaddr_in Socket_Addr;

    pthread_t Task_ID;
};

struct clients_info_t
{
    pthread_mutex_t mtx;
    int *connected_client_num;
    struct in_addr socket[MAX_CLIENT_SIZE];
    uint32_t socket_message_seq[MAX_CLIENT_SIZE];
    uint32_t Life_Timer[MAX_CLIENT_SIZE];
    enum job_type_e socket_job_state[MAX_CLIENT_SIZE];
    struct client_data_info_t client_data_info[MAX_CLIENT_SIZE];
};

struct ticktimer_t
{
    uint32_t G_10ms_Tick;
    uint32_t G_100ms_Tick;
    uint32_t G_1000ms_Tick;
    pthread_t Th_TickTimer;
};

extern enum debug_lever_e G_Debug_Level;
extern struct ticktimer_t G_TickTimer;
extern struct clients_info_t G_Clients_Info;
extern struct Memory_Used_Data_Info_t G_Data_Info;


extern struct socket_info_t F_s_RelayServer_TcpIp_Initial_Server(char *Device_Name, int *Port, int *err);
extern int F_i_RelayServer_TcpIp_Get_Address(char *Device_Name, char Output_IPv4Adrress[40]);
extern int F_i_RelayServer_TcpIp_Task_Run(struct socket_info_t *Socket_Info);

static void* th_RelayServer_TcpIp_Task_Server(void *socket_info);
static int f_i_RelayServer_TcpIp_Bind(int *Server_Socket, struct sockaddr_in Socket_Addr);
static int f_i_RelayServer_TcpIp_Setup_Socket(int *Socket, int Timer, bool Linger);

//General Type Code
static int f_i_Hex2Dec(char data);
static struct data_header_info_t f_s_Parser_Data_Header(char *Data, size_t Data_Size);

extern void F_RelayServer_Print_Debug(enum debug_lever_e Debug_Level, const char *format, ...);
extern void* Th_i_RelayServer_TickTimer(void *Data);

extern void *Th_RelayServer_Job_Task(void *Data);

enum job_type_e f_e_RelayServer_Job_Process_Do(struct data_header_info_t *Now_Hader, uint8_t **Data, int Client_is, struct Memory_Used_Data_Info_t *Data_Info);
static struct client_data_info_t f_s_RelayServer_Job_Process_Initial(struct data_header_info_t *Now_Hader, uint8_t *Data, int *err);
static int f_i_RelayServer_Job_Process_InfoReport(struct data_header_info_t *Now_Hader, uint8_t *Data);
static int f_i_RelayServer_Job_Process_InfoRequest(struct data_header_info_t *Now_Hader, uint8_t **Data, struct Memory_Used_Data_Info_t *Data_Info);
static int f_i_RelayServer_Job_Process_InfoResponse(struct data_header_info_t *Now_Hader, uint8_t **Data);
static int f_i_RelayServer_Job_Process_InfoIndication(struct data_header_info_t *Now_Hader, uint8_t **Data);
static int f_i_RelayServer_Job_Process_Finish(struct data_header_info_t *Now_Hader, uint8_t *Data, int Client_is);
static int wait_on_socket(curl_socket_t sockfd, int for_recv, long timeout_ms);

#define DEFAULT_HTTP_INFO_SIZE 512
#define DEFAULT_HTTP_METHOD "POST"
#define DEFAULT_HTTP_SERVER_FIREWARE_URL  "http://192.168.0.2/download/program/"
#define DEFAULT_HTTP_SERVER_PROGRAM_URL  "http://192.168.0.2/download/program/"
#define DEFAULT_HTTP_VERSION "1.1"
#define DEFAULT_HTTP_ACCEPT "*/*"
#define DEFAULT_HTTP_CONTENT_TYPE "Application/octet-stream"

#define HTTP_BUFFER_SIZE 10240
#define HTTP_SOCKET_TIMEOUT 1000L //ms
#define MAX_UDP_RECV_DATA 2048

struct curl_info_t{
    CURL *curl;
    curl_socket_t socket;
    uint8_t *request;
    size_t request_len;

    struct data_header_info_t *Now_Hader; 
    struct Memory_Used_Data_Info_t *Data_Info;

    pthread_t Task_ID;
    int Timer;
};

struct http_request_line{
    char *Method;
    char *To;
    char *What;
    char *Version;
};
struct http_info_t
{
    struct http_request_line Request_Line;
    char *HOST;
    char *PORT;
    char *ACCEPT;
    char *CONTENT_TYPE;
};

extern uint8_t *G_HTTP_Request_Info_Program;
extern uint8_t *G_HTTP_Request_Info_Fireware;

extern int F_i_RelayServer_HTTP_Initial(uint8_t *G_HTTP_Request_Info, struct http_info_t *http_info);
size_t f_i_RelayServer_HTTP_Payload(uint8_t *G_HTTP_Request_Info, uint8_t *Body, size_t Body_Size, uint8_t **Http_Request);

int f_i_RelayServer_HTTP_Task_Run(struct data_header_info_t *Now_Header, struct http_socket_info_t *curl_info, uint8_t **out_data);
void *th_RelayServer_HTTP_Task_Receive(void *data);
int f_i_RelayServer_HTTP_WaitOnSocket(curl_socket_t sockfd, int for_recv, long timeout_ms);

enum NUVO_signal_state_e
{
    NUVO_SIGNAL_STATE_CONUNT = 0x00,
    NUVO_SIGNAL_STATE_REQ_CONNECT = 0xF1,
    NUVO_SIGNAL_STATE_RES_CONNECT,
    NUVO_SIGNAL_STATE_REQ_SAVEDATA,
    NUVO_SIGNAL_STATE_RES_SAVEDATA,
    NUVO_SIGNAL_STATE_DONE_SAVEDATA,
    NUVO_SIGNAL_STATE_DOWNLOAD_PREPARE = 0xFD,
    NUVO_SIGNAL_STATE_DOWNOAD_DONE
};

#define DEFAULT_NUVO_ADDRESS "192.168.137.1"
#define DEFAULT_NUVO_PORT "50000"

enum NUVO_connection_state{
    GW_SLEEP_CONNECTIONING_NUVO = 0,
	
    GW_TRYING_CONNECTION_NUVO = 10,
    GW_TRYING_CONNECTION_NUVO_REPEAT_1,
    GW_TRYING_CONNECTION_NUVO_REPEAT_2,
    GW_TRYING_CONNECTION_NUVO_REPEAT_3,
    GW_TRYING_CONNECTION_NUVO_REPEAT_4,
    GW_TRYING_CONNECTION_NUVO_REPEAT_5,
    GW_TRYING_CONNECTION_NUVO_REPEAT_MAX,
    
    GW_WATING_REPLY_CONNECTION_FROM_NUVO = 20,

    GW_REQUEST_SAVE_DRIVING_HISTORY_TO_NUVO = 30,
    GW_WATING_REPLY_SAVE_DRIVING_HISTORY_FROM_NUVO,
    GW_WAIT_DONE_SAVE_DRIVING_HISTORY_FROM_ECU, 
    GW_REQUEST_DONE_SAVE_DRIVING_HISTORY_TO_NUVO,

    GW_WAIT_DRIVING_HISTORY_INFO_FROM_NOVO = 40,
    GW_RECEIVE_DRIVING_HISTORY_DATA_FROM_NOVO,
};

struct NUVO_recv_task_info_t
{
    int *task_info_state;
    int sock;
    struct sockaddr_in serv_adr;
    socklen_t server_addr_len;
    enum NUVO_connection_state state;
    char ACK[4];
    int life_time;
};

extern void *Th_RelayServer_NUVO_Client_Task(void *d);