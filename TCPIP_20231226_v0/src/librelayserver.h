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
#include <signal.h>

  /* Epoll */
  #include <poll.h>
  #include <sys/epoll.h>
  /* Timer with timerfd */
  #include <sys/timerfd.h>

/* Util DebugPrintf */
#include <sys/time.h>
#include <stdarg.h>

/* Network */
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <./memory_allocation_include.h>
#include <./memory_allocation_api.h>
#include <./memory_allocation_param.h>

#include <curl/curl.h>

#define HTTP_HOST_PORT "50000"
#define NOT_CODE_FINISH 0

#define PROGRAM_HEADER_SIZE 6
#define PROGRAM_INFO_SIZE 16
#define FIREWARE_HEADER_SIZE 6
#define FIREWARE_INFO_SIZE 16

#define MAX_CLIENT_SIZE 1024
#define MAX_TASK_NUM 128
#define SOCKET_TIMER 5000000 // 1us
#define TASK_TIMER 3000000 // 1us
#define DeviceName "eth0"

#define HEADER_SIZE 20
#define HEADER_PAD "%01X%01X%08X%02X%08X"
#define TCP_RECV_BUFFER_SIZE 1024
#define DEFAULT_UDP_PORT 50000
#define USED_DATA_LIST_SIZE 1024

#define Relay_safefree(ptr) do { free((ptr)); (ptr) = NULL;} while(0)

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
    uint32_t Message_size;
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
    bool used_state;
    uint32_t connected_client_num;
    uint32_t task_num;

    int socket[MAX_CLIENT_SIZE];
    uint32_t socket_message_seq[MAX_CLIENT_SIZE];
    long life_timer[MAX_CLIENT_SIZE];
    pthread_t task_id[MAX_CLIENT_SIZE];
    bool task_running[MAX_CLIENT_SIZE];
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

struct Used_Data_Info_t
{
    pthread_mutex_t mtx;
    enum Data_Type_e type;
    
    uint8_t *Data_Pointer_List[USED_DATA_LIST_SIZE];
    size_t Data_Size_List[USED_DATA_LIST_SIZE];
    size_t Data_Count;
    #if 0 //To Be Making
        bool Used_Index;
        int Index_List[Queue_Index_Size][1024];
    #endif

};
struct data_div_hdr_send_t
{
    uint32_t STX;
    uint16_t type;
    uint16_t div_len;
    uint32_t total_data_len;
    uint16_t div_num;
    uint32_t ecu_timer_left;
    uint32_t crc32_payload;
    uint16_t ETX;
};
struct data_p_hdr_t{
    uint32_t div_num;
    uint32_t payload_len;
};
extern enum debug_lever_e G_Debug_Level;
extern struct ticktimer_t G_TickTimer;
extern struct clients_info_t G_Clients_Info;
extern struct Used_Data_Info_t *G_Data_Info;
extern int g_break_listen;

int G_epfd;
struct epoll_event G_epoll_events[MAX_CLIENT_SIZE - 16];

#ifdef _DEBUG_MODE
    uint32_t G_Recv_Count, G_Send_Count;
#endif

extern struct socket_info_t F_s_RelayServer_TcpIp_Initial_Server(char *Device_Name, int *Port, int *err);
extern int F_i_RelayServer_TcpIp_Get_Address(char *Device_Name, char Output_IPv4Adrress[40]);
extern int F_i_RelayServer_TcpIp_Task_Run(struct socket_info_t *Socket_Info);

static void* th_RelayServer_TcpIp_Task_Server(void *socket_info);
static int f_i_RelayServer_TcpIp_Bind(int *Server_Socket, struct sockaddr_in Socket_Addr);
static int f_i_RelayServer_TcpIp_Setup_Socket(int *Socket, int Timer, bool Linger);

//General Type Code
extern void F_Signal_Handler(int s_signal);
extern long F_l_Timestamp();
extern void F_Print_Debug(enum debug_lever_e Debug_Level, const char *format, ...);
extern void F_Select_Timer(int time_out);
static int f_i_Hex2Dec(char data);
static struct data_header_info_t f_s_Parser_Data_Header(char *Data, size_t Data_Size);

extern void* Th_i_RelayServer_TickTimer(void *Data);

static void *th_RelayServer_Job_Task(void *Data);
static int f_i_RelayServer_Job_Task(uint8_t *Input_Data);
extern void *Th_RelayServer_Job_Scheduler(void *Data);

static enum job_type_e f_e_RelayServer_Job_Process_Do(struct data_header_info_t *Now_Header, uint8_t **Data);
static int f_s_RelayServer_Job_Process_Initial(struct data_header_info_t *Now_Header, uint8_t *Data);
static int f_i_RelayServer_Job_Process_InfoReport(struct data_header_info_t *Now_Header, uint8_t *Data);
static int f_i_RelayServer_Job_Process_InfoRequest(struct data_header_info_t *Now_Header, uint8_t **Data);
static int f_i_RelayServer_Job_Process_InfoResponse(struct data_header_info_t *Now_Header, uint8_t **Data);
static int f_i_RelayServer_Job_Process_InfoIndication(struct data_header_info_t *Now_Header, uint8_t **Data);
static int f_i_RelayServer_Job_Process_Finish(struct data_header_info_t *Now_Header, uint8_t *Data);

size_t F_i_RelayServer_Data_Push(struct Used_Data_Info_t *Data_Info,  uint8_t *Data, size_t Data_size);
void *F_v_RelayServer_Data_Pop(struct Used_Data_Info_t *Data_Info, size_t *out_size);
bool F_RelayServer_Data_isAvaialbe(struct Used_Data_Info_t *Data_Info);
bool F_RelayServer_Data_isEmpty(struct Used_Data_Info_t *Data_Info);

#define DEFALUT_HTTP_INFO_SIZE 512
#define DEFALUT_HTTP_METHOD "POST"
#define DEFALUT_HTTP_SERVER_FIREWARE_URL "https://self-api.wtest.biz/v1/system/verCheck.php"
#define DEFALUT_HTTP_SERVER_PROGRAM_URL "https://self-api.wtest.biz/v1/system/verCheck.php"
#define DEFALUT_HTTP_VERSION "1.1"
#define DEFALUT_HTTP_ACCEPT "*/*"
#define DEFALUT_HTTP_CONTENT_TYPE "Application/octet-stream"

#define HTTP_BUFFER_SIZE 10240
#define HTTP_REQUEST_SIZE 528
#define HTTP_RESPHONE_SIZE 10240
#define HTTP_SOCKET_TIMEOUT 1000L //ms


struct http_socket_info_t{
    int socket;
    uint8_t *request;
    size_t request_len;
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
struct HTTP_Recv_task_info_t
{
    int *state;
    uint32_t *ecu_left_time;

    int sock;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;
};
extern uint8_t *G_HTTP_Request_Info_Program;
extern uint8_t *G_HTTP_Request_Info_Fireware;

extern int F_i_RelayServer_HTTP_Initial(uint8_t *G_HTTP_Request_Info, struct http_info_t *http_info);
size_t f_i_RelayServer_HTTP_Payload(uint8_t *G_HTTP_Request_Info, uint8_t *Body, size_t Body_Size, uint8_t *Http_Request);
static void f_v_RelayServer_HTTP_Message_Parser(char *data_ptr, char *compare_word, void **ret, size_t *ret_len);

int f_i_RelayServer_HTTP_Task_Run(struct data_header_info_t *Now_Header, struct http_socket_info_t *curl_info, uint8_t **out_data);
int f_i_RelayServer_HTTP_WaitOnSocket(int sockfd, int for_recv, long timeout_ms);
static void *f_th_RelayServer_HTTP_Recv_Task(void *d);
