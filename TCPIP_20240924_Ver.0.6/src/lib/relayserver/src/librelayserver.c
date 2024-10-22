  /* LIBRARY Source */
#include <./librelayserver.h>

#define _DEBUG_LOG printf("[DEBUG][%s][%d]\n", __func__, __LINE__);
#define _DEBUG_PRESS_TIMER(t) time_t time_end = time(NULL);while(getchar() != '\n'){if(time(NULL) - time_end > t){break;}else{sleep(1);}}printf("\n");
#define _DEBUG_PRESS(x) printf("\n");printf("[%d][Opration_Gateway] " "\033[0;33m" "Press Any Key" "\033[0;0m" " to [%s:%d]\n", __LINE__, __func__, x);printf("\x1B[1A\r"); _DEBUG_PRESS_TIMER(5)

bool *g_curl_isused;
/* 
Brief:
Parameter[In]
Parameter[Out]
    socket_info_t
 */
struct socket_info_t F_s_RelayServer_TcpIp_Initial_Server(char *Device_Name, int *Port, int *err)
{
    int ret = 0;_DEBUG_LOG
    struct socket_info_t Socket_Info;_DEBUG_LOG
    //Check Argurements
    if(!Port)
    {
        F_RelayServer_Print_Debug(2, "[Error][%s] No Input Argurements.(Port:%p)\n", __func__, Port);_DEBUG_LOG
        *err = -1;_DEBUG_LOG
        return Socket_Info;_DEBUG_LOG
    }else{
        Socket_Info.Socket_Type = SERVER_SOCKET;_DEBUG_LOG
        Socket_Info.Port = *Port;_DEBUG_LOG
         //Socket_Setup
        Socket_Info.Socket = socket(PF_INET, SOCK_DGRAM, 0);_DEBUG_LOG
        memset(&Socket_Info.Socket_Addr, 0x00, sizeof(Socket_Info.Socket_Addr)); 
        Socket_Info.Socket_Addr.sin_family = AF_INET;_DEBUG_LOG
        Socket_Info.Socket_Addr.sin_port = htons(Socket_Info.Port);_DEBUG_LOG
        
        if(Device_Name)
        {
            //Getting the Ethernet Device IP Address  
            Socket_Info.Device_Name = Device_Name;_DEBUG_LOG
            ret = F_i_RelayServer_TcpIp_Get_Address(Socket_Info.Device_Name, Socket_Info.Device_IPv4_Address);_DEBUG_LOG
            if(ret < 0)
            {
                F_RelayServer_Print_Debug(2,"[Error][%s] Return_Value:%d\n", __func__, ret);_DEBUG_LOG
                *err = -1;_DEBUG_LOG
                return Socket_Info;_DEBUG_LOG
            }
            Socket_Info.Socket_Addr.sin_addr.s_addr = inet_addr(Socket_Info.Device_IPv4_Address);_DEBUG_LOG
        }else 
        {
            Socket_Info.Device_Name = "INADDR_ANY";_DEBUG_LOG
            Socket_Info.Socket_Addr.sin_addr.s_addr = htonl(INADDR_ANY);_DEBUG_LOG
        }

        ret = f_i_RelayServer_TcpIp_Setup_Socket(&Socket_Info.Socket, 250, true);_DEBUG_LOG
        if(ret < 0)
        {
            F_RelayServer_Print_Debug(2,"[Error][%s] Return_Value:%d\n", __func__, ret);_DEBUG_LOG
            *err = -1;_DEBUG_LOG
            return Socket_Info;_DEBUG_LOG
        }

    }
    g_curl_isused = malloc(sizeof(bool));_DEBUG_LOG
    *g_curl_isused = 0;_DEBUG_LOG
    return Socket_Info;_DEBUG_LOG
}

/* 
Brief:Getting the IPV4 address of inputed the device name.
Parameter[In]
    Device_Name:Device Name
    Output_IPv4Adrress[]:Array that size 40 to store the IPv4 address.
Parameter[Out]
    int < 0 = Error_Code
 */
int F_i_RelayServer_TcpIp_Get_Address(char *Device_Name, char Output_IPv4Adrress[40])
{
    int ret = 0;_DEBUG_LOG

    //Check Argurement
    if(!Device_Name)
    {
        F_RelayServer_Print_Debug(2, "[Error][%s] No Input Argurements.(Device_Name:%p)\n", __func__, Device_Name);_DEBUG_LOG
        return -1;_DEBUG_LOG
    }

    /* Use the Ethernet Device Name to find IP Address at */
	struct ifreq ifr;_DEBUG_LOG
	int IP_Parsing_Socket;_DEBUG_LOG
    
	IP_Parsing_Socket = socket(AF_INET, SOCK_DGRAM, 0);_DEBUG_LOG
	strncpy(ifr.ifr_name, Device_Name, IFNAMSIZ);_DEBUG_LOG

	if (ioctl(IP_Parsing_Socket, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");_DEBUG_LOG
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, Output_IPv4Adrress, sizeof(struct sockaddr));_DEBUG_LOG
		F_RelayServer_Print_Debug(1, "[Info][%s] %s IP Address is %s\n", __func__, Device_Name, Output_IPv4Adrress);_DEBUG_LOG
	}
    ret = f_i_RelayServer_TcpIp_Setup_Socket(&IP_Parsing_Socket, 100, true);_DEBUG_LOG
    if(ret < 0)
    {
        return -1;_DEBUG_LOG
    }
	close(IP_Parsing_Socket);_DEBUG_LOG
    return  0;_DEBUG_LOG
}
/* 
Brief:
Parameter[In]
Parameter[Out]
 */
int F_i_RelayServer_TcpIp_Task_Run(struct socket_info_t *Socket_Info)
{
    int ret;_DEBUG_LOG
    ret = f_i_RelayServer_TcpIp_Bind(&Socket_Info->Socket, Socket_Info->Socket_Addr);_DEBUG_LOG
    if(ret < 0)
    {
            F_RelayServer_Print_Debug(2, "[Error][%s][f_i_RelayServer_TcpIp_Bind] Return Value:%d", __func__, ret);
    }else{
        pthread_create(&(Socket_Info->Task_ID), NULL, th_RelayServer_TcpIp_Task_Server, (void*)Socket_Info);  
        pthread_detach((Socket_Info->Task_ID));_DEBUG_LOG
        F_RelayServer_Print_Debug(1, "[Sucess][%s][Task_ID:%ld]\n", __func__, Socket_Info->Task_ID);

    }
    return 0;_DEBUG_LOG
}
/* 
Brief:
Parameter[In]
Parameter[Out]
 */
void *Th_RelayServer_Job_Task(void *Data)
{
    Data = Data;
    struct Memory_Used_Data_Info_t *Data_Info = (struct Memory_Used_Data_Info_t *)Data;
    int ret;
    // Using_Timer
    int32_t TimerFd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec itval;
    struct timespec tv;
    uint32_t Task_Timer_Max = 100 * 1000;
    uint32_t Task_Timer_min = 10 * 1000;
    uint64_t res;
    
    int mTime = Task_Timer_Max / 1000;
    setsockopt(TimerFd, SOL_SOCKET, SO_RCVTIMEO, (char*)&mTime, sizeof( mTime));

    clock_gettime(CLOCK_MONOTONIC, &tv); 
    itval.it_interval.tv_sec = 0;
    itval.it_interval.tv_nsec = (Task_Timer_Max % 1000000) * 1e3;
    itval.it_value.tv_sec = tv.tv_sec + 1;
    itval.it_value.tv_nsec = 0;
    ret = timerfd_settime (TimerFd, TFD_TIMER_ABSTIME, &itval, NULL);

    uint32_t tick_count_10ms = 0;
    tick_count_10ms = (uint32_t)tick_count_10ms;
    int Task_Timer_now = Task_Timer_Max;
    size_t Before_data_count = (size_t)(*(Data_Info->Data_Count));
    float Timer_Index;
    while(1)
    {   
        ret = read(TimerFd, &res, sizeof(res));
        if(ret < 0)
        {
            
        }else{
            switch((size_t)(*(Data_Info->Data_Count)))
            {
                case 0:
                    Task_Timer_now = Task_Timer_Max;
                    clock_gettime(CLOCK_MONOTONIC, &tv); 
                    itval.it_interval.tv_nsec = (Task_Timer_now % 1000000) * 1e3;
                    itval.it_value.tv_sec = tv.tv_sec + 1;
                    timerfd_settime (TimerFd, TFD_TIMER_ABSTIME, &itval, NULL);
                    Before_data_count = 0;
                    break;
                case MEMORY_USED_DATA_LIST_SIZE:
                    Task_Timer_now = Task_Timer_min;
                    clock_gettime(CLOCK_MONOTONIC, &tv); 
                    itval.it_interval.tv_nsec = (Task_Timer_now % 1000000) * 1e3;
                    itval.it_value.tv_sec = tv.tv_sec + 1;
                    timerfd_settime (TimerFd, TFD_TIMER_ABSTIME, &itval, NULL);
                    break;
                default:
                    if(Before_data_count + 20 < (size_t)(*(Data_Info->Data_Count)))
                    {
                        Before_data_count = (size_t)(*(Data_Info->Data_Count));
                        Timer_Index = ((size_t)*(Data_Info->Data_Count) * 1e4) / (MEMORY_USED_DATA_LIST_SIZE * 1e4);
                        Task_Timer_now = (Task_Timer_Max * 1e4) * (1e4 - Timer_Index);
                        Task_Timer_now = Task_Timer_now / 1e4;
                        if(Task_Timer_now < Task_Timer_min)
                        {
                        Task_Timer_now = Task_Timer_min;
                        }                    
                        clock_gettime(CLOCK_MONOTONIC, &tv); 
                        itval.it_interval.tv_nsec = (Task_Timer_now % 1000000) * 1e3;
                        itval.it_value.tv_sec = tv.tv_sec + 1;
                        timerfd_settime (TimerFd, TFD_TIMER_ABSTIME, &itval, NULL);
                    }
                    break;
                break;
            }
        
            size_t data_size = 0;
            for(int data_is = 0; data_is < (size_t)*(Data_Info->Data_Count); data_is++)
            {
                if(F_Memory_Data_isEmpty(Data_Info))
                {
                }else{
                    uint8_t *out_data = (uint8_t*)F_v_Memory_Data_Pop(Data_Info, &data_size); 
                    //F_RelayServer_Print_Debug(6,"[Debug][%s][%d][Pop_Data:%s/%d][%d]\n", __func__, __LINE__, out_data, data_size, (size_t)*(Data_Info->Data_Count));
                    if(out_data)
                    {
                        struct data_header_info_t Data_Header_Info = f_s_Parser_Data_Header((char*)out_data, HEADER_SIZE);
                        F_RelayServer_Print_Debug(6,"[Debug][%s][%d][Client:%u]\n", __func__, __LINE__, Data_Header_Info.Client_fd);
                        enum job_type_e Now_Job;
                        if(*G_Clients_Info.connected_client_num > 0)
                        { 
                            for(int client_is = 0; client_is < MAX_CLIENT_SIZE; client_is++)
                            {
                                if(G_Clients_Info.socket[client_is] == Data_Header_Info.Client_fd)
                                {
                                    F_RelayServer_Print_Debug(2,"[Info][%s] Now_Job:%d\n", __func__, Data_Header_Info.Job_State);
                                    Now_Job = f_e_RelayServer_Job_Process_Do(&Data_Header_Info, &out_data, client_is, Data_Info);
                                    F_RelayServer_Print_Debug(6,"[Info][%s] Now_Job:%d\n", __func__, Now_Job);
                                    switch(Now_Job)
                                    {
                                        case Initial:
                                        case FirmwareInfoReport:
                                        case FirmwareInfoResponse:
                                        case FirmwareInfoIndication:

                                        case ProgramInfoReport: 
                                        case ProgramInfoResponse:
                                        case ProgramInfoIndication:

                                        case HandOverReminingData:
                                            F_RelayServer_Print_Debug(2,"[Info][%s] Now_Job:%d\n", __func__, Now_Job);
                                            data_size = Data_Header_Info.Message_size + HEADER_SIZE;
                                            F_RelayServer_Print_Debug(2,"[Debug][%s][%d][Push:%s/%d]\n", __func__, __LINE__, out_data, data_size);
                                            F_i_Memory_Data_Push(Data_Info, out_data, data_size);
                                            break;

                                        case FirmwareInfoRequest:
                                        case ProgramInfoRequest:
                                        case Finish:
                                            F_RelayServer_Print_Debug(0,"[Info][%s] Now_Job:%d\n", __func__, Now_Job);
                                            break;
                                        default:
                                            F_RelayServer_Print_Debug(0,"[Info][%s] Now_Job:%d\n", __func__, Now_Job);
                                            break; 
                                    }  
                                    break;
                                }else{
                                        if(0)//(client_is == *G_Clients_Info.connected_client_num - 1)
                                        {
                                            F_RelayServer_Print_Debug(1, "[Debug][%s][Client Closed:%d]\n", __func__, G_Clients_Info.socket[client_is]);
                                            F_RelayServer_Print_Debug(1, "[Debug][%s][Client Closed:%d]\n", __func__, Data_Header_Info.Client_fd);
                                        }
                                }
                            }
                        }
                        
                        F_RelayServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, out_data);
                        Relay_safefree(out_data);
                    }
                
                }
            }
        }


    }
}

int f_i_Hex2Dec(char data)
{
    int ret;_DEBUG_LOG
    if(48 <= (int)(data)  && (int)(data)  <= 57){
        ret = (int)(data) - 48;_DEBUG_LOG
    }else if(65 <= (int)(data)  && (int)(data)  <= 70)
    {
        ret = (int)(data) - 65 + 10;_DEBUG_LOG
    }else if(97 <= (int)(data)  && (int)(data)  <= 102)
    {
        ret = (int)(data)- 97 + 10;_DEBUG_LOG
    }
    return ret;_DEBUG_LOG
}

struct data_header_info_t f_s_Parser_Data_Header(char *Data, size_t Data_Size)
{
    struct data_header_info_t out_data;_DEBUG_LOG
    int Data_Num = 0;_DEBUG_LOG
    for(int i = 0; i < 4; i++)
    {
        switch(Data_Num)
        {
            case 0:
                out_data.Job_State = f_i_Hex2Dec(Data[0]);_DEBUG_LOG
                out_data.Protocol_Type = f_i_Hex2Dec(Data[1]);_DEBUG_LOG
                break;_DEBUG_LOG
            case 1:
                out_data.Client_fd = 0;_DEBUG_LOG
                for(int i = 0; i < 8; i++)
                {
                    out_data.Client_fd = out_data.Client_fd * 16 + f_i_Hex2Dec(Data[2 + i]);_DEBUG_LOG
                }
                break;_DEBUG_LOG
            case 2:
                out_data.Message_seq = f_i_Hex2Dec(Data[10]) * 16 + f_i_Hex2Dec(Data[11]);_DEBUG_LOG
                break;_DEBUG_LOG
            case 3:
                out_data.Message_size = 0;_DEBUG_LOG
                for(int i = 0; i < 8; i++)
                {
                    out_data.Message_size = out_data.Message_size * 16 + f_i_Hex2Dec(Data[12 + i]);_DEBUG_LOG
                }
                break;_DEBUG_LOG
            default:
                break;_DEBUG_LOG
        }
        Data_Num++;_DEBUG_LOG
    }
    return out_data;_DEBUG_LOG
}

void* th_RelayServer_TcpIp_Task_Server(void *socket_info)
{
    int ret;
    struct socket_info_t *Socket_Info = (struct socket_info_t*)socket_info;
    //int Client_Socket;
    struct sockaddr_in  Client_Address;
    //socklen_t adr_sz = sizeof(Client_Address);
#if 0 
    ret = listen(Socket_Info->Socket, 5);
    if(ret == -1)
    {
        F_RelayServer_Print_Debug(2,"[Error][%s][listen] Return Value:%d\n", __func__, ret);
        return NULL;
    }
#endif
    pthread_mutex_init(&G_Clients_Info.mtx, NULL);
   
    int client_is;
    char *recv_buf = malloc(TCP_RECV_BUFFER_SIZE);
    while(1)
    {
        struct sockaddr_in from_adr;
        socklen_t from_adr_sz;
        memset(recv_buf, 0x00, 128);
        int str_len = recvfrom(Socket_Info->Socket, recv_buf, 128, 0, (struct sockaddr*)&from_adr, &from_adr_sz);
        if(str_len > 0)
        {
            if(*G_Clients_Info.connected_client_num == MAX_CLIENT_SIZE)
            {
                F_RelayServer_Print_Debug(2,"[Error][%s][%d] Connected Client Num > MAX_CLIENT_SIZE:%d/%d\n", __func__, __LINE__, *G_Clients_Info.connected_client_num, MAX_CLIENT_SIZE);
            }else{
                for(client_is = 0; client_is < MAX_CLIENT_SIZE; client_is++)
                {
                    if(G_Clients_Info.socket[client_is] == 0)
                    {
                        pthread_mutex_lock(&G_Clients_Info.mtx);
                        G_Clients_Info.socket[client_is] = (int)(from_adr.sin_addr.s_addr);
                        G_Clients_Info.Life_Timer[client_is] = G_TickTimer.G_100ms_Tick + SOCKET_TIMER;
                        G_Clients_Info.socket_message_seq[client_is] = 0;
                        *G_Clients_Info.connected_client_num = *G_Clients_Info.connected_client_num + 1;
                        pthread_mutex_unlock(&G_Clients_Info.mtx);
                        break;
                    }else if(G_Clients_Info.socket[client_is] == (int)(from_adr.sin_addr.s_addr))
                    {
                        pthread_mutex_lock(&G_Clients_Info.mtx);
                        G_Clients_Info.Life_Timer[client_is] = G_TickTimer.G_100ms_Tick + SOCKET_TIMER;
                        char addr_str[40];
                        inet_ntop(AF_INET, (void *)&from_adr.sin_addr, addr_str, sizeof(addr_str));
                        //F_RelayServer_Print_Debug(2,"[DEBUG][%s][%d] Connected Client %s:%d\n", __func__, __LINE__, addr_str, from_adr.sin_port);
                        G_Clients_Info.socket_message_seq[client_is]++;
                         
                        uint8_t *push_data = malloc(sizeof(uint8_t) * (str_len + HEADER_SIZE));
                        sprintf((char*)push_data, HEADER_PAD,  //Client Data Protocol(Header:Hex_Sring,Payload:OCTETs)
                        0x0, //:job_state(1)
                        0x1, //protocol_type(1)
                        G_Clients_Info.socket[client_is], //client_fd(8)
                        G_Clients_Info.socket_message_seq[client_is], //message_seq(2);
                        str_len - 1);//message_size(8);
                        memcpy(push_data + HEADER_SIZE, recv_buf, str_len);//data(payload_size)
                        //F_RelayServer_Print_Debug(2,"[Debug][%s][%d][Push_Data:%s/%d]\n", __func__, __LINE__, push_data, str_len + HEADER_SIZE);
                        size_t left_buf = F_i_Memory_Data_Push(&G_Data_Info, (void *)push_data, str_len + HEADER_SIZE);
                        pthread_mutex_unlock(&G_Clients_Info.mtx);
                        //F_RelayServer_Print_Debug(2,"[Debug][%s][%d][Free Address:%p]\n", __func__, __LINE__, push_data);
                        Relay_safefree(push_data);
                        if(left_buf >= 0)
                        {
                            F_RelayServer_Print_Debug(2,"[Info][%s] Left_Buffer_Size:%ld\n", __func__, left_buf);
                        }else{
                            F_RelayServer_Print_Debug(2,"[Error][%s] No left buffer:%ld\n", __func__, left_buf);
                        }
                        break;
                    }
                }
            }
        }  
        
#if 1
        if(1)//(init_time + 1 < G_TickTimer.G_100ms_Tick)
        {
            //init_time = G_TickTimer.G_100ms_Tick;
            for(int i = 0; i < MAX_CLIENT_SIZE; i++)
            {   
                if(G_Clients_Info.socket[i] == Socket_Info->Socket)
                {
                   
                }else if(G_Clients_Info.socket[i]  != 0)
                {   
                    if(G_Clients_Info.Life_Timer[i] <= G_TickTimer.G_100ms_Tick)
                    {
                        F_RelayServer_Print_Debug(0,"[Debug][%s][close:%d, Timer:%d/%d, socket:%d]\n", __func__, __LINE__, G_Clients_Info.Life_Timer[i] ,G_TickTimer.G_100ms_Tick ,G_Clients_Info.socket[i]);
                        pthread_mutex_lock(&G_Clients_Info.mtx);
                        G_Clients_Info.socket[i] = 0;
                        memset(G_Clients_Info.client_data_info[i].ID, 0x00, 8);
                        memset(G_Clients_Info.client_data_info[i].Division, 0x00, 1);
                        memset(G_Clients_Info.client_data_info[i].Version, 0x00, 8);
                        G_Clients_Info.Life_Timer[i] = 0;
                        G_Clients_Info.socket_message_seq[i] = 0;
                        G_Clients_Info.socket_job_state[i] = -1; 
                        if(*G_Clients_Info.connected_client_num > 0)
                        {
                            *G_Clients_Info.connected_client_num = *G_Clients_Info.connected_client_num - 1;
                        }else if(*G_Clients_Info.connected_client_num < 0){
                            *G_Clients_Info.connected_client_num = 0;
                        }
                        pthread_mutex_unlock(&G_Clients_Info.mtx);
                        close(G_Clients_Info.socket[i]);  
                    }
                }
            }
        }
#endif
    }
    free(recv_buf);
    printf("While_Loop_Broken!%d\n", __LINE__);
    return (void*)NULL;
}
/* 
Brief:The Socket binding.
Parameter[In]
    Socket:Server Socket
    Socket_Addr:Server Socket Address
Parameter[Out]
    int 0 < Error_Code
 */
int f_i_RelayServer_TcpIp_Bind(int *Server_Socket, struct sockaddr_in Socket_Addr)
{
    int ret, Retry_Count;_DEBUG_LOG
    int Retry_Max = 10;_DEBUG_LOG
    char addr_str[40];_DEBUG_LOG
inet_ntop(AF_INET, (void *)&Socket_Addr.sin_addr, addr_str, sizeof(addr_str));_DEBUG_LOG
    do
    {
        ret = bind(*Server_Socket, (struct sockaddr*)&(Socket_Addr), sizeof(Socket_Addr));_DEBUG_LOG
        if(ret < 0 ) 
        {
            F_RelayServer_Print_Debug(0, "[Error][%s][Return_Value:%d]", __func__, ret);_DEBUG_LOG
            F_RelayServer_Print_Debug(0, "[Error][%s]\
            Server_Socket:%d;\
            Ip:Port:%s:%d\n",\
             __func__, *Server_Socket, addr_str, Socket_Addr.sin_port);_DEBUG_LOG
            if(Retry_Count == Retry_Max)
            {
                close(*Server_Socket);_DEBUG_LOG
                return -1;_DEBUG_LOG
            }
            Retry_Count++;_DEBUG_LOG

            sleep(1);_DEBUG_LOG
        }else{

            F_RelayServer_Print_Debug(0, "[Sucess][%s]\
            Server_Socket:%d;\
            Ip:Port:%s:%d\n",\
             __func__, *Server_Socket, addr_str, Socket_Addr.sin_port);_DEBUG_LOG
            return 0;_DEBUG_LOG
        }
    }while(Retry_Count < 10);_DEBUG_LOG
    return 0;_DEBUG_LOG
}

/* 
Brief:Setting features of the Socket. The Timer set a socket block timer. The Linger set a socket remaining time after closing socket.
Parameter[In]
    Socket:socket
    Timer:socket block time
    Linger:socket remaining time
Parameter[Out]
    int 0 < Error_Code
 */
int f_i_RelayServer_TcpIp_Setup_Socket(int *Socket, int Timer, bool Linger)
{
    if(!Socket || Timer < 0)
    {
        F_RelayServer_Print_Debug(2, "[Error][%s][No Input Argurements.](Socket:%p, Timer:%d)\n", __func__, Socket, Timer);_DEBUG_LOG
        return -1;_DEBUG_LOG
    }
    if(Linger)
    {
        struct linger solinger = { 1, 0 };  /* Socket FD close when the app down. */
        if (setsockopt(*Socket, SOL_SOCKET, SO_LINGER, &solinger, sizeof(struct linger)) == SO_ERROR) {
            perror("setsockopt(SO_LINGER)");_DEBUG_LOG
            return -3;_DEBUG_LOG
        }
    }
    if(Timer > 0)
    {
        struct timeval tv;                  /* Socket Connection End Timer */           
        tv.tv_sec = (int)(Timer / 1000);_DEBUG_LOG
        tv.tv_usec = (Timer % 1000) * 1000; 
        if (setsockopt(*Socket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) == SO_ERROR) {
            perror("setsockopt(SO_RCVTIMEO)");_DEBUG_LOG
            return -2;_DEBUG_LOG
        }
        if (setsockopt(*Socket, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) == SO_ERROR) {
            perror("setsockopt(SO_SNDTIMEO)");_DEBUG_LOG
            return -1;_DEBUG_LOG
        }
    }
    return 0;_DEBUG_LOG
}

/* 
Brief:According to the input debug level to print out a message in compare with the Global Debug Level.
Parameter[In]
    Debug_Lever_e:Debug Level
    String:A message to be print
    format:The Message Format
Parameter[Out]
    NULL
 */
void F_RelayServer_Print_Debug(enum debug_lever_e Debug_Level, const char *format, ...)
{

  if(Debug_Level == 0)
  {
    va_list arg;_DEBUG_LOG
    struct timespec ts;_DEBUG_LOG
    struct tm tm_now;_DEBUG_LOG

    clock_gettime(CLOCK_REALTIME, &ts);_DEBUG_LOG
    localtime_r((time_t *)&ts.tv_sec, &tm_now);_DEBUG_LOG
    fprintf(stderr, "[%04u%02u%02u.%02u%02u%02u.%06ld]", tm_now.tm_year+1900, tm_now.tm_mon+1, tm_now.tm_mday, \
            tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, ts.tv_nsec / 1000);_DEBUG_LOG
    va_start(arg, format);_DEBUG_LOG
    vprintf(format, arg);_DEBUG_LOG
    va_end(arg);_DEBUG_LOG
  }else{
    return;_DEBUG_LOG
  }
}

/* 
Brief:
Parameter[In]
Parameter[Out]
 */
void* Th_i_RelayServer_TickTimer(void *Data)
{
    Data = Data;_DEBUG_LOG
    int ret;_DEBUG_LOG
    // Using_Timer
    int32_t TimerFd = timerfd_create(CLOCK_MONOTONIC, 0);_DEBUG_LOG
    struct itimerspec itval;_DEBUG_LOG
    struct timespec tv;_DEBUG_LOG
    uint32_t usec = 10 * 1000;_DEBUG_LOG
    uint64_t res;_DEBUG_LOG

    clock_gettime(CLOCK_MONOTONIC, &tv); 
    itval.it_interval.tv_sec = 0;_DEBUG_LOG
    itval.it_interval.tv_nsec = (usec % 1000000) * 1e3;_DEBUG_LOG
    itval.it_value.tv_sec = tv.tv_sec + 1;_DEBUG_LOG
    itval.it_value.tv_nsec = 0;_DEBUG_LOG
    ret = timerfd_settime (TimerFd, TFD_TIMER_ABSTIME, &itval, NULL);_DEBUG_LOG

    uint32_t tick_count_10ms = 0;
    tick_count_10ms = (uint32_t)tick_count_10ms;

    while(1)
    {   
        ret = read(TimerFd, &res, sizeof(res));
        if(ret < 0)
        {

        }else{
            G_TickTimer.G_10ms_Tick = tick_count_10ms;
            switch(tick_count_10ms % 10)
            {
                case 0:
                {
                    G_TickTimer.G_100ms_Tick++; 
                    break;
                }
                default: break;
            }
            switch(tick_count_10ms % 100)
            {
                case 0:
                {
                    G_TickTimer.G_1000ms_Tick++;
                    break;
                }
                default:break;
            }
            tick_count_10ms++;
        }

    }
}


/* 
Brief:
Parameter[In]
Parameter[Out]
 */
enum job_type_e f_e_RelayServer_Job_Process_Do(struct data_header_info_t *Now_Header, uint8_t **Data, int Client_is, struct Memory_Used_Data_Info_t *Data_Info)
{
    int ret;_DEBUG_LOG
    enum job_type_e Now_Job_State = Now_Header->Job_State;_DEBUG_LOG
    enum job_type_e After_Job_State;_DEBUG_LOG

    switch(Now_Job_State)
    {
        case Initial: // Now_Job_State:0
            G_Clients_Info.client_data_info[Client_is] = f_s_RelayServer_Job_Process_Initial(Now_Header, *Data, &ret);_DEBUG_LOG
            break;_DEBUG_LOG
        case FirmwareInfoReport:// Now_Job_State:2
        case ProgramInfoReport: // Now_Job_State:7
            ret = f_i_RelayServer_Job_Process_InfoReport(Now_Header, *Data);_DEBUG_LOG
            if(ret < 0)
            {
                break;_DEBUG_LOG
            }else{
                Now_Job_State = ret;_DEBUG_LOG
            }
        case FirmwareInfoRequest: // Now_Job_State:3
        case ProgramInfoRequest:  // Now_Job_State:8
            ret = f_i_RelayServer_Job_Process_InfoRequest(Now_Header, Data, Data_Info);_DEBUG_LOG
            break;_DEBUG_LOG
        case FirmwareInfoResponse:// Now_Job_State:4
        case ProgramInfoResponse: // Now_Job_State:9
            ret = f_i_RelayServer_Job_Process_InfoResponse(Now_Header, Data);_DEBUG_LOG
            break;_DEBUG_LOG
        case FirmwareInfoIndication:// Now_Job_State:5
        case ProgramInfoIndication:// Now_Job_State:11
            break;_DEBUG_LOG
        case Finish: // Now_Job_State:1
            ret = f_i_RelayServer_Job_Process_Finish(Now_Header, *Data, Client_is);_DEBUG_LOG
            break;_DEBUG_LOG
        case HandOverReminingData:
            //f_s_RelayServer_Job_Process_HandOverReminingData()
            break;_DEBUG_LOG
        default:break;_DEBUG_LOG
    }
    
    if(ret > 0)
    {
        After_Job_State = ret;_DEBUG_LOG
    }else{
        After_Job_State = 1;_DEBUG_LOG
    }
    if(Now_Job_State == After_Job_State)
    {
     
    }else{
        Now_Header->Job_State = After_Job_State;_DEBUG_LOG
        G_Clients_Info.socket_job_state[Client_is] = After_Job_State;_DEBUG_LOG
    }
    if(After_Job_State == 1)
    {
        for(int data_is = 0; data_is < (size_t)*(Data_Info->Data_Count); data_is++)
        {
            size_t data_size;_DEBUG_LOG
            
            uint8_t *out_data = (uint8_t*)F_v_Memory_Data_Pop(Data_Info, &data_size); 
            if(out_data)
            {
                struct data_header_info_t Data_Header_Info = f_s_Parser_Data_Header((char*)out_data, HEADER_SIZE);_DEBUG_LOG
                size_t clear_data_size = 0;_DEBUG_LOG
                struct sockaddr_in client_addr = {.sin_addr.s_addr = Data_Header_Info.Client_fd};_DEBUG_LOG
                F_RelayServer_Print_Debug(0,"[Info] Flushing Received Data by Client[%s].\n", inet_ntoa(client_addr.sin_addr));_DEBUG_LOG
                uint8_t *clear_data = (uint8_t*)F_v_Memory_Data_Pop(Data_Info, &clear_data_size); 
                if(clear_data)
                {
                    struct data_header_info_t Data_Header_Info_clear = f_s_Parser_Data_Header((char*)clear_data, HEADER_SIZE);_DEBUG_LOG
                    if(Data_Header_Info_clear.Client_fd != Data_Header_Info.Client_fd)
                    {
                        F_i_Memory_Data_Push(Data_Info, clear_data, &clear_data_size);_DEBUG_LOG
                    }
                }
            }
        }
    }
    return After_Job_State;_DEBUG_LOG
}

/* 
Brief:
Parameter[In]
    Now_Header:
    Data:
    err:
Parameter[Out]
    client_data_info_t:It is made by the function 
 */
struct client_data_info_t f_s_RelayServer_Job_Process_Initial(struct data_header_info_t *Now_Header, uint8_t *Data, int *err)
{
    struct client_data_info_t out_data;_DEBUG_LOG
    if(Data)
    {
        uint8_t *Payload = (Data + HEADER_SIZE); 
        if(Payload[0] == 0x44) // Check STX
        {
            switch((int)Payload[1])
            {
                case 1:
                    if(Now_Header->Message_size  > 23) //Will Make the Over Recv Error Solution
                    {

                    }
                    out_data.Payload_Type = Fireware;_DEBUG_LOG
                    Now_Header->Job_State = 2;_DEBUG_LOG
                    Data[0] = *("2");_DEBUG_LOG
                    *err = Now_Header->Job_State;_DEBUG_LOG
                    break;_DEBUG_LOG
                case 3:
                    if(Now_Header->Message_size > 23) //Will Make the Over Recv Error Solution
                    {
                        F_RelayServer_Print_Debug(6, "[Error][%s][Payload_type:%c]\n", __func__, Payload[1]);_DEBUG_LOG
                    }
                    out_data.Payload_Type = Program;_DEBUG_LOG
                    Now_Header->Job_State = 7;_DEBUG_LOG
                    Data[0] = *("7");_DEBUG_LOG
                    *err = Now_Header->Job_State;_DEBUG_LOG
                    break;_DEBUG_LOG
                default:
                    F_RelayServer_Print_Debug(6, "[Error][%s][Payload_type:%c]\n", __func__, Payload[1]);_DEBUG_LOG
                    *err = -1;_DEBUG_LOG
                    return out_data;_DEBUG_LOG

            }
            memcpy((out_data.ID), Payload + 2, 8);_DEBUG_LOG
            memset((out_data.Division), 0x0A, 1);_DEBUG_LOG
            memcpy((out_data.Version), Payload + 10, 8);_DEBUG_LOG
        }else{
            Now_Header->Job_State = 1;_DEBUG_LOG
            *err = Now_Header->Job_State;_DEBUG_LOG
        }
        
    }
    return out_data;_DEBUG_LOG
}

/* 
Brief:
Parameter[In]
    Now_Header:
    Data:
    Client_is:
Parameter[Out]
    int 0 < Return Error Code
 */
 int f_i_RelayServer_Job_Process_Finish(struct data_header_info_t *Now_Header, uint8_t *Data, int Client_is)
{
    if(Data)
    {
        switch(Now_Header->Job_State)
        {
            case Finish:
                pthread_mutex_lock(&G_Clients_Info.mtx);_DEBUG_LOG
                G_Clients_Info.socket_job_state[Client_is] = -1;_DEBUG_LOG
                pthread_mutex_unlock(&G_Clients_Info.mtx);_DEBUG_LOG
                break;_DEBUG_LOG
            default:
                break;_DEBUG_LOG
        }
    }else{
        F_RelayServer_Print_Debug(2, "[Error][%s][No Data]\n", __func__);_DEBUG_LOG
        return -1;_DEBUG_LOG
    }
    return 0;_DEBUG_LOG
}

/* 
Brief:
Parameter[In]
    Now_Header:
    Data:
Parameter[Out]
    int 0 < Return Error Code
 */
 int f_i_RelayServer_Job_Process_InfoReport(struct data_header_info_t *Now_Header, uint8_t *Data)
{
    
    if(Data)
    {
        uint8_t *Payload = (Data + HEADER_SIZE); 
        printf("[%d]Now_Header->Message_size:%d\n", __LINE__, Now_Header->Message_size);_DEBUG_LOG
        
        if(Payload[0] == 0x44) // Check STX
        {
            
            switch(Now_Header->Job_State)
            {
                case FirmwareInfoReport:
                    if(Now_Header->Message_size == 23 && Payload[Now_Header->Message_size - 1] == 0xAA)
                    {
                         
                        Now_Header->Job_State = 3;_DEBUG_LOG
                        Data[0] = *"3";_DEBUG_LOG
                        F_RelayServer_Print_Debug(0, "[Info][%s][Job_State:%d, STX:%02X ETX:%02X]\n",__func__, Now_Header->Job_State, Payload[0], Payload[Now_Header->Message_size - 1]);_DEBUG_LOG
                        return Now_Header->Job_State;_DEBUG_LOG
                    }else{
                        printf("Now_Header->Message_size:%d,%02X\n", Now_Header->Message_size, Payload[Now_Header->Message_size - 1] );_DEBUG_LOG
                        F_RelayServer_Print_Debug(2, "[Error][%s][Now_Header->Message_size:%d, ETX:%02X]\n",__func__, Now_Header->Message_size, Payload[Now_Header->Message_size - 1]);_DEBUG_LOG
                        return -3;_DEBUG_LOG
                    }
                    break;_DEBUG_LOG
                case ProgramInfoReport:
                    if(Now_Header->Message_size == 23 && Payload[Now_Header->Message_size] == 0xAA)
                    {
                        Now_Header->Job_State = 8;_DEBUG_LOG
                        Data[0] = *"8";_DEBUG_LOG
                        F_RelayServer_Print_Debug(2, "[Info][%s][Job_State:%d, STX:%02X ETX:%02X]\n",__func__, Now_Header->Job_State, Payload[0], Payload[Now_Header->Message_size - 1]);_DEBUG_LOG
                        return Now_Header->Job_State;_DEBUG_LOG
                    }else{
                        F_RelayServer_Print_Debug(2, "[Error][%s][Now_Header->Message_size:%d, ETX:%02X]\n",__func__, Now_Header->Message_size, Payload[Now_Header->Message_size - 1]);_DEBUG_LOG
                        return -8;_DEBUG_LOG
                    }
                default:
                    return 0;_DEBUG_LOG
            }     
        } 
    }else{
        F_RelayServer_Print_Debug(2, "[Error][%s][No Data]\n",__func__);_DEBUG_LOG
        return -1;_DEBUG_LOG
    }
    
    return 0;_DEBUG_LOG
}

/* 
Brief:
Parameter[In]
    Now_Header:
    Data:
    err:
Parameter[Out]
    client_data_info_t:It is made by the function 
 */
 int f_i_RelayServer_Job_Process_InfoRequest(struct data_header_info_t *Now_Header, uint8_t **Data, struct Memory_Used_Data_Info_t *Data_Info)
{
    
    if(Data)
    {
        uint8_t *Payload = (*Data + HEADER_SIZE + 7); 
        struct http_socket_info_t *http_socket_info = malloc(sizeof(struct http_socket_info_t));_DEBUG_LOG
        F_RelayServer_Print_Debug(0,"[Debug][%s][malloc:%d, Address:%p]\n", __func__, __LINE__, http_socket_info);_DEBUG_LOG
        switch(Now_Header->Job_State)
        {
            case FirmwareInfoRequest:
                http_socket_info->request_len = f_i_RelayServer_HTTP_Payload(G_HTTP_Request_Info_Fireware, Payload, 16, &http_socket_info->request);_DEBUG_LOG
                break;_DEBUG_LOG
            case ProgramInfoRequest:
                http_socket_info->request_len = f_i_RelayServer_HTTP_Payload(G_HTTP_Request_Info_Program, Payload, 16, &http_socket_info->request);_DEBUG_LOG
                break;_DEBUG_LOG
            default:
                F_RelayServer_Print_Debug(2, "[Error][%s][Job_State:%d]\n", __func__, Now_Header->Job_State);_DEBUG_LOG
                return -1;_DEBUG_LOG
        }   
            http_socket_info->Now_Header = Now_Header;_DEBUG_LOG
            http_socket_info->Data_Info = Data_Info;_DEBUG_LOG
            Now_Header->Job_State = f_i_RelayServer_HTTP_Task_Run(Now_Header, http_socket_info, Data);_DEBUG_LOG
            F_RelayServer_Print_Debug(0, "[Info][%s][Job_State:%d]\n",__func__, Now_Header->Job_State);_DEBUG_LOG
            Relay_safefree(http_socket_info);_DEBUG_LOG
    }else{
        F_RelayServer_Print_Debug(2, "[Error][%s][No Data]\n",__func__);_DEBUG_LOG
        return -1;_DEBUG_LOG
    }

    return Now_Header->Job_State;_DEBUG_LOG
}


/* 
Brief:
Parameter[In]
    Now_Header:
    Data:
    err:
Parameter[Out]
    client_data_info_t:It is made by the function 
 */
 int f_i_RelayServer_Job_Process_InfoResponse(struct data_header_info_t *Now_Header, uint8_t **Data)
{ 
    if(Data)
    {
        char *Payload = *Data + HEADER_SIZE;_DEBUG_LOG
//* ADD 230906

        if(Now_Header->Message_size > 0)
        {
            printf("Now_Header->Message_size:%d\n", Now_Header->Message_size);_DEBUG_LOG
            char *URL;_DEBUG_LOG
            if(Now_Header->Message_size < 100)
            {
                URL = Payload;_DEBUG_LOG
            }else{
                Relay_safefree(*Data);_DEBUG_LOG
                URL = malloc(strlen("https://itp-self.wtest.biz/v1/system/firmwareDownload.php?fileSeq=350"));_DEBUG_LOG
                sprintf(URL, "%s", "https://itp-self.wtest.biz/v1/system/firmwareDownload.php?fileSeq=350");_DEBUG_LOG
            }

            CURL *curl_handle;_DEBUG_LOG
            CURLcode res;_DEBUG_LOG
            
            struct MemoryStruct chunk;_DEBUG_LOG
            chunk.memory = malloc(1);_DEBUG_LOG
            chunk.size = 0;_DEBUG_LOG
        
            while(*g_curl_isused)
            {
                usleep(1 * 1000);_DEBUG_LOG
                printf("g_curl_isused:%d\n", *g_curl_isused);printf("\x1B[1A\r");_DEBUG_LOG
            }
            printf("\n");_DEBUG_LOG
            *g_curl_isused = 1;_DEBUG_LOG
            curl_handle = curl_easy_init();_DEBUG_LOG
            if(curl_handle)
            {
                
                curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS , 1000);_DEBUG_LOG
                curl_easy_setopt(curl_handle, CURLOPT_URL, URL);_DEBUG_LOG
                curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);_DEBUG_LOG
                curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);_DEBUG_LOG
                
                res = curl_easy_perform(curl_handle);_DEBUG_LOG
                curl_easy_cleanup(curl_handle);_DEBUG_LOG
                curl_global_cleanup();_DEBUG_LOG
                
                if(res != CURLE_OK) {
                    F_RelayServer_Print_Debug(0, "[Error][%s]: %s\n", __func__, curl_easy_strerror(res));_DEBUG_LOG
                    Relay_safefree(chunk.memory);_DEBUG_LOG
                    Now_Header->Job_State = -1;_DEBUG_LOG
                    return -1;_DEBUG_LOG
                }
            }
            *g_curl_isused = 0;_DEBUG_LOG
            char *Http_Recv_data = malloc(sizeof(uint8_t) * (chunk.size + HEADER_SIZE));_DEBUG_LOG
            memset(Http_Recv_data, 0x00, sizeof(uint8_t) * (chunk.size + HEADER_SIZE));_DEBUG_LOG
            switch(Now_Header->Job_State)
            {
                case FirmwareInfoResponse:
                    Now_Header->Job_State = 0x5;_DEBUG_LOG
                    sprintf(Http_Recv_data, HEADER_PAD, 0x5, 0x0, Now_Header->Client_fd, Now_Header->Message_seq, chunk.size);_DEBUG_LOG
                    Now_Header->Message_size = chunk.size;_DEBUG_LOG
                    break;_DEBUG_LOG
                case ProgramInfoResponse:
                    Now_Header->Job_State = 0xA;_DEBUG_LOG
                    sprintf(Http_Recv_data, HEADER_PAD, 0xA, 0x0, Now_Header->Client_fd, Now_Header->Message_seq, chunk.size);_DEBUG_LOG
                    Now_Header->Message_size = chunk.size;_DEBUG_LOG
                    break;_DEBUG_LOG
                default:
                    Now_Header->Job_State = -1;_DEBUG_LOG
                    Relay_safefree(chunk.memory);_DEBUG_LOG
                    return -1;_DEBUG_LOG
            }
            memcpy(Http_Recv_data + HEADER_SIZE, chunk.memory, chunk.size);_DEBUG_LOG
            Relay_safefree(*Data);_DEBUG_LOG
            chunk.size = 0;
            Relay_safefree(chunk.memory);_DEBUG_LOG
            *Data = (uint8_t*)Http_Recv_data;_DEBUG_LOG
            int ret = f_i_RelayServer_Job_Process_InfoIndication(Now_Header, Data);_DEBUG_LOG
            if(ret > 0)
            {
                Now_Header->Job_State = ret;_DEBUG_LOG
            }
            printf("f_i_RelayServer_Job_Process_InfoIndication:%d\n", Now_Header->Job_State );_DEBUG_LOG
        }
        
    }else{
        Now_Header->Job_State = -1;_DEBUG_LOG
        return -1;_DEBUG_LOG
    }
    return Now_Header->Job_State;_DEBUG_LOG
}


static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;_DEBUG_LOG
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;_DEBUG_LOG
    printf("mem->size:%d\n", mem->size);
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);_DEBUG_LOG
    if(!ptr) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");_DEBUG_LOG
    return 0;_DEBUG_LOG
    }

    mem->memory = ptr;_DEBUG_LOG
    memcpy(&(mem->memory[mem->size]), contents, realsize);_DEBUG_LOG
    mem->size += realsize;_DEBUG_LOG
    mem->memory[mem->size] = 0;_DEBUG_LOG

    return realsize;_DEBUG_LOG
}

#if 0
 size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void **userp)
{
    size_t realsize = size * nmemb;_DEBUG_LOG
    struct MemoryStruct *mem = (struct MemoryStruct*)*userp;_DEBUG_LOG

    if(mem->size > 0)
    {   
        size_t temp_size = mem->size;_DEBUG_LOG
        free(*userp);_DEBUG_LOG
        mem = malloc(sizeof(struct MemoryStruct));_DEBUG_LOG
        mem->memory = malloc(temp_size + realsize + 1);_DEBUG_LOG
        mem->size = temp_size;_DEBUG_LOG
        *userp = (void*)mem;_DEBUG_LOG
    }else{
        free(*userp);_DEBUG_LOG
        mem = malloc(sizeof(struct MemoryStruct));_DEBUG_LOG
        mem->memory = malloc(realsize + 1);    
        mem->size = 0;_DEBUG_LOG
        *userp = (void*)mem;_DEBUG_LOG
    }
    if(!mem) {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");_DEBUG_LOG
        return 0;_DEBUG_LOG
    }
    memcpy(&(mem->memory[mem->size]), contents, realsize);_DEBUG_LOG
    mem->size += realsize;_DEBUG_LOG
    mem->memory[mem->size] = 0;_DEBUG_LOG
    return realsize;_DEBUG_LOG
}
#endif
/* 
Brief:
Parameter[In]
    Now_Header:
    Data:
    err:
Parameter[Out]
    client_data_info_t:It is made by the function 
 */
 int f_i_RelayServer_Job_Process_InfoIndication(struct data_header_info_t *Now_Header, uint8_t **Data)
{
    {
        _DEBUG_PRESS(Now_Header->Job_State)

        if(Data)
        {       
            uint8_t *Payload = *Data + HEADER_SIZE;_DEBUG_LOG

            int ret;_DEBUG_LOG
            //Socket_Setup
            int sock;_DEBUG_LOG
            struct sockaddr_in sock_addr; 
            int dest_port = 50000;_DEBUG_LOG
            sock = socket(PF_INET, SOCK_DGRAM, 0);_DEBUG_LOG
            memset(&sock_addr, 0x00, sizeof(sock_addr));_DEBUG_LOG
            sock_addr.sin_family = AF_INET;_DEBUG_LOG
            sock_addr.sin_port = htons(dest_port);_DEBUG_LOG
            sock_addr.sin_addr.s_addr = Now_Header->Client_fd;_DEBUG_LOG
            ret = f_i_RelayServer_TcpIp_Setup_Socket(&sock, 1000, true);_DEBUG_LOG
            switch(Now_Header->Job_State)
            {
                case FirmwareInfoIndication:
                case ProgramInfoIndication:
                    if(Now_Header->Message_size <= 0)
                    {
                        Now_Header->Job_State = 1;_DEBUG_LOG
                        //ret = send(Now_Header->Client_fd, Payload, 20, MSG_DONTWAIT);_DEBUG_LOG
                        ret = sendto(sock, Payload, 20, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));_DEBUG_LOG
                        if(ret <= 0)
                        {
                            F_RelayServer_Print_Debug(0,"[Debug][%s][send:%d, ret:%p]\n", __func__, __LINE__, ret);_DEBUG_LOG
                        }else{
                            printf("send:%d\n", ret);_DEBUG_LOG
                        }
                        break;_DEBUG_LOG
                    }else{
                        //ret = send(Now_Header->Client_fd, Payload, Now_Header->Message_size, MSG_DONTWAIT);_DEBUG_LOG
                        struct Keti_UDP_Header_t send_info;_DEBUG_LOG
                        memset(&send_info, 0x00, sizeof(struct Keti_UDP_Header_t));_DEBUG_LOG
                        uint32_t div_hdr_len = sizeof(struct Keti_UDP_Header_t);_DEBUG_LOG
                        send_info.div_num = 0;_DEBUG_LOG
                        uint32_t send_p_n = 0;_DEBUG_LOG
                        char *sendbuf = malloc(sizeof(char)* 1024);_DEBUG_LOG
                        send_info.STX = 0xAA;_DEBUG_LOG
                        send_info.ETX = 0xCE;_DEBUG_LOG
                        send_info.type[0] = 0x01;_DEBUG_LOG
                        send_info.type[1] = 0x02;_DEBUG_LOG
                        send_info.total_data_len = Now_Header->Message_size;_DEBUG_LOG
                        send_info.div_len = 1024 - div_hdr_len;_DEBUG_LOG

                        while(send_p_n < Now_Header->Message_size)
                        {
                            send_p_n = ((1024 - div_hdr_len) * send_info.div_num);_DEBUG_LOG
                            if(Now_Header->Message_size - send_p_n >= 1024)
                            {
                                
                                int left_len = (Now_Header->Message_size - send_p_n);_DEBUG_LOG
                                memcpy(sendbuf, &send_info, div_hdr_len);_DEBUG_LOG
                                printf("send_data:(%d + %d)/%d, left:%d\n", send_p_n, Now_Header->Message_size - (send_p_n + left_len),  Now_Header->Message_size, left_len);_DEBUG_LOG
                                printf("\033[A");_DEBUG_LOG
                                memcpy(sendbuf + div_hdr_len, Payload + send_p_n, 1024);_DEBUG_LOG
                                ret = sendto(sock, sendbuf, 1024, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));_DEBUG_LOG
                            }else{
                                int left_len = (Now_Header->Message_size - send_p_n);_DEBUG_LOG
                                memcpy(sendbuf, &send_info, div_hdr_len);_DEBUG_LOG
                                printf("send_data:(%d + %d)/%d, left:%d\n", send_p_n, Now_Header->Message_size - (send_p_n + left_len),  Now_Header->Message_size, left_len);_DEBUG_LOG
                                printf("\033[A");_DEBUG_LOG
                                memcpy(sendbuf + div_hdr_len, Payload + send_p_n, left_len);_DEBUG_LOG
                                ret = sendto(sock, sendbuf, left_len + div_hdr_len, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));_DEBUG_LOG
                                send_p_n = send_p_n + left_len;_DEBUG_LOG
                            }
                            if(ret <= 0)
                            {
                                F_RelayServer_Print_Debug(0,"\n[Debug][%s][%d][send:%d/%d]\n", __func__, __LINE__, ret, Now_Header->Message_size);_DEBUG_LOG
                            }else{
                                send_info.div_num  = send_info.div_num  + 1;_DEBUG_LOG
                            }
                            usleep(5 * 1000);_DEBUG_LOG
                        }
                        printf("\n");_DEBUG_LOG

                        printf("\n");_DEBUG_LOG
#if 1
                        FILE *file;_DEBUG_LOG
                        time_t current_time;_DEBUG_LOG
                        time(&current_time);_DEBUG_LOG
                        struct tm *local_time = localtime(&current_time);_DEBUG_LOG
                        char *file_name = malloc(sizeof(char) * 64);_DEBUG_LOG
                        sprintf(file_name, "%s%04d%02d%02d_%02d%02d%02d.bin", "firmware_",local_time->tm_year  + 1900, local_time->tm_mon + 1, local_time->tm_mday, local_time->tm_hour, \
                                                                                          local_time->tm_hour, local_time->tm_min, local_time->tm_sec);_DEBUG_LOG
                        char *file_path = malloc(sizeof("./database/download/") + strlen(file_name));_DEBUG_LOG
                        sprintf(file_path, "%s%s", "./database/download/", file_name);_DEBUG_LOG
                        file = fopen(file_path, "wb");_DEBUG_LOG
                        fwrite(Payload, sizeof(char), Now_Header->Message_size/sizeof(char), file);_DEBUG_LOG
                        fclose(file);_DEBUG_LOG
                        Relay_safefree(file_name);_DEBUG_LOG
                        Relay_safefree(file_path);_DEBUG_LOG
#endif  
                        uint8_t *out_data = malloc(sizeof(uint8_t) * HEADER_SIZE);_DEBUG_LOG
                        Now_Header->Job_State = Finish;                        
                        sprintf((char*)out_data, HEADER_PAD, Now_Header->Job_State, 0x0, Now_Header->Client_fd, Now_Header->Message_seq, 0);_DEBUG_LOG
                        Relay_safefree(*Data);_DEBUG_LOG
                        *Data = out_data;_DEBUG_LOG
                    }
                    break;_DEBUG_LOG
                default:
                    F_RelayServer_Print_Debug(0, "[Error][%s][Job_State:%d]", __func__, Now_Header->Job_State);_DEBUG_LOG
                    return -1;_DEBUG_LOG
            }
            close(sock);_DEBUG_LOG
        }else{
            F_RelayServer_Print_Debug(0, "[Error][%s][No Data]\n",__func__);_DEBUG_LOG
            return -1;_DEBUG_LOG
        }
    }
    return Now_Header->Job_State;_DEBUG_LOG
}

int F_i_RelayServer_HTTP_Initial(uint8_t *G_HTTP_Request_Info, struct http_info_t *http_info)
{
    uint8_t *request = G_HTTP_Request_Info;_DEBUG_LOG
    if(http_info)
    {
        sprintf((char*)request, "%s %s %s/%s\r\n", http_info->Request_Line.Method, http_info->Request_Line.To, http_info->Request_Line.What, http_info->Request_Line.Version);_DEBUG_LOG
        if(http_info->HOST){
            sprintf((char*)request, "%s%s: %s:%s\r\n", request , "Host", http_info->HOST, http_info->PORT);_DEBUG_LOG
        }else{
            sprintf((char*)request, "%s%s: %s:%s\r\n", request , "Host", DEFAULT_HTTP_SERVER_FIREWARE_URL, "80");_DEBUG_LOG
        }
        if(http_info->ACCEPT){
            sprintf((char*)request, "%s%s: %s\r\n", request , "Accept", http_info->ACCEPT);_DEBUG_LOG
        }else{
            sprintf((char*)request, "%s%s: %s\r\n", request , "Accept", DEFAULT_HTTP_ACCEPT);_DEBUG_LOG
        }
        if(http_info->CONTENT_TYPE){
            sprintf((char*)request, "%s%s: %s\r\n", request , "Content-Type", http_info->CONTENT_TYPE);_DEBUG_LOG
        }else{
            sprintf((char*)request, "%s%s: %s\r\n", request , "Content-Type", DEFAULT_HTTP_CONTENT_TYPE);_DEBUG_LOG
        }
    }else
    {
        sprintf((char*)request, "%s %s %s/%s\r\n", DEFAULT_HTTP_METHOD, DEFAULT_HTTP_SERVER_FIREWARE_URL, "HTTP", DEFAULT_HTTP_VERSION);_DEBUG_LOG
        sprintf((char*)request, "%s%s: %s\r\n", request , "Host", DEFAULT_HTTP_SERVER_FIREWARE_URL);_DEBUG_LOG
        sprintf((char*)request, "%s%s: %s\r\n", request , "Accept", DEFAULT_HTTP_ACCEPT);_DEBUG_LOG
        sprintf((char*)request, "%s%s: %s\r\n", request , "Content-Type", DEFAULT_HTTP_CONTENT_TYPE);_DEBUG_LOG
    }

    return 0;_DEBUG_LOG
}

size_t f_i_RelayServer_HTTP_Payload(uint8_t *G_HTTP_Request_Info, uint8_t *Body, size_t Body_Size, uint8_t **Http_Request)
{
    size_t request_len;_DEBUG_LOG
    uint8_t *request = malloc(sizeof(uint8_t) * 526);_DEBUG_LOG
    if(G_HTTP_Request_Info){
        memcpy(request, G_HTTP_Request_Info, strlen((char*)G_HTTP_Request_Info));_DEBUG_LOG
    }else{
        return -1;_DEBUG_LOG
    }
    
    if(Body)
    {
        if(Body_Size > 0)
        {
            sprintf((char*)request, "%s%s: %ld\r\n", request , "Content-Length", Body_Size);_DEBUG_LOG
        }
        sprintf((char*)request, "%s\r\n", request);_DEBUG_LOG
        request_len = strlen(request) + Body_Size;_DEBUG_LOG
        memcpy(request + strlen((char*)request), Body, Body_Size);_DEBUG_LOG
        *Http_Request = malloc(sizeof(uint8_t) * request_len);_DEBUG_LOG
        memcpy(*Http_Request, request, request_len);_DEBUG_LOG
        F_RelayServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, request);_DEBUG_LOG
        Relay_safefree(request);_DEBUG_LOG
    }else {
        return -1;_DEBUG_LOG
    }
    return request_len;_DEBUG_LOG
}

# if 0
#else // 20240909 Change //20240912 Confirm
int f_i_RelayServer_HTTP_Task_Run(struct data_header_info_t *Now_Header, struct http_socket_info_t *http_socket_info, uint8_t **out_data)
{
    curl_socket_t sockfd;   
    CURLcode res;_DEBUG_LOG
    char *URL;_DEBUG_LOG
    switch(http_socket_info->Now_Header->Job_State)
    {
        case FirmwareInfoRequest:
        {
            URL = DEFAULT_HTTP_SERVER_PROGRAM_URL;_DEBUG_LOG
            break;_DEBUG_LOG
        }
        case ProgramInfoRequest:
        {
            URL = DEFAULT_HTTP_SERVER_PROGRAM_URL;_DEBUG_LOG
            break;_DEBUG_LOG
        }
        default:
        {
            Now_Header->Job_State = -1;_DEBUG_LOG
            goto th_RelayServer_HTTP_Task_Receive_OUT;_DEBUG_LOG
        }    
    }
    if(1)
    {
        while(*g_curl_isused)
        {
            usleep(1 * 1000);_DEBUG_LOG
            printf("g_curl_isused:%d\n", *g_curl_isused);printf("\x1B[1A\r");_DEBUG_LOG
        }
        printf("\n");_DEBUG_LOG
        *g_curl_isused = 1;_DEBUG_LOG
        CURL *curl = curl_easy_init();_DEBUG_LOG
        if(curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, URL);_DEBUG_LOG
            curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);_DEBUG_LOG
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS , 1000);_DEBUG_LOG
            res = curl_easy_perform(curl);_DEBUG_LOG
            if(res != CURLE_OK) {
                F_RelayServer_Print_Debug(0, "[Error][%s]: %s\n", __func__, curl_easy_strerror(res));_DEBUG_LOG
                Now_Header->Job_State = -1;_DEBUG_LOG
                goto th_RelayServer_HTTP_Task_Receive_OUT;_DEBUG_LOG
            }

            res = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);_DEBUG_LOG
            if(res != CURLE_OK) {
                F_RelayServer_Print_Debug(2, "[Error][%s]: %s\n", __func__, curl_easy_strerror(res));_DEBUG_LOG
                Now_Header->Job_State = -1;_DEBUG_LOG
                goto th_RelayServer_HTTP_Task_Receive_OUT;_DEBUG_LOG
            }
            size_t nsent_total = 0;_DEBUG_LOG
        do 
            {
                size_t nsent;_DEBUG_LOG
                do {
                    nsent = 0;_DEBUG_LOG
                    res = curl_easy_send(curl, http_socket_info->request + nsent_total, http_socket_info->request_len - nsent_total, &nsent);_DEBUG_LOG
                    nsent_total += nsent;_DEBUG_LOG

                    if(res == CURLE_AGAIN && !f_i_RelayServer_HTTP_WaitOnSocket(sockfd, 0, HTTP_SOCKET_TIMEOUT)) 
                    {
                        F_RelayServer_Print_Debug(2, "[Error][%s]: timeout.\n", __func__);_DEBUG_LOG
                        Now_Header->Job_State = -1;_DEBUG_LOG
                        goto th_RelayServer_HTTP_Task_Receive_OUT;_DEBUG_LOG
                    }
                } while(res == CURLE_AGAIN);_DEBUG_LOG

                if(res != CURLE_OK) 
                {
                    F_RelayServer_Print_Debug(2, "[Error][%s]: %s\n", __func__, curl_easy_strerror(res));_DEBUG_LOG
                    Now_Header->Job_State = -1;_DEBUG_LOG
                    goto th_RelayServer_HTTP_Task_Receive_OUT;_DEBUG_LOG
                }
            } while(nsent_total < http_socket_info->request_len);_DEBUG_LOG

            char buf[HTTP_BUFFER_SIZE] = {0,};_DEBUG_LOG
            size_t buf_len = 0;_DEBUG_LOG
            for(;;) 
            {
                
                size_t nread;_DEBUG_LOG
                do {
                    nread = 0;_DEBUG_LOG
                    res = curl_easy_recv(curl, buf, sizeof(buf), &nread);_DEBUG_LOG
                    buf_len += nread;_DEBUG_LOG
                    if(res == CURLE_AGAIN && !f_i_RelayServer_HTTP_WaitOnSocket(sockfd, 1, HTTP_SOCKET_TIMEOUT)) 
                    {
                        F_RelayServer_Print_Debug(2, "[Error][%s]: timeout.\n", __func__);_DEBUG_LOG
                        Now_Header->Job_State = -1;_DEBUG_LOG
                        goto th_RelayServer_HTTP_Task_Receive_OUT;_DEBUG_LOG
                    }
                } while(res == CURLE_AGAIN);_DEBUG_LOG
                
                if(res != CURLE_OK) 
                {
                    buf_len = 0;_DEBUG_LOG
                    F_RelayServer_Print_Debug(2, "[Error][%s]: %s\n", __func__, curl_easy_strerror(res));_DEBUG_LOG
                    break;_DEBUG_LOG
                }
                if(nread == 0) {
                    break;_DEBUG_LOG
                }
            }
            curl_easy_cleanup(curl);_DEBUG_LOG
            if(buf_len > 0)
            {
                int http_body_len;_DEBUG_LOG
                char* ptr = strstr(buf, "\r\n\r\n");_DEBUG_LOG
                ptr = ptr + 4;_DEBUG_LOG
                http_body_len = buf_len - (ptr - &buf[0]); /// -2 delete /r/n
                char http_body[http_body_len];_DEBUG_LOG
                memcpy(http_body, ptr, http_body_len);_DEBUG_LOG
                uint8_t *Http_Recv_data = malloc(sizeof(uint8_t) * (http_body_len + HEADER_SIZE));_DEBUG_LOG
                if(http_body_len > 0)
                {
                    uint8_t *Http_Recv_data = malloc(sizeof(uint8_t) * (http_body_len + HEADER_SIZE));_DEBUG_LOG
                    memset(Http_Recv_data, 0x00, sizeof(uint8_t) * (http_body_len + HEADER_SIZE));_DEBUG_LOG
                    switch(Now_Header->Job_State)
                    {
                        case FirmwareInfoRequest:
                            Now_Header->Job_State = 4;_DEBUG_LOG
                            sprintf(Http_Recv_data, HEADER_PAD, 0x4, 0x0, Now_Header->Client_fd, Now_Header->Message_seq, http_body_len);_DEBUG_LOG
                            Now_Header->Message_size = http_body_len;_DEBUG_LOG
                            break;_DEBUG_LOG
                        case ProgramInfoRequest:
                            Now_Header->Job_State = 9;_DEBUG_LOG
                            sprintf(Http_Recv_data, HEADER_PAD, 0x9, 0x0, Now_Header->Client_fd, Now_Header->Message_seq, http_body_len);_DEBUG_LOG
                            Now_Header->Message_size = http_body_len;_DEBUG_LOG
                            break;_DEBUG_LOG
                        default:
                            memset(http_body, 0x00, http_body_len);_DEBUG_LOG
                            Now_Header->Job_State = -1;_DEBUG_LOG
                            goto th_RelayServer_HTTP_Task_Receive_OUT;_DEBUG_LOG
                    }

                    memcpy(Http_Recv_data + HEADER_SIZE, http_body, http_body_len);        
                    memset(http_body, 0x00, http_body_len);_DEBUG_LOG
                    Relay_safefree(*out_data);_DEBUG_LOG
                    *out_data = Http_Recv_data;_DEBUG_LOG
                    goto th_RelayServer_HTTP_Task_Receive_OUT;_DEBUG_LOG
                }

            }
    th_RelayServer_HTTP_Task_Receive_OUT:

        /* always cleanup */
        memset(buf, 0x00, sizeof(buf));_DEBUG_LOG
        close(sockfd);_DEBUG_LOG

        }
    }
    *g_curl_isused = 0;_DEBUG_LOG
    return Now_Header->Job_State;_DEBUG_LOG
}
#endif

 void f_v_RelayServer_HTTP_Message_Parser(char *data_ptr, char *compare_word, void **ret, size_t *ret_len)
{ 
    int ptr_right = 0;_DEBUG_LOG
    int compare_word_len = strlen(compare_word);_DEBUG_LOG
    if(ret == NULL)
    {
        return;_DEBUG_LOG
    }
    while(data_ptr[ptr_right])
    {
        if(strncmp(data_ptr + ptr_right,  compare_word, compare_word_len) == 0)
        {
            char *ptr = strtok(data_ptr + ptr_right, "\r\n");_DEBUG_LOG
            *ret = ptr;_DEBUG_LOG
            if(*ret_len == 0)
            {
                strtok(ptr, "\"");_DEBUG_LOG
                strtok(NULL, "\"");_DEBUG_LOG
                ptr = strtok(NULL, "\"");_DEBUG_LOG
                *ret = ptr;_DEBUG_LOG
               size_t char_len = 0;_DEBUG_LOG
                char_len = strlen(ptr);_DEBUG_LOG
                *ret_len = char_len;_DEBUG_LOG
                return;_DEBUG_LOG
            }else{
                int test = atoi(ptr);_DEBUG_LOG
                memcpy(*ret, &test, *ret_len);_DEBUG_LOG
                return;_DEBUG_LOG
            }
            break;_DEBUG_LOG
        }
        ptr_right++;_DEBUG_LOG
    }
    *ret_len = 0;_DEBUG_LOG
}

int f_i_RelayServer_HTTP_WaitOnSocket(curl_socket_t sockfd, int for_recv, long timeout_ms)
{
  struct timeval tv;_DEBUG_LOG
  fd_set infd, outfd, errfd;_DEBUG_LOG
  int res;_DEBUG_LOG
 
  tv.tv_sec = timeout_ms / 1000;_DEBUG_LOG
  tv.tv_usec = (int)(timeout_ms % 1000) * 1000;_DEBUG_LOG
 
  FD_ZERO(&infd);_DEBUG_LOG
  FD_ZERO(&outfd);_DEBUG_LOG
  FD_ZERO(&errfd);_DEBUG_LOG
 
  FD_SET(sockfd, &errfd); /* always check for error */
 
  if(for_recv) {
    FD_SET(sockfd, &infd);_DEBUG_LOG
  }
  else {
    FD_SET(sockfd, &outfd);_DEBUG_LOG
  }
 
  /* select() returns the number of signalled sockets or -1 */
  res = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);_DEBUG_LOG
  return res;_DEBUG_LOG
}

/* Define NUVO */
#define DNM_Req_Signal 0x00
#define DNM_Done_Signal 0xFF

extern void *Th_RelayServer_NUVO_Client_Task(void *d)
{
    struct NUVO_recv_task_info_t *nubo_info = (struct NUVO_recv_task_info_t*)d;_DEBUG_LOG
    int ret;_DEBUG_LOG

    // Using_Timer
    int32_t TimerFd = timerfd_create(CLOCK_REALTIME, 0);//CLOCK_MONOTONIC(시각동기화 미사용시)
    struct itimerspec itval;_DEBUG_LOG
    struct timespec tv;_DEBUG_LOG
    uint32_t timer_tick_usec = 100 * 1000; //ms
    uint64_t res = 0;_DEBUG_LOG
    clock_gettime(CLOCK_REALTIME, &tv); 
    itval.it_interval.tv_sec = 0;_DEBUG_LOG
    itval.it_interval.tv_nsec = (timer_tick_usec % 1000000) * 1e3;_DEBUG_LOG
    itval.it_value.tv_sec = tv.tv_sec + 1;_DEBUG_LOG
    itval.it_value.tv_nsec = 0;_DEBUG_LOG
    ret = timerfd_settime (TimerFd, TFD_TIMER_ABSTIME, &itval, NULL);_DEBUG_LOG
    nubo_info->life_time = 0;_DEBUG_LOG
    sprintf(nubo_info->ACK,"%s%02X", "ACK", 0x5D);_DEBUG_LOG
    nubo_info->state = 0;_DEBUG_LOG

    uint32_t timer_100ms_tick = 0;_DEBUG_LOG
    //int tick_count_10ms = 0;_DEBUG_LOG

    srand(time(NULL));//Random 값의 Seed 값 변경
    uint32_t timer_op_1s = ((rand() % 9) + 0);_DEBUG_LOG
    nubo_info->task_info_state = malloc(sizeof(int));_DEBUG_LOG
    *nubo_info->task_info_state = 1;_DEBUG_LOG

    nubo_info->sock = socket(PF_INET, SOCK_DGRAM, 0);_DEBUG_LOG
    
    memset(&nubo_info->serv_adr, 0, sizeof(nubo_info->serv_adr));_DEBUG_LOG
    nubo_info->serv_adr.sin_family = AF_INET;_DEBUG_LOG
    nubo_info->serv_adr.sin_addr.s_addr = inet_addr(DEFAULT_NUVO_ADDRESS);_DEBUG_LOG
    nubo_info->serv_adr.sin_port = htons(atoi(DEFAULT_NUVO_PORT));_DEBUG_LOG
    
    struct timeval sock_tv;                  /* Socket Send/Recv Block Timer */               
    sock_tv.tv_sec = (int)(50 / 1000);_DEBUG_LOG
    sock_tv.tv_usec = (90 % 1000) * 1000; 
    if (setsockopt(nubo_info->sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&sock_tv, sizeof(struct timeval)) == SO_ERROR) {
    perror("setsockopt(SO_RCVTIMEO)");_DEBUG_LOG
    }
    sock_tv.tv_usec = (50 % 1000) * 1000; 
    if (setsockopt(nubo_info->sock, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&sock_tv, sizeof(struct timeval)) == SO_ERROR) {
    perror("setsockopt(SO_SNDTIMEO)");_DEBUG_LOG
    }
    printf("[DRIVING HISTORY] UDP Socket Initial\n");_DEBUG_LOG
    printf("[DRIVING HISTORY] UDP Socket Infomation ...... NUVO IP Address:Port - %s:%d\n", inet_ntoa(nubo_info->serv_adr.sin_addr), atoi(DEFAULT_NUVO_PORT));_DEBUG_LOG

    time_t now = time(NULL);_DEBUG_LOG
    for(int i = 0; i < 1; i++)
    {
        printf("[DRIVING HISTORY] Waiting ECU Indication ...... %ld[s](Working Time)\n", time(NULL) - now);_DEBUG_LOG
        sleep(1);_DEBUG_LOG
    }

    printf("[DRIVING HISTORY] Received ECU Start Indication ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
    //printf("[DRIVING HISTORY] " "\033[0;33m" "Press Any Key" "\033[0;0m" " to continue ...... %ld[s]\n", time(NULL) - now);while(getchar() != '\n');printf("\x1B[1A\r");   
    nubo_info->state = GW_SLEEP_CONNECTIONING_NUVO;_DEBUG_LOG
    char Ack_Data[11] = {0,};_DEBUG_LOG
    nubo_info->life_time = -1;_DEBUG_LOG
    uint32_t Start_Save_Driving_History = 0;_DEBUG_LOG
    //char *file_data = NULL;_DEBUG_LOG
    size_t file_data_len = 0;_DEBUG_LOG
    time_t timer = time(NULL);_DEBUG_LOG
    struct tm *t = localtime(&timer);_DEBUG_LOG
    char file_name[19];_DEBUG_LOG
    sprintf(file_name, "%04d%02d%02d_%02d%02d%02d", 1900 + t->tm_year, t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);_DEBUG_LOG
    
    for(;;)
    {     
        ret = read(TimerFd, &res, sizeof(uint64_t));_DEBUG_LOG
        if(nubo_info->life_time >= 0)
        {
            nubo_info->life_time += 1;_DEBUG_LOG
            if((timer_100ms_tick % 50 == 0 && nubo_info->life_time >= 0) || nubo_info->life_time > 50)
            {
                Ack_Data[9] = (int)(nubo_info->life_time / 10) % 0xF0;_DEBUG_LOG
                do{
                    ret = recvfrom(nubo_info->sock , recv_buf, 128, 0, (struct sockaddr*)&from_adr, &from_adr_sz);
                    if(ret > 0)
                    {
                        printf("[DRIVING HISTORY] Receive buffer flushing :%d\n", ret);
                    }
                }while(ret > 0);
                ret = sendto(nubo_info->sock , Ack_Data, 11, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));_DEBUG_LOG
                printf("[DRIVING HISTORY] [Send Ack Every 5sec] ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                nubo_info->life_time = 0;_DEBUG_LOG
            }
        }
        
        switch((timer_100ms_tick % 10) - timer_op_1s)
        {
            default:
            {
No_GW_SLEEP_CONNECTIONING_NUVO: 
                if(nubo_info->state != GW_RECEIVE_DRIVING_HISTORY_DATA_FROM_NOVO)
                {
                    struct sockaddr_in from_adr;_DEBUG_LOG
                    socklen_t from_adr_sz;_DEBUG_LOG
                    char recv_buf[128] = {0,};_DEBUG_LOG
                    ret = recvfrom(nubo_info->sock , recv_buf, 128, 0, (struct sockaddr*)&from_adr, &from_adr_sz);_DEBUG_LOG
                    if(ret > 0)
                    {
                        printf("[DRIVING HISTORY] [Recvive From NUVO] Received Data Length:%d ...... %ld[s]\n", ret, time(NULL) - now);_DEBUG_LOG
                        printf("[DRIVING HISTORY] [Recvive From NUVO] Received Data Hex Stream : ");_DEBUG_LOG
                        for(int k = 0; k < ret; k++)
                        {   
                            if(k == 9)
                            {
                                printf("\033[0;32m");_DEBUG_LOG
                            }else{
                                printf("\033[0m");_DEBUG_LOG
                            }         
                            printf("%02X ", recv_buf[k]);_DEBUG_LOG
                        }
                        printf("\n");_DEBUG_LOG
                    }
                    switch(recv_buf[9])
                    {
                        default:break;_DEBUG_LOG
                        case NUVO_SIGNAL_STATE_RES_CONNECT:
                        {
                            printf("[DRIVING HISTORY] [Recvive Response Connecting] Response From NUVO ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Recvive Response Connecting] Receive Success ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            nubo_info->state = GW_REQUEST_SAVE_DRIVING_HISTORY_TO_NUVO;_DEBUG_LOG
                            break;_DEBUG_LOG
                        }
                        case NUVO_SIGNAL_STATE_RES_SAVEDATA:
                        {
                            printf("[DRIVING HISTORY] [Recvive Response Save Driving History] Response From NUVO  ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Recvive Response Save Driving History] Receive Success ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            nubo_info->state = GW_WAIT_DONE_SAVE_DRIVING_HISTORY_FROM_ECU;_DEBUG_LOG
                            break;_DEBUG_LOG
                        }
                        case NUVO_SIGNAL_STATE_DOWNLOAD_PREPARE:
                        {
                            printf("[DRIVING HISTORY] [Waiting Driving History Data Info] Response From NUVO  ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Waiting Driving History Data Info] Receive Success ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            memcpy(&file_data_len, recv_buf + 6 + 4, 4);_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Waiting Driving History Data Info] Prepare File Size %ld ...... %ld[s]\n", file_data_len, time(NULL) - now);_DEBUG_LOG
                            nubo_info->state = GW_RECEIVE_DRIVING_HISTORY_DATA_FROM_NOVO;_DEBUG_LOG
                            break;_DEBUG_LOG
                        }
                    }
                    
                }
                switch(nubo_info->state)
                {
                    default: 
                    {
                        break;_DEBUG_LOG
                    }
                    case GW_WATING_REPLY_CONNECTION_FROM_NUVO:
                    {
                        if(0)
                        {
                            if(nubo_info->life_time > 20)
                            {
                                printf("[DRIVING HISTORY] [Recvive Response Connecting] Response From NUVO ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                                printf("[DRIVING HISTORY] [Recvive Response Connecting] Receive Success ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                                printf("[DRIVING HISTORY] [Recvive Response Connecting] Receive Data(Hex) ...... ");_DEBUG_LOG
                                char hdr[6] = {0,};_DEBUG_LOG
                                hdr[0] = 0x43;_DEBUG_LOG
                                hdr[1] = 0x08;_DEBUG_LOG
                                int data_length = 256;_DEBUG_LOG
                                memcpy(&hdr[2], &data_length, 4);_DEBUG_LOG
                                char STX = 0x43;_DEBUG_LOG
                                char ETX = 0xAA;_DEBUG_LOG
                                char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));_DEBUG_LOG
                                memcpy(send_buf, hdr, 6);_DEBUG_LOG
                                nubo_info->ACK[0] = 'A';_DEBUG_LOG
                                nubo_info->ACK[1] = 'C';_DEBUG_LOG
                                nubo_info->ACK[2] = 'K';_DEBUG_LOG
                                nubo_info->ACK[3] = NUVO_SIGNAL_STATE_RES_CONNECT;_DEBUG_LOG
                                memcpy(send_buf + 6, &nubo_info->ACK[0], 4);_DEBUG_LOG
                                memcpy(send_buf + 6 + 4, &ETX, 1);_DEBUG_LOG
                                for(int k = 0; k < 11; k++)
                                {
                                    if(k == 9)
                                    {
                                        printf("\033[0;32m");_DEBUG_LOG
                                    }else{
                                        printf("\033[0m");_DEBUG_LOG
                                    }                                    
                                    printf("%02X ", send_buf[k]);_DEBUG_LOG
                                }
                                printf("\n");_DEBUG_LOG
                                nubo_info->life_time = 1;_DEBUG_LOG
                                memcpy(Ack_Data, send_buf, 11);_DEBUG_LOG
                                Relay_safefree(send_buf);_DEBUG_LOG
                                nubo_info->state = GW_REQUEST_SAVE_DRIVING_HISTORY_TO_NUVO;_DEBUG_LOG
                            }
                        }else{
                            if(timer_100ms_tick % 10 == 0)
                            {
                                printf("[DRIVING HISTORY] [Recvive Response Connecting] Wating Response ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            }
                        }
                        break;_DEBUG_LOG
                    }
                    case GW_REQUEST_SAVE_DRIVING_HISTORY_TO_NUVO:
                    {
                        char hdr[6] = {0,};_DEBUG_LOG
                        hdr[0] = 0x43;_DEBUG_LOG
                        hdr[1] = 0x08;_DEBUG_LOG
                        int data_length = 256;_DEBUG_LOG
                        memcpy(&hdr[2], &data_length, 4);_DEBUG_LOG
                        char STX = 0x43;_DEBUG_LOG
                        char ETX = 0xAA;_DEBUG_LOG
                        char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));_DEBUG_LOG
                        memcpy(send_buf, hdr, 6);_DEBUG_LOG
                        nubo_info->ACK[0] = 'A';_DEBUG_LOG
                        nubo_info->ACK[1] = 'C';_DEBUG_LOG
                        nubo_info->ACK[2] = 'K';_DEBUG_LOG
                        nubo_info->ACK[3] = NUVO_SIGNAL_STATE_REQ_SAVEDATA;_DEBUG_LOG
                        memcpy(send_buf + 6, &nubo_info->ACK[0], 4);_DEBUG_LOG
                        int DNM = 1234;_DEBUG_LOG
                        memcpy(send_buf + 6 + 4, &DNM, 4);_DEBUG_LOG
                        memcpy(send_buf + 6 + 4 + 4, &ETX, 1);_DEBUG_LOG
                        printf("\n");printf("[DRIVING HISTORY] " "\033[0;33m" "Press Any Key" "\033[0;0m" " to [Send Request Start Save Driving History] ...... %ld[s]\n", time(NULL) - now);while(getchar() != '\n');printf("\x1B[1A\r");_DEBUG_LOG
                        printf("[DRIVING HISTORY] [Send Request Start Save Driving History] 'Request Start Save Driving History To NUVO' ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                        ret = sendto(nubo_info->sock , send_buf, 11, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));_DEBUG_LOG
                        printf("[DRIVING HISTORY] [Send Request Start Save Driving History] Send Success ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                        printf("[DRIVING HISTORY] [Send Request Start Save Driving History] Send Data(Hex) ...... ");_DEBUG_LOG
                        Start_Save_Driving_History =  time(NULL) - now;_DEBUG_LOG
                        for(int k = 0; k < 15; k++)
                        {
                            if(k == 9)
                            {
                                printf("\033[0;32m");_DEBUG_LOG
                            }else{
                                printf("\033[0m");_DEBUG_LOG
                            }
                            printf("%02X ", send_buf[k]);_DEBUG_LOG
                        }
                        printf("\n");_DEBUG_LOG
                        Relay_safefree(send_buf); 
                        nubo_info->state = GW_WATING_REPLY_SAVE_DRIVING_HISTORY_FROM_NUVO;_DEBUG_LOG
                        break;_DEBUG_LOG
                    }
                    case GW_WATING_REPLY_SAVE_DRIVING_HISTORY_FROM_NUVO:
                    {
                        if(0)
                        {
                            printf("[DRIVING HISTORY] [Recvive Response Save Driving History] Response From NUVO  ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Recvive Response Save Driving History] Receive Success ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Recvive Response Save Driving History] Receive Data(Hex) ...... ");_DEBUG_LOG
                            char hdr[6] = {0,};_DEBUG_LOG
                            hdr[0] = 0x43;_DEBUG_LOG
                            hdr[1] = 0x08;_DEBUG_LOG
                            int data_length = 256;_DEBUG_LOG
                            memcpy(&hdr[2], &data_length, 4);_DEBUG_LOG
                            char STX = 0x43;_DEBUG_LOG
                            char ETX = 0xAA;_DEBUG_LOG
                            char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));_DEBUG_LOG
                            memcpy(send_buf, hdr, 6);_DEBUG_LOG
                            nubo_info->ACK[0] = 'A';_DEBUG_LOG
                            nubo_info->ACK[1] = 'C';_DEBUG_LOG
                            nubo_info->ACK[2] = 'K';_DEBUG_LOG
                            nubo_info->ACK[3] = NUVO_SIGNAL_STATE_RES_SAVEDATA;_DEBUG_LOG
                            memcpy(send_buf + 6, &nubo_info->ACK[0], 4);_DEBUG_LOG
                            int DNM = 5678;_DEBUG_LOG
                            memcpy(send_buf + 6 + 4, &DNM, 4);_DEBUG_LOG
                            memcpy(send_buf + 6 + 4 + 4, &ETX, 1);_DEBUG_LOG
                            for(int k = 0; k < 15; k++)
                            {
                                if(k == 9)
                                {
                                    printf("\033[0;32m");_DEBUG_LOG
                                }else{
                                    printf("\033[0m");_DEBUG_LOG
                                }                                    
                                printf("%02X ", send_buf[k]);_DEBUG_LOG
                            }
                            printf("\n"); 
                            nubo_info->state = GW_WAIT_DONE_SAVE_DRIVING_HISTORY_FROM_ECU;_DEBUG_LOG
                        }else{
                            if(timer_100ms_tick % 10 == 0)
                            {
                                printf("[DRIVING HISTORY] [Recvive Response Save Driving History] Wating Response ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            }
                        }
                        
                    }
                    case GW_WAIT_DONE_SAVE_DRIVING_HISTORY_FROM_ECU:
                    {
                        if(1)
                        {
                            printf("[DRIVING HISTORY] Received ECU Done Indication ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            char hdr[6] = {0,};_DEBUG_LOG
                            hdr[0] = 0x43;_DEBUG_LOG
                            hdr[1] = 0x08;_DEBUG_LOG
                            int data_length = 256;_DEBUG_LOG
                            memcpy(&hdr[2], &data_length, 4);_DEBUG_LOG
                            char STX = 0x43;_DEBUG_LOG
                            char ETX = 0xAA;_DEBUG_LOG
                            char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));_DEBUG_LOG
                            memcpy(send_buf, hdr, 6);_DEBUG_LOG
                            nubo_info->ACK[0] = 'A';_DEBUG_LOG
                            nubo_info->ACK[1] = 'C';_DEBUG_LOG
                            nubo_info->ACK[2] = 'K';_DEBUG_LOG
                            nubo_info->ACK[3] = NUVO_SIGNAL_STATE_DONE_SAVEDATA;_DEBUG_LOG
                            memcpy(send_buf + 6, &nubo_info->ACK[0], 4);_DEBUG_LOG
                            int DNM = 9101112;_DEBUG_LOG
                            memcpy(send_buf + 6 + 4, &DNM, 4);_DEBUG_LOG
                            memcpy(send_buf + 6 + 4 + 4, &ETX, 1);_DEBUG_LOG
                            printf("\n");printf("[DRIVING HISTORY] " "\033[0;33m" "Press Any Key" "\033[0;0m" " to [Send Request Done Save Driving History] ...... %ld[s]\n", time(NULL) - now);while(getchar() != '\n');printf("\x1B[1A\r");_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Send Request Done Save Driving History] 'Request Done Save Driving History To NUVO' ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            ret = sendto(nubo_info->sock , send_buf, 11, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Send Request Done Save Driving History] Send Success ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Send Request Done Save Driving History] Send Data(Hex) ...... ");_DEBUG_LOG
                            Start_Save_Driving_History =  time(NULL) - now;_DEBUG_LOG
                            for(int k = 0; k < 15; k++)
                            {
                                if(k == 9)
                                {
                                    printf("\033[0;32m");_DEBUG_LOG
                                }else{
                                    printf("\033[0m");_DEBUG_LOG
                                }
                                printf("%02X ", send_buf[k]);_DEBUG_LOG
                            }
                            printf("\n");_DEBUG_LOG
                            Relay_safefree(send_buf); 
                            nubo_info->state = GW_WAIT_DRIVING_HISTORY_INFO_FROM_NOVO;_DEBUG_LOG
                        }else{
                            if(timer_100ms_tick % 10 == 0)
                            {
                                printf("[DRIVING HISTORY] Wating ECU Done Indication ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            }
                        }     
                        break;_DEBUG_LOG
                    }
                    case GW_WAIT_DRIVING_HISTORY_INFO_FROM_NOVO:
                    {
                        if(0)
                        {
                            printf("[DRIVING HISTORY] [Waiting Driving History Data Info] Response From NUVO  ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Waiting Driving History Data Info] Receive Success ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            printf("[DRIVING HISTORY] [Waiting Driving History Data Info] Receive Data(Hex) ...... ");_DEBUG_LOG
                            char hdr[6] = {0,};_DEBUG_LOG
                            hdr[0] = 0x43;_DEBUG_LOG
                            hdr[1] = 0x08;_DEBUG_LOG
                            int data_length = 256;_DEBUG_LOG
                            memcpy(&hdr[2], &data_length, 4);_DEBUG_LOG
                            char STX = 0x43;_DEBUG_LOG
                            char ETX = 0xAA;_DEBUG_LOG
                            char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));_DEBUG_LOG
                            memcpy(send_buf, hdr, 6);_DEBUG_LOG
                            nubo_info->ACK[0] = 'A';_DEBUG_LOG
                            nubo_info->ACK[1] = 'C';_DEBUG_LOG
                            nubo_info->ACK[2] = 'K';_DEBUG_LOG
                            nubo_info->ACK[3] = NUVO_SIGNAL_STATE_DOWNLOAD_PREPARE;_DEBUG_LOG
                            memcpy(send_buf + 6, &nubo_info->ACK[0], 4);_DEBUG_LOG
                            int Data_Length = 2781319;_DEBUG_LOG
                            memcpy(send_buf + 6 + 4, &Data_Length, 4);_DEBUG_LOG
                            memcpy(send_buf + 6 + 4 + 4, &ETX, 1);_DEBUG_LOG
                            for(int k = 0; k < 15; k++)
                            {
                                if(k == 9)
                                {
                                    printf("\033[0;32m");_DEBUG_LOG
                                }else{
                                    printf("\033[0m");_DEBUG_LOG
                                }                                    
                                printf("%02X ", send_buf[k]);_DEBUG_LOG
                            }
                            printf("\n"); 
                            nubo_info->state = GW_RECEIVE_DRIVING_HISTORY_DATA_FROM_NOVO;_DEBUG_LOG
                        }else{
                            if(timer_100ms_tick % 10 == 0)
                            {
                                printf("[DRIVING HISTORY] [Waiting Driving History Data Info] Waiting Start Upload Signal From Nuvo ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                            }
                        }     

                    }
                    case GW_RECEIVE_DRIVING_HISTORY_DATA_FROM_NOVO:
                    {
                        printf("\n");printf("[DRIVING HISTORY] " "\033[0;33m" "Press Any Key" "\033[0;0m" " to Recvive Driving History Data]...... %ld[s]\n", time(NULL) - now);while(getchar() != '\n');printf("\x1B[1A\r");_DEBUG_LOG
                        struct sockaddr_in from_adr;_DEBUG_LOG
                        socklen_t from_adr_sz;_DEBUG_LOG
                        char *recv_file_data = malloc(1);_DEBUG_LOG
                        int total_recv_len = 0;_DEBUG_LOG
                        time_t recv_end_time;;_DEBUG_LOG
                        printf("[DRIVING HISTORY] [Recvive Driving History Data] Start Recvive From NUVO ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                        while(1)
                        {
                            char recv_buf[MAX_UDP_RECV_DATA] = {0,};_DEBUG_LOG
                            int recv_len = 0;_DEBUG_LOG
                            recv_len = recvfrom(nubo_info->sock , recv_buf, MAX_UDP_RECV_DATA, 0, (struct sockaddr*)&from_adr, &from_adr_sz);_DEBUG_LOG
                            if(recv_len > 0)
                            {
                                printf("recv_buf:%d/%d\n", total_recv_len, file_data_len);_DEBUG_LOG
                                printf("\033[A");_DEBUG_LOG
                                total_recv_len += recv_len;_DEBUG_LOG
                                recv_file_data = realloc(recv_file_data, total_recv_len);_DEBUG_LOG
                                memset(recv_file_data + total_recv_len - recv_len, recv_buf, recv_len);_DEBUG_LOG
                                recv_end_time = time(NULL);_DEBUG_LOG
                            }else{
                                printf("\ntime:%ld\n", (time(NULL) - recv_end_time));_DEBUG_LOG
                                printf("\033[A");_DEBUG_LOG
                                if(time(NULL) - recv_end_time > 3)
                                {
                                    if(file_data_len >= total_recv_len)
                                    {
                                        printf("[DRIVING HISTORY] [Recvive Driving History Data] Finish Recvive From NUVO, Recvive Data Length : %d/%ld ...... %ld[s]\n", total_recv_len, file_data_len, time(NULL) - now);_DEBUG_LOG
                                    }
                                    break;_DEBUG_LOG
                                }
                            }
                        }
protobuf_data_info_t
{
    bool data_alloc;
    char *data;
    size_t data_len;
};
g_protobuf_data_t
{
    protobuf_data_info_t data_nubo;
    protobuf_data_info_t data_v2x;
    protobuf_data_info_t data_log_ecu;
    protobuf_data_info_t data_log_ide;
};
g_protobuf_data_t g_protobuf_data;

                        printf("\n");_DEBUG_LOG
                        #if 1 //20241010 PROTOBUF 병합 기능 추가
                        

                        #define NOVO_FILE_PATH "/home/root/Project_Relayserver/nubo_sample"
                        ret = access(NOVO_FILE_PATH, F_OK);_DEBUG_LOG
                        
                        char *file_path = malloc(sizeof(char) * strlen(file_name) + sizeof(NOVO_FILE_PATH));_DEBUG_LOG
                        sprintf(file_path, "%s/%s", NOVO_FILE_PATH, file_name);_DEBUG_LOG
                        printf("file_path:%s, %ld\n", file_path, strlen(file_path));_DEBUG_LOG
                        FILE *fp = fopen(file_path, "w+");_DEBUG_LOG
                       
                        for(int k = 0; k < file_data_len; k++)
                        {
                             if (fputc(recv_file_data[k], fp) == EOF) {
                                perror("Error writing to file");_DEBUG_LOG
                                fclose(fp);_DEBUG_LOG
                                return -1;_DEBUG_LOG
                            }
                        }
                        if(file_path)Relay_safefree(file_path);_DEBUG_LOG
                        if(recv_file_data)Relay_safefree(recv_file_data);_DEBUG_LOG
                        fclose(fp);_DEBUG_LOG
                        goto GW_JOB_BY_NUBO_DONE;_DEBUG_LOG

                        break;_DEBUG_LOG
                    }
                }
            }
            case 0:
            {
                switch(nubo_info->state)
                {
                    default:
                    {
                        goto No_GW_SLEEP_CONNECTIONING_NUVO;_DEBUG_LOG
                        break;_DEBUG_LOG
                    }
                    case GW_TRYING_CONNECTION_NUVO:
                    case GW_TRYING_CONNECTION_NUVO_REPEAT_1:
                    case GW_TRYING_CONNECTION_NUVO_REPEAT_2:
                    case GW_TRYING_CONNECTION_NUVO_REPEAT_3:
                    case GW_TRYING_CONNECTION_NUVO_REPEAT_4:
                    case GW_TRYING_CONNECTION_NUVO_REPEAT_5:
                    case GW_SLEEP_CONNECTIONING_NUVO:
                    {
                        srand(time(NULL));//Random 값의 Seed 값 변경
                        usleep(((rand() % 20) + 4) * 1000); // 매초 + 4~20ms의 랜덤값을 갖는 시간에 동작
                        char hdr[6] = {0,};_DEBUG_LOG
                        hdr[0] = 0x43;_DEBUG_LOG
                        hdr[1] = 0x08;_DEBUG_LOG
                        int data_length = 256;_DEBUG_LOG
                        memcpy(&hdr[2], &data_length, 4);_DEBUG_LOG
                        //char STX = 0x43;_DEBUG_LOG
                        char ETX = 0xAA;_DEBUG_LOG
                        char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));_DEBUG_LOG
                        memcpy(send_buf, hdr, 6);_DEBUG_LOG
                        nubo_info->ACK[0] = 'A';_DEBUG_LOG
                        nubo_info->ACK[1] = 'C';_DEBUG_LOG
                        nubo_info->ACK[2] = 'K';_DEBUG_LOG
                        nubo_info->ACK[3] = NUVO_SIGNAL_STATE_REQ_CONNECT;_DEBUG_LOG
                        memcpy(send_buf + 6, &nubo_info->ACK[0], 4);_DEBUG_LOG
                        memcpy(send_buf + 6 + 4, &ETX, 1);_DEBUG_LOG
                        printf("\n");printf("[DRIVING HISTORY] " "\033[0;33m" "Press Any Key" "\033[0;0m" " to [Send Request Connecting]...... %ld[s]\n", time(NULL) - now);while(getchar() != '\n');printf("\x1B[1A\r");_DEBUG_LOG
                        printf("[DRIVING HISTORY] [Send Request Connecting] 'Connecting To NUVO' ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                        ret = sendto(nubo_info->sock , send_buf, 11, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));_DEBUG_LOG
                        if(ret <= 0)
                        {
                            if(nubo_info->state != GW_TRYING_CONNECTION_NUVO)
                            {
                                nubo_info->state = GW_TRYING_CONNECTION_NUVO;_DEBUG_LOG
                            }else{
                                nubo_info->state++;_DEBUG_LOG
                                if(nubo_info->state == GW_TRYING_CONNECTION_NUVO_REPEAT_MAX)
                                {
                                    goto CONNECTION_REPEAT_MAX;_DEBUG_LOG
                                }
                            }
                            printf("[DRIVING HISTORY] [Send Request Connecting] 'Connecting To NUVO Error - Count:%d' ...... %ld[s]\n", nubo_info->state - GW_TRYING_CONNECTION_NUVO, time(NULL) - now);_DEBUG_LOG
                        }
                        printf("[DRIVING HISTORY] [Send Request Connecting] Send Success ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
                        printf("[DRIVING HISTORY] [Send Request Connecting] Send Data(Hex) ...... ");_DEBUG_LOG
                        for(int k = 0; k < 11; k++)
                        {
                            if(k == 9)
                            {
                                printf("\033[0;32m");_DEBUG_LOG
                            }else{
                                printf("\033[0m");_DEBUG_LOG
                            }
                            printf("%02X ", send_buf[k]);_DEBUG_LOG
                        }
                        printf("\n");_DEBUG_LOG
                        Relay_safefree(send_buf);_DEBUG_LOG
                        nubo_info->life_time = 0;_DEBUG_LOG
                        nubo_info->state = GW_WATING_REPLY_CONNECTION_FROM_NUVO;_DEBUG_LOG
                        break;_DEBUG_LOG
                    }
                }
                
                break;_DEBUG_LOG
            }
        }
        timer_100ms_tick = (timer_100ms_tick + 1) % 0xF0; 
    }


GW_JOB_BY_NUBO_DONE:

    printf("[DRIVING HISTORY] [Combine Start Driving History Data] ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG
    sleep(3);_DEBUG_LOG
    printf("[DRIVING HISTORY] [Combine Done Driving History Data] ...... %ld[s]\n", time(NULL) - now);_DEBUG_LOG


    printf("[DRIVING HISTORY] [Combine Done] File Name ...... %s\n", file_name);_DEBUG_LOG
    printf("[DRIVING HISTORY] [Combine Done] File Length ...... %ld[byte]\n", file_data_len);_DEBUG_LOG
    printf("\n");printf("[DRIVING HISTORY] " "\033[0;33m" "Press Any Key" "\033[0;0m" " to [Send DRIVING HISTORY DATA To Server] ...... File_Name:" "\033[0;31m" "%s" "\033[0;0m" "\n", file_name);while(getchar() != '\n');printf("\x1B[1A\r");_DEBUG_LOG
    char cmd[256] = {0,};_DEBUG_LOG
    char *url_nuvo = "https://itp-self.wtest.biz//v1/system/firmwareUpload.php";_DEBUG_LOG

    sprintf(cmd, "curl -F file=@example.httpbody -F title=./nubo_sample/%s %s > /dev/null", file_name, url_nuvo); //nubo_sample/2024610_044658_000.zip
    system(cmd);_DEBUG_LOG
    memset(cmd, 0x00, 256);_DEBUG_LOG
    sleep(2);_DEBUG_LOG
    
CONNECTION_REPEAT_MAX:

    if(nubo_info->state == GW_TRYING_CONNECTION_NUVO_REPEAT_MAX)
    {
        *nubo_info->task_info_state = -15;_DEBUG_LOG
        close(nubo_info->sock);_DEBUG_LOG
    }else{
        *nubo_info->task_info_state = 2;_DEBUG_LOG
        close(nubo_info->sock);_DEBUG_LOG
        *nubo_info->task_info_state = 0;_DEBUG_LOG
        Relay_safefree(nubo_info->task_info_state);_DEBUG_LOG
    }
    

}

 int wait_on_socket(curl_socket_t sockfd, int for_recv, long timeout_ms)
{
  struct timeval tv;_DEBUG_LOG
  fd_set infd, outfd, errfd;_DEBUG_LOG
  int res;_DEBUG_LOG
 
  tv.tv_sec = timeout_ms / 1000;_DEBUG_LOG
  tv.tv_usec = (int)(timeout_ms % 1000) * 1000;_DEBUG_LOG
 
  FD_ZERO(&infd);_DEBUG_LOG
  FD_ZERO(&outfd);_DEBUG_LOG
  FD_ZERO(&errfd);_DEBUG_LOG
 
  FD_SET(sockfd, &errfd); /* always check for error */
 
  if(for_recv) {
    FD_SET(sockfd, &infd);_DEBUG_LOG
  }
  else {
    FD_SET(sockfd, &outfd);_DEBUG_LOG
  }
 
  /* select() returns the number of signalled sockets or -1 */
  res = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);_DEBUG_LOG
  return res;_DEBUG_LOG
}


 int f_i_RelayServer_HTTP_Check_URL(const char *url) {
    CURL *curl;_DEBUG_LOG
    CURLcode res;_DEBUG_LOG
    long response_code = 0;_DEBUG_LOG

    // curl 초기화
    curl = curl_easy_init();_DEBUG_LOG
    if(curl) {
        // URL 설정
        curl_easy_setopt(curl, CURLOPT_URL, url);_DEBUG_LOG
        // 응답을 받지 않게 설정
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // HEAD 요청만 보냄
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS , 1000);_DEBUG_LOG
        // 요청 실행
        res = curl_easy_perform(curl);_DEBUG_LOG

        // 요청이 성공했는지 확인
        if (res == CURLE_OK) {
            // HTTP 응답 코드 확인
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);_DEBUG_LOG

            if (response_code == 200) {
                printf("URL is valid and reachable: %ld\n", response_code);_DEBUG_LOG
            } else {
                printf("URL is not reachable, HTTP response code: %ld\n", response_code);_DEBUG_LOG
            }
        } else {
            printf("URL:%s\n", url);_DEBUG_LOG
            printf("curl_easy_perform() URL:%s, failed: \n%s\n", curl_easy_strerror(res), url);_DEBUG_LOG
        }

        // curl 정리
        curl_easy_cleanup(curl);_DEBUG_LOG
        curl_global_cleanup();_DEBUG_LOG
        
    }

    return (res == CURLE_OK && response_code == 200) ? 1 : 0;  // 1 = valid, 0 = invalid
}

#define _V2X_ENABLE 1
#if _V2X_ENABLE

#define S_HOSTNAME "192.168.1.50" //OBU IP
#define S_PORT    63113 

#define MYHOSTNAME "192.168.1.100" //Autonomous Vehicle Data Receive Socket IP
#define MYPORT    63113 


static void Debug_Msg_Print_Data(int msgLv, unsigned char* data, int len)
{
    int rep;
    if(msgLv <= 3)
    {
		printf("\n\t (Len : 0x%X(%d) bytes)", len, len);
		printf("\n\t========================================================");
		printf("\n\t Hex.   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
		printf("\n\t--------------------------------------------------------");
		for(rep = 0 ; rep < len ; rep++)
		{
			if(rep % 16 == 0) printf("\n\t %03X- : ", rep/16);
			printf("%02X ", data[rep]);
		}
		printf("\n\t========================================================");
		printf("\n\n");
    }
}

typedef struct
{
	unsigned short MagicKey;
	unsigned char MsgType;
	unsigned short crc;
	unsigned short PacketLen;

} __attribute__((__packed__)) Msg_Header;
typedef struct 
{
	Msg_Header header;
	unsigned char MsgCount; //1byte
	char TmpID[4];     //4byte -> 4byte
	unsigned short DSecond; //2byte
	int Latitude;
	int Longitude;
	short Elevation; //2byte

	//unsigned int postionalAccuracy; //4byte -> 4byte
	unsigned char SemiMajor;
	unsigned char SemiMinor;
	unsigned short Orientation;

	unsigned short TransmissionState; //2byte
	short heading;
	unsigned char SteeringWheelAngle;

	//unsigned char AccelerationSet4Way[7]; //7byte -> 7byte
	short Accel_long;
	short  Accel_lat;
	unsigned char Accel_vert;
	short YawRate;
	
	unsigned short BrakeSystemStatus;

	//unsigned char VehicleSize[3]; //3byte -> 4byte
	unsigned short Width;
	unsigned short Length;

	unsigned int L2id; //Add 4byte 
} __attribute__((__packed__)) BSM_Core;  
typedef struct
{
	Msg_Header header;
	unsigned int Sender;	
	unsigned int Receiver; //ADD receivder, for broadcast Receivdr = FFFFFFFF, for unciast Receiver = L2ID
	unsigned short ManeuverType;
	unsigned char RemainDistance;

} __attribute__((__packed__)) DMM; // Driving Maneuver Message(3) 
typedef struct
{
	Msg_Header header;
	unsigned int Sender;	
	unsigned int Receiver;
	unsigned char RemainDistance;
} __attribute__((__packed__)) DNM_Req; 
typedef struct
{
	Msg_Header header;
	unsigned int Sender;	
	unsigned int Receiver;
	unsigned char AgreeFlag; //Agreement 1 (default), disagreement (0)
} __attribute__((__packed__)) DNM_Res; 
typedef struct
{
	Msg_Header header;
	unsigned int Sender;	
	unsigned int Receiver;
	unsigned char NegoDone; //Default 0, Negotiation ing 1, Done 2
} __attribute__((__packed__)) DNM_Done; 


extern void *Th_RelayServer_V2X_UDP_Task(void *arg)
{
    arg = (void*)arg;

    int recv_sock, send_sock;
    struct sockaddr_in recv_addr, send_addr;

    recv_sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    send_sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);

    bzero(&recv_addr,sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = inet_addr(MYHOSTNAME);
    recv_addr.sin_port = htons(S_PORT);
    bind(recv_sock, (struct sockaddr*) &recv_addr, sizeof(recv_addr));

    bzero(&send_addr,sizeof(send_addr));
    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr = inet_addr(S_HOSTNAME);
    send_addr.sin_port = htons(S_PORT);

    struct linger solinger = { 1, 0 };  /* Socket FD close when the app down. */
    setsockopt(recv_sock, SOL_SOCKET, SO_LINGER, &solinger, sizeof(struct linger));
    setsockopt(send_sock, SOL_SOCKET, SO_LINGER, &solinger, sizeof(struct linger));

    struct timeval t_val={1, 0}; //sec, msec
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &t_val, sizeof(t_val));
    setsockopt(send_sock, SOL_SOCKET, SO_SNDTIMEO, &t_val, sizeof(t_val));

    int ret_recv, ret_send, recv_len;

    while(1)
    {
        struct sockaddr_in client_addr;
        bzero(&client_addr,sizeof(client_addr));
        char msg[1024] = {0,};
        ret_recv = recvfrom(recv_sock, (char*)msg, 1024, 0, (struct sockaddr *)&client_addr, &recv_len);
        char temp_sendr_id[4] = {0x00, 0x22, 0x55, 0x33};
        if(ret_recv > 0)
        {
            printf("[DEBUG] recvfrom() UDP read len : %d\n", recv_len);
            Debug_Msg_Print_Data(2, (char*)msg, recv_len);

            Msg_Header *t_msg_hdr = (Msg_Header *)msg;
            #if 1
                printf("[DEBUG] t_msg_hdr->MagicKey = %04X\n", t_msg_hdr->MagicKey);
            #endif
            
            if(t_msg_hdr->MagicKey == 0xF1F1)
            {
                DNM_Req *t_msg_req =(DNM_Req *)msg;
                printf("[DEBUG] t_msg_hdr->MsgType = %d\n", t_msg_hdr->MsgType);
                printf("[DEBUG] t_msg_hdr->PacketLen = %d\n", t_msg_hdr->PacketLen);

                switch(t_msg_req->header.MsgType)
                {
                    default:
                    {
                        printf("[DEBUG] t_msg_hdr->MsgType = %d\n", t_msg_hdr->MsgType);
                        break;
                    }
                    case 4://DNM_REQ
                    {
                        printf("[DEBUG] t_msg_req->Sender = %08X\n", t_msg_req->Sender);
                        printf("[DEBUG] t_msg_req->Receiver = %08X\n", t_msg_req->Receiver);
                        printf("[DEBUG] t_msg_req->RemainDistance = %02X\n", t_msg_req->RemainDistance);
                        char send_buf[1024] = {0,};
                        DNM_Res *t_msg_res =(DNM_Res *)send_buf;
                        t_msg_res->header.MagicKey = 0xF1F1;
                        t_msg_res->header.MsgType = 5;
                        t_msg_res->header.PacketLen = htons(sizeof(DNM_Res));
                        
                        memcpy(&t_msg_res->Sender, temp_sendr_id, 4);
                        t_msg_res->Receiver = t_msg_res->Sender;
                        //t_msg_req->Receiver = htonl(11);
                        t_msg_res->AgreeFlag = 0;//Default - Agreement 1, Disagreement 0
                        
                        ret_send = sendto(send_sock, (char*)send_buf, ntohs(t_msg_res->header.PacketLen), 0, (struct sockaddr*)&send_addr, sizeof(send_addr));
                        if(ret_send < 0)
                        {
                            printf("[DEBUG] Send Error ! :%d\n", ret_send);
                        }else{
                            printf("[DEBUG] Send Sucess ! :%d\n", ret_send);
                            Debug_Msg_Print_Data(3, (char*)send_buf, ntohs(t_msg_res->header.PacketLen));	
                        }

                        break;
                    }
                    case 1://ETRI_TYPE_BSM_NOTI
                    {

                        break;
                    }
                    case 2://ETRI_TYPE_PIM_NOTI
                    {
                        break;
                    }
                }
               
            }
        }

    }

    return (void*)NULL;
}



#endif