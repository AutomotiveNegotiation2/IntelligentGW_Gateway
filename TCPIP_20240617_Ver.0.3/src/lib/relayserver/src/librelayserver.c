  /* LIBRARY Source */
#include <./librelayserver.h>

#define DEBUG_1 printf("[DEBUG][%s][%d]\n", __func__, __LINE__);

/* 
Brief:
Parameter[In]
Parameter[Out]
    socket_info_t
 */
struct socket_info_t F_s_RelayServer_TcpIp_Initial_Server(char *Device_Name, int *Port, int *err)
{
    int ret = 0;
    struct socket_info_t Socket_Info;
    //Check Argurements
    if(!Port)
    {
        F_RealyServer_Print_Debug(0, "[Error][%s] No Input Argurements.(Port:%p)\n", __func__, Port);
        *err = -1;
        return Socket_Info;
    }else{
        Socket_Info.Socket_Type = SERVER_SOCKET;
        Socket_Info.Port = *Port;
    
        if(Device_Name)
        {
            //Getting the Ethernet Device IP Address  
            ret = F_i_RelayServer_TcpIp_Get_Address(Socket_Info.Device_Name, Socket_Info.Device_IPv4_Address);
            if(ret < 0)
            {
                F_RealyServer_Print_Debug(0,"[Error][%s] Return_Value:%d\n", __func__, ret);
                *err = -1;
                return Socket_Info;
            }
            Socket_Info.Device_Name = Device_Name;
            Socket_Info.Socket_Addr.sin_addr.s_addr = inet_addr(Socket_Info.Device_IPv4_Address);
        }else 
        {
            
            Socket_Info.Device_Name = malloc(sizeof(uint8_t) * 10);
            Socket_Info.Device_Name = "INADDR_ANY";
            Socket_Info.Socket_Addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        Socket_Info.Socket = socket(AF_INET, SOCK_STREAM, 0);
        //Socket_Setup
        ret = f_i_RelayServer_TcpIp_Setup_Socket(&Socket_Info.Socket, 10, true);
        if(ret < 0)
        {
            F_RealyServer_Print_Debug(0,"[Error][%s] Return_Value:%d\n", __func__, ret);
            *err = -1;
            return Socket_Info;
        }

        memset(&Socket_Info.Socket_Addr, 0x00, sizeof(Socket_Info.Socket_Addr));  
        Socket_Info.Socket_Addr.sin_family = AF_INET;  
        Socket_Info.Socket_Addr.sin_port = htons(Socket_Info.Port);
    }

    return Socket_Info;
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
    int ret = 0;

    //Check Argurement
    if(!Device_Name)
    {
        F_RealyServer_Print_Debug(0, "[Error][%s] No Input Argurements.(Device_Name:%p)\n", __func__, Device_Name);
        return -1;
    }

    /* Use the Ethernet Device Name to find IP Address at */
	struct ifreq ifr;
	int IP_Parsing_Socket;
    
	IP_Parsing_Socket = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, Device_Name, IFNAMSIZ);

	if (ioctl(IP_Parsing_Socket, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, Output_IPv4Adrress, sizeof(struct sockaddr));
		F_RealyServer_Print_Debug(1, "[Info][%s] %s IP Address is %s\n", __func__, Device_Name, Output_IPv4Adrress);
	}
    ret = f_i_RelayServer_TcpIp_Setup_Socket(&IP_Parsing_Socket, 100, true);
    if(ret < 0)
    {
        return -1;
    }
	close(IP_Parsing_Socket);
    return  0;
}
/* 
Brief:
Parameter[In]
Parameter[Out]
 */
int F_i_RelayServer_TcpIp_Task_Run(struct socket_info_t *Socket_Info)
{
    int ret;
    ret = f_i_RelayServer_TcpIp_Bind(&Socket_Info->Socket, Socket_Info->Socket_Addr);
    if(ret < 0)
    {
            F_RealyServer_Print_Debug(0, "[Error][%s][f_i_RelayServer_TcpIp_Bind] Return Value:%d", __func__, ret);
    }else{
        pthread_create(&(Socket_Info->Task_ID), NULL, th_RelayServer_TcpIp_Task_Server, (void*)Socket_Info);  
        pthread_detach((Socket_Info->Task_ID));
        F_RealyServer_Print_Debug(1, "[Sucess][%s][Task_ID:%ld]\n", __func__, Socket_Info->Task_ID);

    }
    return 0;
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
                //F_RealyServer_Print_Debug(6,"[Debug][%s][%d][Pop_Data:%s/%d][%d]\n", __func__, __LINE__, out_data, data_size, (size_t)*(Data_Info->Data_Count));
                    if(out_data)
                    {
                        struct data_header_info_t Data_Header_Info = f_s_Parser_Data_Header((char*)out_data, HEADER_SIZE);
                        F_RealyServer_Print_Debug(6,"[Debug][%s][%d][Client:%u]\n", __func__, __LINE__, Data_Header_Info.Client_fd);
                        enum job_type_e Now_Job;
                        if(*G_Clients_Info.connected_client_num > 0)
                        { 
                            for(int client_is = 0; client_is < MAX_CLIENT_SIZE; client_is++)
                            {
                                if(G_Clients_Info.socket[client_is] == Data_Header_Info.Client_fd)
                                {
                                    Now_Job = f_e_RelayServer_Job_Process_Do(&Data_Header_Info, &out_data, client_is, Data_Info);
                                    F_RealyServer_Print_Debug(6,"[Info][%s] Now_Job:%d\n", __func__, Now_Job);
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
                                            F_RealyServer_Print_Debug(1,"[Info][%s] Now_Job:%d\n", __func__, Now_Job);
                                            F_RealyServer_Print_Debug(5,"[Debug][%s][%d][Push:%s/%d]\n", __func__, __LINE__, out_data, data_size);
                                            F_i_Memory_Data_Push(Data_Info, out_data, data_size);
                                            break;

                                        case FirmwareInfoRequest:
                                        case ProgramInfoRequest:
                                        case Finish:
                                            F_RealyServer_Print_Debug(1,"[Info][%s] Now_Job:%d\n", __func__, Now_Job);
                                            break;
                                        default:
                                            F_RealyServer_Print_Debug(1,"[Info][%s] Now_Job:%d\n", __func__, Now_Job);
                                            break; 
                                    }  
                                    break;
                                }else{
                                        if(0)//(client_is == *G_Clients_Info.connected_client_num - 1)
                                        {
                                            F_RealyServer_Print_Debug(1, "[Debug][%s][Client Closed:%d]\n", __func__, G_Clients_Info.socket[client_is]);
                                            F_RealyServer_Print_Debug(1, "[Debug][%s][Client Closed:%d]\n", __func__, Data_Header_Info.Client_fd);
                                        }
                                }
                            }
                        }
                        
                        F_RealyServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, out_data);
                        free(out_data);
                    }
                
                }
            }
        }


    }
}

int f_i_Hex2Dec(char data)
{
    int ret;
    if(48 <= (int)(data)  && (int)(data)  <= 57){
        ret = (int)(data) - 48;
    }else if(65 <= (int)(data)  && (int)(data)  <= 70)
    {
        ret = (int)(data) - 65 + 10;
    }else if(97 <= (int)(data)  && (int)(data)  <= 102)
    {
        ret = (int)(data)- 97 + 10;
    }
    return ret;
}

struct data_header_info_t f_s_Parser_Data_Header(char *Data, size_t Data_Size)
{
    struct data_header_info_t out_data;
    int Data_Num = 0;
    for(int i = 0; i < 4; i++)
    {
        switch(Data_Num)
        {
            case 0:
                out_data.Job_State = f_i_Hex2Dec(Data[0]);
                out_data.Protocol_Type = f_i_Hex2Dec(Data[1]);
                break;
            case 1:
                out_data.Client_fd = 0;
                for(int i = 0; i < 8; i++)
                {
                    out_data.Client_fd = out_data.Client_fd * 16 + f_i_Hex2Dec(Data[2 + i]);
                }
                break;
            case 2:
                out_data.Message_seq = f_i_Hex2Dec(Data[10]) * 16 + f_i_Hex2Dec(Data[11]);
                break;
            case 3:
                out_data.Message_size = 0;
                for(int i = 0; i < 4; i++)
                {
                    out_data.Message_size = out_data.Message_size * 16 + f_i_Hex2Dec(Data[12 + i]);
                }
                break;
            default:
                break;
        }
        Data_Num++;
    }
    return out_data;
}

void* th_RelayServer_TcpIp_Task_Server(void *socket_info)
{
    int ret, i;
    struct socket_info_t *Socket_Info = (struct socket_info_t*)socket_info;
    int Client_Socket;
    struct sockaddr_in  Client_Address;
    socklen_t adr_sz = sizeof(Client_Address);

    ret = listen(Socket_Info->Socket, 5);
    if(ret == -1)
    {
        F_RealyServer_Print_Debug(0,"[Error][%s][listen] Return Value:%d\n", __func__, ret);
        return NULL;
    }
    pthread_mutex_init(&G_Clients_Info.mtx, NULL);
    int epoll_size = MAX_CLIENT_SIZE + 1;
    int epoll_event_count;
    struct epoll_event *epoll_events= malloc(sizeof(struct epoll_event)*epoll_size);


	int epfd = epoll_create(epoll_size);

	struct epoll_event epoll_event;
    epoll_event.events = EPOLLIN;
	epoll_event.data.fd = Socket_Info->Socket;	
	epoll_ctl(epfd, EPOLL_CTL_ADD, Socket_Info->Socket, &epoll_event);

    uint32_t init_time = G_TickTimer.G_100ms_Tick;
    int str_len;
    int client_is, client_count;
    char *buf = malloc(TCP_RECV_BUFFER_SIZE);
    while(1)
    {
        epoll_event_count = epoll_wait(epfd, epoll_events, epoll_size, 10);
		if(epoll_event_count < 0)
		{
			F_RealyServer_Print_Debug(6, "[Error][%s][epoll_wait() error]", __func__);
			break;
		}
		for(i = 0; i < epoll_event_count; i++)
		{
			if(epoll_events[i].data.fd == Socket_Info->Socket)
			{
				Client_Socket = accept(Socket_Info->Socket, (struct sockaddr*)&Client_Address, &adr_sz);
                 if(Client_Socket > 0)
                {               
                    ret = f_i_RelayServer_TcpIp_Setup_Socket(&Client_Socket, 10, true);
                    if(ret < 0)
                    {
                        F_RealyServer_Print_Debug(0,"[Error][%s] Return_Value:%d\n", __func__, ret);
                        return Socket_Info;
                    }
                    if(*G_Clients_Info.connected_client_num == MAX_CLIENT_SIZE)
                    {
                        F_RealyServer_Print_Debug(0,"[Error][%s][%d] Connected Client Num > MAX_CLIENT_SIZE:%d/%d\n", __func__, __LINE__, *G_Clients_Info.connected_client_num, MAX_CLIENT_SIZE);
                        close(epoll_events[i].data.fd);
                    }else{
                        
                        for(client_is = 0; client_is < MAX_CLIENT_SIZE; client_is++)
                        {
                            
                            if(G_Clients_Info.socket[client_is] == 0)
                            {
                                pthread_mutex_lock(&G_Clients_Info.mtx);
                                G_Clients_Info.socket[client_is] = Client_Socket;
                                G_Clients_Info.Life_Timer[client_is] = G_TickTimer.G_100ms_Tick + SOCKET_TIMER;
                                G_Clients_Info.socket_message_seq[client_is] = 0;
                                *G_Clients_Info.connected_client_num = *G_Clients_Info.connected_client_num + 1;
                                pthread_mutex_unlock(&G_Clients_Info.mtx);
                                break;
                            }
                        }
                        
                    }  
                    epoll_event.events = EPOLLIN;
                    epoll_event.data.fd = Client_Socket;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, Client_Socket, &epoll_event);
                    F_RealyServer_Print_Debug(6,"[Sucess][%s] Client_Socket:%u[%d]\n", __func__, G_Clients_Info.socket[client_is], client_is);
                }else{
                    F_RealyServer_Print_Debug(1,"[Error][%s] Return Value:%d\n", __func__, Client_Socket);
                }
			}else{
                str_len = read(epoll_events[i].data.fd, buf, TCP_RECV_BUFFER_SIZE);
                if(str_len > 0)
                {
                    pthread_mutex_lock(&G_Clients_Info.mtx);
                    client_count = 0;
                    for(client_is = 0; client_is < MAX_CLIENT_SIZE; client_is++)
                    {
                        if(G_Clients_Info.socket[client_is] != 0)
                        {
                            client_count++;
                        }
                        if(G_Clients_Info.socket[client_is] == epoll_events[i].data.fd)
                        {
                            break;
                        }else{
                            if(client_count == *G_Clients_Info.connected_client_num)
                            {
                                client_is = -1;
                                break;
                            }
                        }
                    }
                    if(client_is >= 0)
                    {
                        G_Clients_Info.socket_message_seq[client_is]++;
                        uint8_t *push_data = malloc(sizeof(uint8_t) * (str_len + HEADER_SIZE));
                        sprintf((char*)push_data, HEADER_PAD,  //Client Data Protocol(Header:Hex_Sring,Payload:OCTETs)
                        0x0, //:job_state(1)
                        0x1, //protocol_type(1)
                        epoll_events[i].data.fd, //client_fd(8)
                        G_Clients_Info.socket_message_seq[client_is], //message_seq(2);
                        str_len - 1);//message_size(2);
                        strncat((char*)push_data, buf, str_len);//data(payload_size)
                        F_RealyServer_Print_Debug(6,"[Debug][%s][%d][Push_Data:%s/%d]\n", __func__, __LINE__, push_data, str_len + HEADER_SIZE);
                        size_t left_buf = F_i_Memory_Data_Push(&G_Data_Info, (void *)push_data, str_len + HEADER_SIZE);
                        pthread_mutex_unlock(&G_Clients_Info.mtx);
                        memset(buf, 0x00, TCP_RECV_BUFFER_SIZE);
                        F_RealyServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, push_data);
                        free(push_data);
                        if(left_buf >= 0)
                        {
                            F_RealyServer_Print_Debug(2,"[Info][%s] Left_Buffer_Size:%ld\n", __func__, left_buf);
                        }else{
                            F_RealyServer_Print_Debug(2,"[Error][%s] No left buffer:%ld\n", __func__, left_buf);
                            
                        }
                    }
                }else if(str_len == 0)
                {
                    if(0)//(G_Clients_Info.socket[epoll_events[i].data.fd] != 0)
                    {
                        epoll_ctl(epfd, EPOLL_CTL_DEL, epoll_events[i].data.fd, NULL);
                        F_RealyServer_Print_Debug(7,"[Debug][%s][close:%d, socket:%p]\n", __func__, __LINE__, epoll_events[i].data.fd);
                        close(epoll_events[i].data.fd);
                    }
                }
            }
        }
#if 1
        if(1)//(init_time + 1 < G_TickTimer.G_100ms_Tick)
        {
            init_time = G_TickTimer.G_100ms_Tick;
            for(int i = 0; i < MAX_CLIENT_SIZE; i++)
            {   
                if(G_Clients_Info.socket[i] == Socket_Info->Socket)
                {
                }else if(G_Clients_Info.socket[i]  != 0)
                {   
                    if(G_Clients_Info.Life_Timer[i] <= G_TickTimer.G_100ms_Tick)
                    {
                        F_RealyServer_Print_Debug(7,"[Debug][%s][close:%d, Timer:%d/%d, socket:%d]\n", __func__, __LINE__, G_Clients_Info.Life_Timer[i] ,G_TickTimer.G_100ms_Tick ,G_Clients_Info.socket[i]);
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
                        epoll_ctl(epfd, EPOLL_CTL_DEL, G_Clients_Info.socket[i], NULL);
                        close(G_Clients_Info.socket[i]);  
                    }
                }
            }
        }
#endif
    }
    printf("While_Loop_Broken!%d\n", __LINE__);
    return;
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
    int ret, Retry_Count;
    int Retry_Max = 10;
    do
    {
        ret = bind(*Server_Socket, (struct sockaddr*)&(Socket_Addr), sizeof(Socket_Addr));
        if(ret < 0 ) 
        {
            F_RealyServer_Print_Debug(0, "[Error][%s][Return_Value:%d]", __func__, ret);
            if(Retry_Count == Retry_Max)
            {
                close(*Server_Socket);
                return -1;
            }
            Retry_Count++;

            sleep(1);
        }else{
            char addr_str[40];
            inet_ntop(AF_INET, (void *)&Socket_Addr.sin_addr, addr_str, sizeof(addr_str));
            F_RealyServer_Print_Debug(1, "[Sucess][%s]\
            Server_Socket:%d;\
            Ip:Port:%s:%d\n",\
             __func__, *Server_Socket, addr_str, Socket_Addr.sin_port);
            return 0;
        }
    }while(Retry_Count < 10);
    return 0;
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
        F_RealyServer_Print_Debug(0, "[Error][%s][No Input Argurements.](Socket:%p, Timer:%d)\n", __func__, Socket, Timer);
        return -1;
    }
    if(Linger)
    {
        struct linger solinger = { 1, 0 };  /* Socket FD close when the app down. */
        if (setsockopt(*Socket, SOL_SOCKET, SO_LINGER, &solinger, sizeof(struct linger)) == SO_ERROR) {
            perror("setsockopt(SO_LINGER)");
            return -3;
        }
    }
    if(Timer > 0)
    {
        struct timeval tv;                  /* Socket Connection End Timer */           
        tv.tv_sec = (int)(Timer / 1000);
        tv.tv_usec = (Timer % 1000) * 1000; 
        if (setsockopt(*Socket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) == SO_ERROR) {
            perror("setsockopt(SO_RCVTIMEO)");
            return -2;
        }
        if (setsockopt(*Socket, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) == SO_ERROR) {
            perror("setsockopt(SO_SNDTIMEO)");
            return -1;
        }
    }
    return 0;
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
void F_RealyServer_Print_Debug(enum debug_lever_e Debug_Level, const char *format, ...)
{

  if(Debug_Level == 6)
  {
    va_list arg;
    struct timespec ts;
    struct tm tm_now;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r((time_t *)&ts.tv_sec, &tm_now);
    fprintf(stderr, "[%04u%02u%02u.%02u%02u%02u.%06ld]", tm_now.tm_year+1900, tm_now.tm_mon+1, tm_now.tm_mday, \
            tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, ts.tv_nsec / 1000);
    va_start(arg, format);
    vprintf(format, arg);
    va_end(arg);
  }else{
    return;
  }
}

/* 
Brief:
Parameter[In]
Parameter[Out]
 */
void* Th_i_RelayServer_TickTimer(void *Data)
{
    Data = Data;
    int ret;
    // Using_Timer
    int32_t TimerFd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec itval;
    struct timespec tv;
    uint32_t usec = 10 * 1000;
    uint64_t res;

    clock_gettime(CLOCK_MONOTONIC, &tv); 
    itval.it_interval.tv_sec = 0;
    itval.it_interval.tv_nsec = (usec % 1000000) * 1e3;
    itval.it_value.tv_sec = tv.tv_sec + 1;
    itval.it_value.tv_nsec = 0;
    ret = timerfd_settime (TimerFd, TFD_TIMER_ABSTIME, &itval, NULL);

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
enum job_type_e f_e_RelayServer_Job_Process_Do(struct data_header_info_t *Now_Hader, uint8_t **Data, int Client_is, struct Memory_Used_Data_Info_t *Data_Info)
{
    int ret;
    enum job_type_e Now_Job_State = Now_Hader->Job_State;
    enum job_type_e After_Job_State;

    switch(Now_Job_State)
    {
        case Initial: // Now_Job_State:0
            G_Clients_Info.client_data_info[Client_is] = f_s_RelayServer_Job_Process_Initial(Now_Hader, *Data, &ret);
            printf("f_s_RelayServer_Job_Process_Initial:%d\n", ret);
            break;
        case FirmwareInfoReport:// Now_Job_State:2
        case ProgramInfoReport: // Now_Job_State:7
            ret = f_i_RelayServer_Job_Process_InfoReport(Now_Hader, *Data);
            printf("f_i_RelayServer_Job_Process_InfoReport:%d\n", ret);
            if(ret < 0)
            {
                break;
            }
        case FirmwareInfoRequest: // Now_Job_State:3
        case ProgramInfoRequest:  // Now_Job_State:8
            ret = f_i_RelayServer_Job_Process_InfoRequest(Now_Hader, Data, Data_Info);
            printf("f_i_RelayServer_Job_Process_InfoRequest:%d\n", ret);
            
            break;
        case FirmwareInfoResponse:// Now_Job_State:4
        case ProgramInfoResponse: // Now_Job_State:9
            ret = f_i_RelayServer_Job_Process_InfoResponse(Now_Hader, Data);
            printf("f_i_RelayServer_Job_Process_InfoResponse:%d\n", ret);
            break;
        case FirmwareInfoIndication:// Now_Job_State:5
        case ProgramInfoIndication:// Now_Job_State:11
            ret = f_i_RelayServer_Job_Process_InfoIndication(Now_Hader, Data);
            printf("f_i_RelayServer_Job_Process_InfoIndication:%d\n", ret);
            break;
        case Finish: // Now_Job_State:1
            ret = f_i_RelayServer_Job_Process_Finish(Now_Hader, *Data, Client_is);
            break;
        case HandOverReminingData:
            //f_s_RelayServer_Job_Process_HandOverReminingData()
            break;
        default:break;
    }
    
    if(ret > 0)
    {
        After_Job_State = ret;
    }else{
        After_Job_State = 1;
    }
    if(Now_Job_State == After_Job_State)
    {
     
    }else{
        Now_Hader->Job_State = After_Job_State;
        G_Clients_Info.socket_job_state[Client_is] = After_Job_State;
    }

    return After_Job_State;
}

/* 
Brief:
Parameter[In]
    Now_Hader:
    Data:
    err:
Parameter[Out]
    client_data_info_t:It is made by the function 
 */
struct client_data_info_t f_s_RelayServer_Job_Process_Initial(struct data_header_info_t *Now_Hader, uint8_t *Data, int *err)
{
    struct client_data_info_t out_data;
    if(Data)
    {
        uint8_t *Payload = (Data + HEADER_SIZE); 
        if(Payload[0] == 0x44) // Check STX
        {
            switch((int)Payload[1])
            {
                case 1:
                    if(Now_Hader->Message_size  + 1 > 19) //Will Make the Over Recv Error Solution
                    {

                    }
                    out_data.Payload_Type = Fireware;
                    Now_Hader->Job_State = 2;
                    Data[0] = *("2");
                    *err = Now_Hader->Job_State;
                    break;
                case 3:
                    if(Now_Hader->Message_size + 1  > 19) //Will Make the Over Recv Error Solution
                    {
                        F_RealyServer_Print_Debug(6, "[Error][%s][Payload_type:%c]\n", __func__, Payload[1]);
                    }
                    out_data.Payload_Type = Program;
                    Now_Hader->Job_State = 7;
                    Data[0] = *("7");
                    *err = Now_Hader->Job_State;
                    break;
                default:
                    F_RealyServer_Print_Debug(6, "[Error][%s][Payload_type:%c]\n", __func__, Payload[1]);
                    *err = -1;
                    return out_data;

            }
            memcpy((out_data.ID), Payload + 2, 8);
            memset((out_data.Division), 0x0A, 1);
            memcpy((out_data.Version), Payload + 10, 8);
        }else{
            Now_Hader->Job_State = 1;
            *err = Now_Hader->Job_State;
        }
        
    }
    return out_data;
}

/* 
Brief:
Parameter[In]
    Now_Hader:
    Data:
    Client_is:
Parameter[Out]
    int 0 < Return Error Code
 */
int f_i_RelayServer_Job_Process_Finish(struct data_header_info_t *Now_Hader, uint8_t *Data, int Client_is)
{
    if(Data)
    {
        switch(Now_Hader->Job_State)
        {
            case Finish:
                pthread_mutex_lock(&G_Clients_Info.mtx);
                G_Clients_Info.socket_job_state[Client_is] = -1;
                pthread_mutex_unlock(&G_Clients_Info.mtx);
                break;
            default:
                break;
        }
    }else{
        F_RealyServer_Print_Debug(0, "[Error][%s][No Data]\n", __func__);
        return -1;
    }
    return 0;
}

/* 
Brief:
Parameter[In]
    Now_Hader:
    Data:
Parameter[Out]
    int 0 < Return Error Code
 */
int f_i_RelayServer_Job_Process_InfoReport(struct data_header_info_t *Now_Hader, uint8_t *Data)
{
    if(Data)
    {
        uint8_t *Payload = (Data + HEADER_SIZE); 

        if(Payload[0] == 0x44) // Check STX
        {
            switch(Now_Hader->Job_State)
            {
                case FirmwareInfoReport:
                    if(Now_Hader->Message_size + 1 == 19 && Payload[Now_Hader->Message_size] == 0xAA)
                    {
                        Now_Hader->Job_State = 3;
                        Data[0] = *"3";
                        F_RealyServer_Print_Debug(2, "[Info][%s][Job_State:%d, STX:%02X ETX:%02X]\n",__func__, Now_Hader->Job_State, Payload[0], Payload[Now_Hader->Message_size]);
                        return Now_Hader->Job_State;
                    }else{
                        F_RealyServer_Print_Debug(0, "[Error][%s][Now_Hader->Message_size:%d, ETX:%02X]\n",__func__, Now_Hader->Message_size, Payload[Now_Hader->Message_size]);
                        return -3;
                    }
                    break;
                case ProgramInfoReport:
                    if(Now_Hader->Message_size + 1 == 19 && Payload[Now_Hader->Message_size] == 0xAA)
                    {
                        Now_Hader->Job_State = 8;
                        Data[0] = *"8";
                        F_RealyServer_Print_Debug(2, "[Info][%s][Job_State:%d, STX:%02X ETX:%02X]\n",__func__, Now_Hader->Job_State, Payload[0], Payload[Now_Hader->Message_size]);
                        return Now_Hader->Job_State;
                    }else{
                        F_RealyServer_Print_Debug(0, "[Error][%s][Now_Hader->Message_size:%d, ETX:%02X]\n",__func__, Now_Hader->Message_size, Payload[Now_Hader->Message_size]);
                        return -8;
                    }
                default:
                    return 0;
            }     
        } 
    }else{
        F_RealyServer_Print_Debug(0, "[Error][%s][No Data]\n",__func__);
        return -1;
    }
    return 0;
}

/* 
Brief:
Parameter[In]
    Now_Hader:
    Data:
    err:
Parameter[Out]
    client_data_info_t:It is made by the function 
 */
int f_i_RelayServer_Job_Process_InfoRequest(struct data_header_info_t *Now_Hader, uint8_t **Data, struct Memory_Used_Data_Info_t *Data_Info)
{
    if(Data)
    {
        uint8_t *Payload = (*Data + HEADER_SIZE); 
        struct curl_info_t *curl_info = malloc(sizeof(struct curl_info_t));
        F_RealyServer_Print_Debug(4,"[Debug][%s][malloc:%d, Address:%p]\n", __func__, __LINE__, curl_info);
        switch(Now_Hader->Job_State)
        {
            case FirmwareInfoRequest:
                curl_info->request_len = f_i_RelayServer_HTTP_Payload(G_HTTP_Request_Info_Fireware, Payload, sizeof(Payload), &curl_info->request);
                break;
            case ProgramInfoRequest:
                curl_info->request_len = f_i_RelayServer_HTTP_Payload(G_HTTP_Request_Info_Program, Payload, sizeof(Payload), &curl_info->request);
                break;
            default:
                F_RealyServer_Print_Debug(0, "[Error][%s][Job_State:%d]\n", __func__, Now_Hader->Job_State);
                return -1;
        }   
            curl_info->Now_Hader = Now_Hader;
            curl_info->Data_Info = Data_Info;
            Now_Hader->Job_State = f_i_RelayServer_HTTP_Task_Run(curl_info);
            F_RealyServer_Print_Debug(2, "[Info][%s][Job_State:%d]\n",__func__, Now_Hader->Job_State);
    }else{
        F_RealyServer_Print_Debug(0, "[Error][%s][No Data]\n",__func__);
        return -1;
    }

    return Now_Hader->Job_State;
}

/* 
Brief:
Parameter[In]
    Now_Hader:
    Data:
    err:
Parameter[Out]
    client_data_info_t:It is made by the function 
 */
int f_i_RelayServer_Job_Process_InfoResponse(struct data_header_info_t *Now_Hader, uint8_t **Data)
{ 
    if(Data)
    {
        uint8_t *Payload = (*Data + HEADER_SIZE); 
        switch(Now_Hader->Job_State)
        {
            case FirmwareInfoResponse:
                //Recv the Data From PC_Server with HTTP Protocol
                Now_Hader->Job_State = 5;
                *Data[0] = *("5");
                break;
            case ProgramInfoResponse:
                //Recv the Data From PC_Server with HTTP Protocol
                Now_Hader->Job_State = 0xA;
                *Data[0] = *("A");
                break;
            default:
                F_RealyServer_Print_Debug(0, "[Error][%s][Job_State:%d]\n", __func__, Now_Hader->Job_State);
                return -1;
        }
        struct client_data_info_t client_info_is;
        uint8_t *ID_InData = malloc(sizeof(uint8_t) * 8);
        F_RealyServer_Print_Debug(4,"[Debug][%s][malloc:%d, Address:%p]\n", __func__, __LINE__, ID_InData);
        uint8_t *Version_InData = malloc(sizeof(uint8_t) * 8);
        F_RealyServer_Print_Debug(4,"[Debug][%s][malloc:%d, Address:%p]\n", __func__, __LINE__, Version_InData);
        uint8_t *data_len = malloc(sizeof(uint32_t));
        F_RealyServer_Print_Debug(4,"[Debug][%s][malloc:%d, Address:%p]\n", __func__, __LINE__, data_len);
        for(int Client_is = 0; Client_is < MAX_CLIENT_SIZE; Client_is++)
        {
            if(G_Clients_Info.socket[Client_is] == Now_Hader->Client_fd)
            {
                client_info_is =  G_Clients_Info.client_data_info[Client_is];
                memcpy(ID_InData, Payload + 2, 8);
                memcpy(Version_InData, Payload + 10, 8);
                memcpy(data_len, Payload + 18, sizeof(uint32_t));
                break;
            }else{
                if(0)//(*G_Clients_Info.connected_client_num - 1 == Client_is)
                {
                    Now_Hader->Job_State = 0x1;
                    *Data[0] = *("1");
                    F_RealyServer_Print_Debug(0, "[Error][%s][Disconnected Client:%d]\n",__func__, Now_Hader->Client_fd);
                    return -2;
                }
            } 

        }
        if(strncmp((char*)client_info_is.ID, (char*)ID_InData, 8))
        {
            F_RealyServer_Print_Debug(0, "[Error][%s][Incorrect ID:%s/%s]\n",__func__, client_info_is.ID, ID_InData);
            Now_Hader->Job_State = 0x1;
            *Data[0] = *("1");
        }else{
            
        }
        if(strncmp((char*)client_info_is.Version, (char*)Version_InData, 8))
        {
            F_RealyServer_Print_Debug(0, "[Error][%s][Incorrect VERSION:%s/%s]\n",__func__, client_info_is.Version, Version_InData);
            Now_Hader->Job_State = 0x1;
            *Data[0] = *("1");
        }else{
            
        }
        if(Now_Hader->Message_size < *data_len)
        {
            F_RealyServer_Print_Debug(0, "[Error][%s][Incorrect MESSAGE_SIZE:%d/%d]\n",__func__, Now_Hader->Message_size, *data_len);
            Now_Hader->Job_State = 0x1;
            *Data[0] = *("1");
        }else{
            
        }
        F_RealyServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, ID_InData);
        free(ID_InData);
        F_RealyServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, Version_InData);
        free(Version_InData);
        F_RealyServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, data_len);
        free(data_len);
    }else{
        F_RealyServer_Print_Debug(0, "[Error][%s][No Data]\n",__func__);
        return -1;
    }
    return Now_Hader->Job_State;
}

/* 
Brief:
Parameter[In]
    Now_Hader:
    Data:
    err:
Parameter[Out]
    client_data_info_t:It is made by the function 
 */
int f_i_RelayServer_Job_Process_InfoIndication(struct data_header_info_t *Now_Hader, uint8_t **Data)
{
    
    if(Data)
    {
        uint8_t *Payload = *Data + HEADER_SIZE;
        int ret;
        switch(Now_Hader->Job_State)
        {
            case FirmwareInfoIndication:
            case ProgramInfoIndication:
                if(Now_Hader->Message_size <= 0)
                {
                    Now_Hader->Job_State = 1;
                    ret = send(Now_Hader->Client_fd, Payload, 20, MSG_DONTWAIT);
                    if(ret <= 0)
                    {
                        F_RealyServer_Print_Debug(6,"[Debug][%s][send:%d, ret:%p]\n", __func__, __LINE__, ret);
                    }
                    break;
                }else{
                    ret = send(Now_Hader->Client_fd, Payload, Now_Hader->Message_size, MSG_DONTWAIT);
                    if(ret <= 0)
                    {
                        F_RealyServer_Print_Debug(4,"[Debug][%s][send:%d, ret:%p]\n", __func__, __LINE__, ret);
                    }
                    uint8_t *out_data = malloc(sizeof(uint8_t) * HEADER_SIZE + 20);
                    F_RealyServer_Print_Debug(4,"[Debug][%s][malloc:%d, Address:%p]\n", __func__, __LINE__, out_data);
                    sprintf((char*)out_data, HEADER_PAD, Now_Hader->Job_State, 0x0, Now_Hader->Client_fd, Now_Hader->Message_seq, 0);
                    memset(Payload + 16, 0x00, 4);
                    memcpy(out_data + HEADER_SIZE, Payload, 20);
                    F_RealyServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__,  *Data);
                    free(*Data);
                    *Data = out_data;
                }
                break;
            default:
                F_RealyServer_Print_Debug(0, "[Error][%s][Job_State:%d]", __func__, Now_Hader->Job_State);
                return -1;
        }
    }else{
        F_RealyServer_Print_Debug(0, "[Error][%s][No Data]\n",__func__);
        return -1;
    }
    return Now_Hader->Job_State;
}

int F_i_RelayServer_HTTP_Initial(uint8_t *G_HTTP_Request_Info, struct http_info_t *http_info)
{
    uint8_t *request = G_HTTP_Request_Info;
    if(http_info)
    {
        sprintf((char*)request, "%s %s %s/%s\r\n", http_info->Request_Line.Method, http_info->Request_Line.To, http_info->Request_Line.What, http_info->Request_Line.Version);
        if(http_info->HOST){
            sprintf((char*)request, "%s%s: %s:%s\r\n", request , "Host", http_info->HOST, http_info->PORT);
        }else{
            sprintf((char*)request, "%s%s: %s:%s\r\n", request , "Host", DEFALUT_HTTP_SERVER_FIREWARE_URL, "80");
        }
        if(http_info->ACCEPT){
            sprintf((char*)request, "%s%s: %s\r\n", request , "Accept", http_info->ACCEPT);
        }else{
            sprintf((char*)request, "%s%s: %s\r\n", request , "Accept", DEFALUT_HTTP_ACCEPT);
        }
        if(http_info->CONTENT_TYPE){
            sprintf((char*)request, "%s%s: %s\r\n", request , "Content-Type", http_info->CONTENT_TYPE);
        }else{
            sprintf((char*)request, "%s%s: %s\r\n", request , "Content-Type", DEFALUT_HTTP_CONTENT_TYPE);
        }
    }else
    {
        sprintf((char*)request, "%s %s %s/%s\r\n", DEFALUT_HTTP_METHOD, DEFALUT_HTTP_SERVER_FIREWARE_URL, "HTTP", DEFALUT_HTTP_VERSION);
        sprintf((char*)request, "%s%s: %s\r\n", request , "Host", DEFALUT_HTTP_SERVER_FIREWARE_URL);
        sprintf((char*)request, "%s%s: %s\r\n", request , "Accept", DEFALUT_HTTP_ACCEPT);
        sprintf((char*)request, "%s%s: %s\r\n", request , "Content-Type", DEFALUT_HTTP_CONTENT_TYPE);
    }

    return 0;
}

size_t f_i_RelayServer_HTTP_Payload(uint8_t *G_HTTP_Request_Info, uint8_t *Body, size_t Body_Size, uint8_t **Http_Request)
{
    size_t request_len;
    uint8_t *request = malloc(sizeof(uint8_t) * 526);
    if(G_HTTP_Request_Info){
        memcpy(request, G_HTTP_Request_Info, strlen(G_HTTP_Request_Info));
    }else{
        return -1;
    }
    if(Body)
    {
        if(Body_Size > 0)
        {
            sprintf((char*)request, "%s%s: %d\r\n", request , "Content-Length", Body_Size);
        }
        sprintf((char*)request, "%s\r\n", request);
        request_len = strlen(request) + Body_Size;
        memcpy(request + strlen(request), Body, Body_Size);
        *Http_Request = malloc(sizeof(uint8_t) * request_len);
        memcpy(*Http_Request, request, request_len);
        F_RealyServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, request);
        free(request);
    }else {
        return -1;
    }
    return request_len;
}


int f_i_RelayServer_HTTP_Task_Run(struct curl_info_t *curl_info)
{
    
    curl_info->curl = curl_easy_init();
    CURLcode res;
    uint8_t *URL;
    switch(curl_info->Now_Hader->Job_State)
    {
        case FirmwareInfoRequest:
            URL = DEFALUT_HTTP_SERVER_PROGRAM_URL;
            break;
        case ProgramInfoRequest:
            URL = DEFALUT_HTTP_SERVER_PROGRAM_URL;
            break;
        default:
            return -1;
    }
    curl_easy_setopt(curl_info->curl, CURLOPT_URL, DEFALUT_HTTP_SERVER_PROGRAM_URL);
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
            res = curl_easy_send(curl_info->curl, curl_info->request + nsent_total, curl_info->request_len - nsent_total, &nsent);
            nsent_total += nsent;

            if(res == CURLE_AGAIN && !f_i_RelayServer_HTTP_WaitOnSocket(curl_info->socket, 0, HTTP_SOCKET_TIMEOUT)) 
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
    } while(nsent_total < curl_info->request_len);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    curl_info->Timer = 1000; //ms
    pthread_create(&curl_info->Task_ID, &attr, th_RelayServer_HTTP_Task_Receive, curl_info);
    //pthread_datech(curl_info->Task_ID);

    return curl_info->Now_Hader->Job_State;
}

void *th_RelayServer_HTTP_Task_Receive(void *data)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  
    struct curl_info_t *curl_info = (struct curl_info_t*)data;
    curl_info->curl = (CURL *)((struct curl_info_t*)data)->curl;

    uint32_t Timer_Init = G_TickTimer.G_10ms_Tick;
    CURLcode res;
    size_t buf_len = 0;
    char buf[HTTP_BUFFER_SIZE];
    memset(buf, 0x00, HTTP_BUFFER_SIZE);
    for(;;) 
    {
        if(Timer_Init + (curl_info->Timer)/10  < G_TickTimer.G_10ms_Tick)
        {
            F_RealyServer_Print_Debug(0, "[Error][%s]:timeout. %d/%d\n", __func__, Timer_Init + curl_info->Timer/10 , G_TickTimer.G_10ms_Tick);
            pthread_cancel(curl_info->Task_ID);
        }
        
        size_t nread;
        do {
            nread = 0;
            res = curl_easy_recv(curl_info->curl, buf, sizeof(buf), &nread);
            buf_len += nread;
            if(res == CURLE_AGAIN && !f_i_RelayServer_HTTP_WaitOnSocket(curl_info->socket, 1, HTTP_SOCKET_TIMEOUT)) 
            {
                F_RealyServer_Print_Debug(0, "[Error][%s]: timeout.\n", __func__);
                return NULL;
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
        int http_body_len;
        char* ptr = strstr(buf, "\r\n\r\n");
        ptr = ptr + 4;
        http_body_len = buf_len - (ptr - &buf[0] + 2); /// -2 delete /r/n
        char http_body[http_body_len];
        memcpy(http_body, ptr, http_body_len);
        uint8_t *Http_Recv_data = malloc(sizeof(uint8_t) * (http_body_len + HEADER_SIZE));
        F_RealyServer_Print_Debug(4,"[Debug][%s][malloc:%d, Address:%p]\n", __func__, __LINE__, Http_Recv_data);
#if 0 
        for(int i = 0;  i < http_body_len; i++)
		{
			printf("%02X", http_body[i]);
		}
		printf("\n");
#endif
        struct data_header_info_t *Now_Hader = curl_info->Now_Hader;
        switch(Now_Hader->Job_State)
        {
            case FirmwareInfoRequest:
                Now_Hader->Job_State = 4;
                sprintf(Http_Recv_data, HEADER_PAD, 0x4, 0x0, Now_Hader->Client_fd, Now_Hader->Message_seq, http_body_len);
                break;
            case ProgramInfoRequest:
                Now_Hader->Job_State = 9;
                sprintf(Http_Recv_data, HEADER_PAD, 0x9, 0x0, Now_Hader->Client_fd, Now_Hader->Message_seq, http_body_len);
                break;
            default:
                F_RealyServer_Print_Debug(0, "[Error][%s][Job_State:%d]\n", __func__, Now_Hader->Job_State);
                return NULL;
        }   
        memcpy(Http_Recv_data + HEADER_SIZE, http_body, http_body_len);
        F_RealyServer_Print_Debug(5,"[Debug][%s][%d][Push_Data:%s/%d]\n", __func__, __LINE__, http_body, http_body_len);
        F_i_Memory_Data_Push(curl_info->Data_Info, Http_Recv_data, (http_body_len + HEADER_SIZE));
        F_RealyServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, Http_Recv_data);
        memset(http_body, 0x00, http_body_len);
        free(Http_Recv_data);
    }
    /* always cleanup */
    memset(buf, 0x00, sizeof(buf));
    curl_easy_cleanup(curl_info->curl);
    F_RealyServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, curl_info->request);
    //free(curl_info->request);
    F_RealyServer_Print_Debug(4,"[Debug][%s][Free:%d, Address:%p]\n", __func__, __LINE__, curl_info);
    free(curl_info);
    return NULL;
}

int f_i_RelayServer_HTTP_WaitOnSocket(curl_socket_t sockfd, int for_recv, long timeout_ms)
{
  struct timeval tv;
  fd_set infd, outfd, errfd;
  int res;
 
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (int)(timeout_ms % 1000) * 1000;
 
  FD_ZERO(&infd);
  FD_ZERO(&outfd);
  FD_ZERO(&errfd);
 
  FD_SET(sockfd, &errfd); /* always check for error */
 
  if(for_recv) {
    FD_SET(sockfd, &infd);
  }
  else {
    FD_SET(sockfd, &outfd);
  }
 
  /* select() returns the number of signalled sockets or -1 */
  res = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);
  return res;
}

/* Define NUVO */
#define DNM_Req_Signal 0x00
#define DNM_Done_Signal 0xFF

extern void *Th_RelayServer_NUVO_Client_Task(void *d)
{
    struct NUVO_recv_task_info_t *nubo_info = (struct NUVO_recv_task_info_t*)d;
    int ret;

    // Using_Timer
    int32_t TimerFd = timerfd_create(CLOCK_REALTIME, 0);//CLOCK_MONOTONIC(시각동기화 미사용시)
    struct itimerspec itval;
    struct timespec tv;
    uint32_t timer_tick_usec = 100 * 1000; //ms
    uint64_t res = 0;
    clock_gettime(CLOCK_REALTIME, &tv); 
    itval.it_interval.tv_sec = 0;
    itval.it_interval.tv_nsec = (timer_tick_usec % 1000000) * 1e3;
    itval.it_value.tv_sec = tv.tv_sec + 1;
    itval.it_value.tv_nsec = 0;
    ret = timerfd_settime (TimerFd, TFD_TIMER_ABSTIME, &itval, NULL);
    nubo_info->life_time = 0;
    sprintf(nubo_info->ACK,"%s%02X", "ACK", 0x5D);
    nubo_info->state = 0;

    uint32_t timer_100ms_tick = 0;
    int tick_count_10ms = 0;

    srand(time(NULL));//Random 값의 Seed 값 변경
    uint32_t timer_op_1s = ((rand() % 9) + 0);
    nubo_info->task_info_state = malloc(sizeof(int));
    *nubo_info->task_info_state = 2;

    nubo_info->sock = socket(PF_INET, SOCK_DGRAM, 0);
    
    memset(&nubo_info->serv_adr, 0, sizeof(nubo_info->serv_adr));
    nubo_info->serv_adr.sin_family = AF_INET;
    nubo_info->serv_adr.sin_addr.s_addr = inet_addr(DEFAULT_NUVO_ADDRESS);
    nubo_info->serv_adr.sin_port = htons(atoi(DEFAULT_NUVO_PORT));
    
    struct timeval sock_tv;                  /* Socket Send/Recv Block Timer */               
    sock_tv.tv_sec = (int)(50 / 1000);
    sock_tv.tv_usec = (90 % 1000) * 1000; 
    if (setsockopt(nubo_info->sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&sock_tv, sizeof(struct timeval)) == SO_ERROR) {
    perror("setsockopt(SO_RCVTIMEO)");
    }
    sock_tv.tv_usec = (50 % 1000) * 1000; 
    if (setsockopt(nubo_info->sock, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&sock_tv, sizeof(struct timeval)) == SO_ERROR) {
    perror("setsockopt(SO_SNDTIMEO)");
    }
    printf("[DRIVING HISTORY] UDP Socket Initial\n");
    printf("[DRIVING HISTORY] UDP Socket Infomation ...... NUVO IP Address:Port - %s:%d\n", inet_ntoa(nubo_info->serv_adr.sin_addr), atoi(DEFAULT_NUVO_PORT));

    time_t now = time(NULL);
    for(int i = 0; i < 4; i++)
    {
        printf("[DRIVING HISTORY] Waiting ECU Indication ...... %ld[s](Working Time)\n", time(NULL) - now);
        sleep(1);
    }

    printf("[DRIVING HISTORY] Received ECU Start Indication ...... %ld[s]\n", time(NULL) - now);
    printf("[DRIVING HISTORY] Press Any Key to continue ...... %ld[s]\n", time(NULL) - now);while(getchar() != '\n');printf("\x1B[1A\r");   
    nubo_info->state = GW_SLEEP_CONNECTIONING_NUVO;
    char Ack_Data[11] = {0,};
    nubo_info->life_time = -1;
    uint32_t Start_Save_Driving_History = 0;
    char *file_data = NULL;
    size_t file_data_len = 0;
#if 1
    CURLcode curl_res;
    size_t buf_len = 0;
    char http_recv_buf[1024] = {0,};
    char *http_send_buf= malloc(sizeof(char) * (file_data_len + 1024));
    memset(http_send_buf, 0x00, (file_data_len + 1024));
    curl_socket_t sockfd;     
    char *url = "https://self-api.wtest.biz/v1/system/firmwareUpload.php";

    CURL *curl = curl_easy_init();

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        printf("Error: %s\n", curl_easy_strerror(res));
        return 1;
    }
        
    JSON_Value *rootValue = json_value_init_object();
    JSON_Object *rootObject = json_value_get_object(rootValue);  
    json_object_set_string_with_len(rootObject, "file", "file_data_sample", 16);
    json_object_set_string_with_len(rootObject, "title", "12345", 5);
    //json_serialize_to_file_pretty(rootValue, "example.json");
    json_value_free(rootValue);

    FILE *length_fp = fopen("example.json", "r");
    fseek(length_fp, 0, SEEK_END);
    size_t http_body_len = ftell(length_fp); 
    char *http_body = (char*)malloc(sizeof(char) * http_body_len);
    fseek(length_fp, 0, SEEK_SET);
    uint32_t ptr_now = 0;
    while(feof(length_fp) == 0)
    {       
        memset(http_body + ptr_now, fgetc(length_fp) , 1);
        ptr_now++;
    }
    char *request = malloc(sizeof(char) * 1024);
    sprintf(request, "%s %s %s\r\n", "POST", url, "HTTP/1.1");
    sprintf(request, "%s%s: %s\r\n", request , "Host", url);
    sprintf(request, "%s%s: %s\r\n", request , "Accept", "*/*");
    sprintf(request, "%s%s: %s\r\n", request , "Content-Type", "multipart/form-data; boundary=--00--00--");
    sprintf(request, "%s%s: %d\r\n", request , "Content-Length", http_body_len);
    sprintf(request, "%s\r\n", request);
    size_t request_len = strlen(request);
    memcpy(request + request_len, http_body, http_body_len);
    request_len += http_body_len;

    for(int i = 0; i < request_len; i++)
    {
        printf("%c", request[i]);
    }
    printf("\n");
    size_t nsent_total = 0;
    do 
    {
        size_t nsent;
        do {
            nsent = 0;
            curl_res = curl_easy_send(curl, request + nsent_total, request_len - nsent_total, &nsent);
            nsent_total += nsent;
            if(curl_res == CURLE_AGAIN && !f_i_RelayServer_HTTP_WaitOnSocket(sockfd, 0, HTTP_SOCKET_TIMEOUT)) {
                printf("Error: timeout.\n");
                return 1;
            }
        } while(curl_res == CURLE_AGAIN);
        if(curl_res != CURLE_OK) 
        {
            printf("Error: %s\n", curl_easy_strerror(curl_res));
            return 1;
        }
    } while(nsent_total < request_len);

        printf("Reading response.\n");
        char buf[2048];
        for(;;) 
        {
            /* Warning: This example program may loop indefinitely (see above). */
            size_t nread;
            do {
                nread = 0;
                res = curl_easy_recv(curl, buf, sizeof(buf), &nread);

                if(res == CURLE_AGAIN && !wait_on_socket(sockfd, 1, 60000L)) {
                    printf("Error: timeout.\n");
                    return 1;
                }
            } while(res == CURLE_AGAIN);

            if(res != CURLE_OK) {
                printf("Error: %s\n", curl_easy_strerror(res));
                break;
            }

            if(nread == 0) {
                /* end of the response */
                break;
            }
            for(int i = 0; i < 2048; i++)
            {
                printf("%c", buf[i]);
            }
            printf("\n");
            
        }
       
        /* always cleanup */
        curl_easy_cleanup(curl);
        free(http_body_len);
#endif
    for(;;)
    {     
        ret = read(TimerFd, &res, sizeof(uint64_t));
        if(nubo_info->life_time >= 0)
        {
            nubo_info->life_time += 1;
            if((timer_100ms_tick % 50 == 0 && nubo_info->life_time >= 0) || nubo_info->life_time > 50)
            {
                Ack_Data[9] = (int)(nubo_info->life_time / 10) % 0xF0;
                ret = sendto(nubo_info->sock , Ack_Data, 11, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));
                printf("[DRIVING HISTORY] [Send Ack Every 5sec] ...... %ld[s]\n", time(NULL) - now);
                nubo_info->life_time = 0;
            }
        }
        
        switch((timer_100ms_tick % 10) - timer_op_1s)
        {
            default:
            {
No_GW_SLEEP_CONNECTIONING_NUVO: 
                if(nubo_info->state != GW_RECEIVE_DRIVING_HISTORY_DATA_FROM_NOVO)
                {
                    struct sockaddr_in from_adr;
                    socklen_t from_adr_sz;
                    char recv_buf[128] = {0,};
                    ret = recvfrom(nubo_info->sock , recv_buf, 128, 0, (struct sockaddr*)&from_adr, &from_adr_sz);
                }
                switch(nubo_info->state)
                {
                    default: 
                    {
                        break;
                    }
                    case GW_WATING_REPLY_CONNECTION_FROM_NUVO:
                    {
                        if(1)
                        {
                            if(nubo_info->life_time > 20)
                            {
                                printf("[DRIVING HISTORY] [Recvive Response Connecting] Response From NUVO  ...... %ld[s]\n", time(NULL) - now);
                                printf("[DRIVING HISTORY] [Recvive Response Connecting] Receive Success ...... %ld[s]\n", time(NULL) - now);
                                printf("[DRIVING HISTORY] [Recvive Response Connecting] Receive Data(Hex) ...... ");
                                char hdr[6] = {0,};
                                hdr[0] = 0x43;
                                hdr[1] = 0x08;
                                int data_length = 256;
                                memcpy(&hdr[2], &data_length, 4);
                                char STX = 0x43;
                                char ETX = 0xAA;
                                char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));
                                memcpy(send_buf, hdr, 6);
                                nubo_info->ACK[0] = "A";
                                nubo_info->ACK[1] = "C";
                                nubo_info->ACK[2] = "K";
                                nubo_info->ACK[3] = 0xF2;
                                memcpy(send_buf + 6, &nubo_info->ACK[0], 4);
                                memcpy(send_buf + 6 + 4, &ETX, 1);
                                for(int k = 0; k < 11; k++)
                                {
                                    if(k == 9)
                                    {
                                        printf("\033[0;32m");
                                    }else{
                                        printf("\033[0m");
                                    }                                    
                                    printf("%02X ", send_buf[k]);
                                }
                                printf("\n");
                                nubo_info->life_time = 1;
                                memcpy(Ack_Data, send_buf, 11);
                                free(send_buf);
                                nubo_info->state = GW_REQUEST_SAVE_DRIVING_HISTORY_TO_NUVO;
                            }
                        }else{
                            printf("[DRIVING HISTORY] [Recvive Response Connecting] Wating Response ...... %ld[s]\n", time(NULL) - now);
                        }
                        break;
                    }
                    case GW_REQUEST_SAVE_DRIVING_HISTORY_TO_NUVO:
                    {
                        char hdr[6] = {0,};
                        hdr[0] = 0x43;
                        hdr[1] = 0x08;
                        int data_length = 256;
                        memcpy(&hdr[2], &data_length, 4);
                        char STX = 0x43;
                        char ETX = 0xAA;
                        char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));
                        memcpy(send_buf, hdr, 6);
                        nubo_info->ACK[0] = "A";
                        nubo_info->ACK[1] = "C";
                        nubo_info->ACK[2] = "K";
                        nubo_info->ACK[3] = 0xF3;
                        memcpy(send_buf + 6, &nubo_info->ACK[0], 4);
                        int DNM = 1234;
                        memcpy(send_buf + 6 + 4, &DNM, 4);
                        memcpy(send_buf + 6 + 4 + 4, &ETX, 1);
                        printf("\n");printf("[DRIVING HISTORY] Press Any Key to [Send Request Start Save Driving History] ...... %ld[s]\n", time(NULL) - now);while(getchar() != '\n');printf("\x1B[1A\r");
                        printf("[DRIVING HISTORY] [Send Request Start Save Driving History] 'Request Start Save Driving History To NUVO' ...... %ld[s]\n", time(NULL) - now);
                        ret = sendto(nubo_info->sock , send_buf, 11, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));
                        printf("[DRIVING HISTORY] [Send Request Start Save Driving History] Send Success ...... %ld[s]\n", time(NULL) - now);
                        printf("[DRIVING HISTORY] [Send Request Start Save Driving History] Send Data(Hex) ...... ");
                        Start_Save_Driving_History =  time(NULL) - now;
                        for(int k = 0; k < 15; k++)
                        {
                            if(k == 9)
                            {
                                printf("\033[0;32m");
                            }else{
                                printf("\033[0m");
                            }
                            printf("%02X ", send_buf[k]);
                        }
                        printf("\n");
                        free(send_buf); 
                        nubo_info->state = GW_WATING_REPLY_SAVE_DRIVING_HISTORY_FROM_NUVO;
                        break;
                    }
                    case GW_WATING_REPLY_SAVE_DRIVING_HISTORY_FROM_NUVO:
                    {
                        
                            printf("[DRIVING HISTORY] [Recvive Response Save Driving History] Response From NUVO  ...... %ld[s]\n", time(NULL) - now);
                            printf("[DRIVING HISTORY] [Recvive Response Save Driving History] Receive Success ...... %ld[s]\n", time(NULL) - now);
                            printf("[DRIVING HISTORY] [Recvive Response Save Driving History] Receive Data(Hex) ...... ");
                            char hdr[6] = {0,};
                            hdr[0] = 0x43;
                            hdr[1] = 0x08;
                            int data_length = 256;
                            memcpy(&hdr[2], &data_length, 4);
                            char STX = 0x43;
                            char ETX = 0xAA;
                            char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));
                            memcpy(send_buf, hdr, 6);
                            nubo_info->ACK[0] = "A";
                            nubo_info->ACK[1] = "C";
                            nubo_info->ACK[2] = "K";
                            nubo_info->ACK[3] = 0xF4;
                            memcpy(send_buf + 6, &nubo_info->ACK[0], 4);
                            int DNM = 5678;
                            memcpy(send_buf + 6 + 4, &DNM, 4);
                            memcpy(send_buf + 6 + 4 + 4, &ETX, 1);
                            for(int k = 0; k < 15; k++)
                            {
                                if(k == 9)
                                {
                                    printf("\033[0;32m");
                                }else{
                                    printf("\033[0m");
                                }                                    
                                printf("%02X ", send_buf[k]);
                            }
                            printf("\n"); 
                            nubo_info->state = GW_WAIT_DONE_SAVE_DRIVING_HISTORY_FROM_ECU;
                        
                    }
                    case GW_WAIT_DONE_SAVE_DRIVING_HISTORY_FROM_ECU:
                    {
                        if((time(NULL) - now) - Start_Save_Driving_History > 5)
                        {
                            printf("[DRIVING HISTORY] Received ECU Done Indication ...... %ld[s]\n", time(NULL) - now);
                            char hdr[6] = {0,};
                            hdr[0] = 0x43;
                            hdr[1] = 0x08;
                            int data_length = 256;
                            memcpy(&hdr[2], &data_length, 4);
                            char STX = 0x43;
                            char ETX = 0xAA;
                            char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));
                            memcpy(send_buf, hdr, 6);
                            nubo_info->ACK[0] = "A";
                            nubo_info->ACK[1] = "C";
                            nubo_info->ACK[2] = "K";
                            nubo_info->ACK[3] = 0xF5;
                            memcpy(send_buf + 6, &nubo_info->ACK[0], 4);
                            int DNM = 9101112;
                            memcpy(send_buf + 6 + 4, &DNM, 4);
                            memcpy(send_buf + 6 + 4 + 4, &ETX, 1);
                            printf("[DRIVING HISTORY] [Send Request Done Save Driving History] 'Request Done Save Driving History To NUVO' ...... %ld[s]\n", time(NULL) - now);
                            ret = sendto(nubo_info->sock , send_buf, 11, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));
                            printf("[DRIVING HISTORY] [Send Request Done Save Driving History] Send Success ...... %ld[s]\n", time(NULL) - now);
                            printf("[DRIVING HISTORY] [Send Request Done Save Driving History] Send Data(Hex) ...... ");
                            Start_Save_Driving_History =  time(NULL) - now;
                            for(int k = 0; k < 15; k++)
                            {
                                if(k == 9)
                                {
                                    printf("\033[0;32m");
                                }else{
                                    printf("\033[0m");
                                }
                                printf("%02X ", send_buf[k]);
                            }
                            printf("\n");
                            free(send_buf); 
                            nubo_info->state = GW_WAIT_DRIVING_HISTORY_INFO_FROM_NOVO;
                        }else{
                            if(timer_100ms_tick % 10 == 0)
                            {
                                printf("[DRIVING HISTORY] Wating ECU Done Indication ...... %ld[s]\n", time(NULL) - now);
                            }
                        }     
                        break;
                    }
                    case GW_WAIT_DRIVING_HISTORY_INFO_FROM_NOVO:
                    {
                        printf("[DRIVING HISTORY] [Waiting Driving History Data Info] Response From NUVO  ...... %ld[s]\n", time(NULL) - now);
                        printf("[DRIVING HISTORY] [Waiting Driving History Data Info] Receive Success ...... %ld[s]\n", time(NULL) - now);
                        printf("[DRIVING HISTORY] [Waiting Driving History Data Info] Receive Data(Hex) ...... ");
                        char hdr[6] = {0,};
                        hdr[0] = 0x43;
                        hdr[1] = 0x08;
                        int data_length = 256;
                        memcpy(&hdr[2], &data_length, 4);
                        char STX = 0x43;
                        char ETX = 0xAA;
                        char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));
                        memcpy(send_buf, hdr, 6);
                        nubo_info->ACK[0] = "A";
                        nubo_info->ACK[1] = "C";
                        nubo_info->ACK[2] = "K";
                        nubo_info->ACK[3] = 0xF4;
                        memcpy(send_buf + 6, &nubo_info->ACK[0], 4);
                        int Data_Length = 2781319;
                        memcpy(send_buf + 6 + 4, &Data_Length, 4);
                        memcpy(send_buf + 6 + 4 + 4, &ETX, 1);
                        for(int k = 0; k < 15; k++)
                        {
                            if(k == 9)
                            {
                                printf("\033[0;32m");
                            }else{
                                printf("\033[0m");
                            }                                    
                            printf("%02X ", send_buf[k]);
                        }
                        printf("\n"); 
                        nubo_info->state = GW_RECEIVE_DRIVING_HISTORY_DATA_FROM_NOVO;
                    }
                    case GW_RECEIVE_DRIVING_HISTORY_DATA_FROM_NOVO:
                    {
                        printf("\n");printf("[DRIVING HISTORY] Press Any Key to Recvive Driving History Data]...... %ld[s]\n", time(NULL) - now);while(getchar() != '\n');printf("\x1B[1A\r");
                        struct sockaddr_in from_adr;
                        socklen_t from_adr_sz;
                        char recv_buf[1 + 7] = {0,};
                        int recv_len = 0;
                        while(0)
                        {
                             recv_len = recvfrom(nubo_info->sock , recv_buf + recv_len, 128, 0, (struct sockaddr*)&from_adr, &from_adr_sz);
                             if(recv_len == 0)
                             {
                                break;
                            }
                        }
#if 1
                        #define NOVO_FILE_PATH "/home/root/Project_Relayserver/nubo_sample"

                            ret = access(NOVO_FILE_PATH, F_OK);

                            DIR *dr = opendir(NOVO_FILE_PATH);
                            struct dirent *de;
                            char *file_name = NULL;
                            while ((de = readdir(dr)) != NULL) 
                            {
                                if (de->d_type == DT_REG)
                                {
                                    file_name = malloc(sizeof(char) * de->d_reclen);
                                    memcpy(file_name, de->d_name, de->d_reclen);
                                    break;
                                }else if (de->d_type == DT_DIR)
                                {
                                }else{
                                }
                            }
                            closedir(dr);
                            char *file_path = malloc(sizeof(char) * de->d_reclen + sizeof(NOVO_FILE_PATH));
                            sprintf(file_path, "%s/%s", NOVO_FILE_PATH, file_name);
                        
                            FILE *fp = fopen(file_path, "r");
                            fseek(fp, 0, SEEK_END);
                            file_data_len = ftell(fp); 
                            file_data = malloc(sizeof(char) * file_data_len);
                            fseek(fp, 0, SEEK_SET);
                            uint32_t ptr_now = 0;
                            while(feof(fp) == 0)
                            {       
                                memset(file_data + ptr_now, fgetc(fp) , 1);
                                ptr_now++;
                            }
                            if(file_path)free(file_path);
                            if(file_name)free(file_name);
#endif
                        printf("[DRIVING HISTORY] [Recvive Driving History Data] Recvive From NUVO  ...... %ld[s]\n", time(NULL) - now);
                        printf("[DRIVING HISTORY] [Recvive Driving History Data] Receive Success ...... %ld[s]\n", time(NULL) - now);
                        printf("[DRIVING HISTORY] [Recvive Driving History Data] Receive Data Length ...... %d[byte]\n", file_data_len + 7);
                        printf("[DRIVING HISTORY] [Recvive Driving History Data] Receive Data Length Check ...... OK!\n");
                        goto GW_JOB_BY_NUBO_DONE;
                    }
                }

                break;
            }
            case 0:
            {
                switch(nubo_info->state)
                {
                    default:
                    {
                        goto No_GW_SLEEP_CONNECTIONING_NUVO;
                        break;
                    }
                    case GW_SLEEP_CONNECTIONING_NUVO:
                    {
                        srand(time(NULL));//Random 값의 Seed 값 변경
                        usleep(((rand() % 20) + 4) * 1000); // 매초 + 4~20ms의 랜덤값을 갖는 시간에 동작
                        char hdr[6] = {0,};
                        hdr[0] = 0x43;
                        hdr[1] = 0x08;
                        int data_length = 256;
                        memcpy(&hdr[2], &data_length, 4);
                        char STX = 0x43;
                        char ETX = 0xAA;
                        char *send_buf = malloc(sizeof(char) * (6 + 4 + 1));
                        memcpy(send_buf, hdr, 6);
                        nubo_info->ACK[0] = "A";
                        nubo_info->ACK[1] = "C";
                        nubo_info->ACK[2] = "K";
                        nubo_info->ACK[3] = 0xF1;
                        memcpy(send_buf + 6, &nubo_info->ACK[0], 4);
                        memcpy(send_buf + 6 + 4, &ETX, 1);
                        printf("\n");printf("[DRIVING HISTORY] Press Any Key to [Send Request Connecting]...... %ld[s]\n", time(NULL) - now);while(getchar() != '\n');printf("\x1B[1A\r");
                        printf("[DRIVING HISTORY] [Send Request Connecting] 'Connecting To NUVO' ...... %ld[s]\n", time(NULL) - now);
                        ret = sendto(nubo_info->sock , send_buf, 11, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));
                        printf("[DRIVING HISTORY] [Send Request Connecting] Send Success ...... %ld[s]\n", time(NULL) - now);
                        printf("[DRIVING HISTORY] [Send Request Connecting] Send Data(Hex) ...... ");
                        for(int k = 0; k < 11; k++)
                        {
                            if(k == 9)
                            {
                                printf("\033[0;32m");
                            }else{
                                printf("\033[0m");
                            }
                            printf("%02X ", send_buf[k]);
                        }
                        printf("\n");
                        free(send_buf);
                        nubo_info->life_time = 0;
                        nubo_info->state = GW_WATING_REPLY_CONNECTION_FROM_NUVO;
                        break;
                    }
                }
                
                break;
            }
        }
        timer_100ms_tick = (timer_100ms_tick + 1) % 0xF0; 
    }


GW_JOB_BY_NUBO_DONE:
#if 0
    printf("[DRIVING HISTORY] [Combine Start Driving History Data] ...... %ld[s]\n", time(NULL) - now);
    sleep(3);
    printf("[DRIVING HISTORY] [Combine Done Driving History Data] ...... %ld[s]\n", time(NULL) - now);

    time_t timer = time(NULL);
    struct tm *t = localtime(&timer);
    char file_name[19];
    sprintf(file_name, "%04d%02d%02d_%02d%02d%02d.zip", t->tm_year, t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
    printf("[DRIVING HISTORY] [Combine Done] File Name ...... %s\n", file_name);
    printf("[DRIVING HISTORY] [Combine Done] File Length ...... %ld[byte]\n", file_data_len);
    printf("\n");printf("[DRIVING HISTORY] Press Any Key to [Send DRIVING HISTORY DATA To Server]...... %ld[s]\n", time(NULL) - now);while(getchar() != '\n');printf("\x1B[1A\r");
    
    CURLcode curl_res;
    size_t buf_len = 0;
    char http_recv_buf[1024] = {0,};
    char *http_send_buf= malloc(sizeof(char) * (file_data_len + 1024));
    memset(http_send_buf, 0x00, (file_data_len + 1024));
    curl_socket_t sockfd;     
    char *url = "https://self-api.wtest.biz/v1/system/firmwareUpload.php";

    CURL *curl = curl_easy_init();
    curl_res = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);

    JSON_Value *rootValue = json_value_init_object();
    JSON_Object *rootObject = json_value_get_object(rootValue);  

    json_object_set_string_with_len(rootObject, "file", "file_data_sample", 16);
    json_object_set_string_with_len(rootObject, "title", "12345", 5);
    json_serialize_to_file_pretty(rootValue, "example.json");
    json_value_free(rootValue);

    FILE *length_fp = fopen("example.json", "r");
    fseek(length_fp, 0, SEEK_END);
    size_t http_body_len = ftell(length_fp); 
    char *http_body = (char*)malloc(sizeof(char) * http_body_len);
    fseek(length_fp, 0, SEEK_SET);
    uint32_t ptr_now = 0;
    while(feof(length_fp) == 0)
    {       
        memset(http_body + ptr_now, fgetc(length_fp) , 1);
        ptr_now++;
    }
    char *request = malloc(sizeof(char) * 1024);
    sprintf(request, "%s %s %s\r\n", "POST", url, "HTTP/1.0");
    sprintf(request, "%s%s: %s\r\n", request , "Host", url);
    sprintf(request, "%s%s: %s\r\n", request , "Accept", "*/*");
    sprintf(request, "%s%s: %s\r\n", request , "Content-Type", "Application/octet-stream");
    sprintf(request, "%s%s: %d\r\n", request , "Content-Length", http_body_len);
    sprintf(request, "%s\r\n", request);
    size_t request_len = strlen(request);
    memcpy(request + request_len, http_body, http_body_len);
    request_len += http_body_len;

    for(int i = 0; i < request_len; i++)
    {
        printf("%c", request[i]);
    }
    printf("\n");
    size_t nsent_total = 0;
    do 
    {
        size_t nsent;
        do {
            nsent = 0;
            curl_res = curl_easy_send(curl, request + nsent_total, request_len - nsent_total, &nsent);
            nsent_total += nsent;
            if(curl_res == CURLE_AGAIN && !f_i_RelayServer_HTTP_WaitOnSocket(sockfd, 0, HTTP_SOCKET_TIMEOUT)) {
                printf("Error: timeout.\n");
                return 1;
            }
        } while(curl_res == CURLE_AGAIN);
        if(curl_res != CURLE_OK) 
        {
            printf("Error: %s\n", curl_easy_strerror(curl_res));
            return 1;
        }
    } while(nsent_total < request_len);

        printf("Reading response.\n");
        char buf[2048];
        for(;;) 
        {
            /* Warning: This example program may loop indefinitely (see above). */
            size_t nread;
            do {
                nread = 0;
                res = curl_easy_recv(curl, buf, sizeof(buf), &nread);

                if(res == CURLE_AGAIN && !wait_on_socket(sockfd, 1, 60000L)) {
                    printf("Error: timeout.\n");
                    return 1;
                }
            } while(res == CURLE_AGAIN);

            if(res != CURLE_OK) {
                printf("Error: %s\n", curl_easy_strerror(res));
                break;
            }

            if(nread == 0) {
                /* end of the response */
                break;
            }
            for(int i = 0; i < 2048; i++)
            {
                printf("%c", buf[i]);
            }
            printf("\n");
            
        }
       
        /* always cleanup */
        curl_easy_cleanup(curl);
        free(http_body_len);
        
#endif

  
    *nubo_info->task_info_state = 2;
    close(nubo_info->sock);
    if(file_data)free(file_data);
    
    if(*nubo_info->task_info_state == 2)
    {
        *nubo_info->task_info_state = 0;
        free(nubo_info->task_info_state);
    }
}

static int wait_on_socket(curl_socket_t sockfd, int for_recv, long timeout_ms)
{
  struct timeval tv;
  fd_set infd, outfd, errfd;
  int res;
 
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (int)(timeout_ms % 1000) * 1000;
 
  FD_ZERO(&infd);
  FD_ZERO(&outfd);
  FD_ZERO(&errfd);
 
  FD_SET(sockfd, &errfd); /* always check for error */
 
  if(for_recv) {
    FD_SET(sockfd, &infd);
  }
  else {
    FD_SET(sockfd, &outfd);
  }
 
  /* select() returns the number of signalled sockets or -1 */
  res = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);
  return res;
}