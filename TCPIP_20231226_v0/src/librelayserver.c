/* LIBRARY Source */
#include <./librelayserver.h>

/* 
Brief:
Parameter[In]: 
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
        //Socket_Info.Socket = socket(AF_INET, SOCK_STREAM, 0);
        Socket_Info.Socket = socket(AF_INET, SOCK_DGRAM, 0);
        //Socket_Setup
        ret = f_i_RelayServer_TcpIp_Setup_Socket(&Socket_Info.Socket, 10, true);
        if(ret < 0)
        {
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
	}
    ret = f_i_RelayServer_TcpIp_Setup_Socket(&IP_Parsing_Socket, 100, true);
	close(IP_Parsing_Socket);
}
/* 
Brief:Run the Server_Tesk which is receiving from ecu
Parameter[In]
Parameter[Out]
 */
int F_i_RelayServer_TcpIp_Task_Run(struct socket_info_t *Socket_Info)
{
    int ret;
    ret = f_i_RelayServer_TcpIp_Bind(&Socket_Info->Socket, Socket_Info->Socket_Addr);
    if(ret < 0)
    {
    }else{
        pthread_create(&(Socket_Info->Task_ID), NULL, th_RelayServer_TcpIp_Task_Server, (void*)Socket_Info);  
        pthread_detach((Socket_Info->Task_ID));
    }
    return 0;
}
/* 
Brief:
Parameter[In]
Parameter[Out]
 */
void *Th_RelayServer_Job_Scheduler(void *Data)
{
    Data = Data;
    int ret;
    uint32_t Task_Timer_Max = 100 * 1000;
    uint32_t Task_Timer_min = 10 * 1000;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    struct Used_Data_Info_t *Data_Info = (struct Used_Data_Info_t *)Data;
    //int epoll_block_timer;
    for(;;)
    {        
        if(G_Clients_Info.connected_client_num > 0)
        {
          if(Data_Info->Data_Count <= 0)
          { 
            F_Select_Timer(100 * 1000);
          }else{
            F_Select_Timer(1000);
          }
        }else{
            F_Select_Timer(1000 * 1000);
        }
        //epoll_wait(G_epfd, G_epoll_events, MAX_CLIENT_SIZE - 16, epoll_block_timer);
        if(G_Clients_Info.connected_client_num > 0 && G_Clients_Info.task_num < MAX_TASK_NUM)
        {
            for(int i = 0; i < Data_Info->Data_Count; i++)
            {
                size_t data_size;
                uint8_t *out_data = (uint8_t*)F_v_RelayServer_Data_Pop(Data_Info, &data_size);  

                struct data_header_info_t Data_Header_Info = f_s_Parser_Data_Header(out_data, HEADER_SIZE);
                int Client_is = Data_Header_Info.Client_fd % MAX_CLIENT_SIZE;
                if(G_Clients_Info.socket[Client_is] != 0)
                {
                    if(G_Clients_Info.task_running[Client_is] == false && G_Clients_Info.life_timer[Client_is] > 0)
                    {
                        G_Clients_Info.task_running[Client_is] == true;
                        ret = f_i_RelayServer_Job_Task(out_data);
                        //ret = pthread_create(&G_Clients_Info.task_id[Client_is], &attr, th_RelayServer_Job_Task, (void *)out_data);
                        if(ret == 0)
                        {
                            G_Clients_Info.task_running[Client_is] = true;
                            G_Clients_Info.life_timer[Client_is] =  F_l_Timestamp() + TASK_TIMER;
                            G_Clients_Info.task_num++;
                        }else{
                        }
                    }
                }
            }
        }
    }
    return NULL;
}

int f_i_RelayServer_Job_Task(uint8_t *Input_Data)
{
    if(Input_Data)
    {
        uint8_t *Data = Input_Data;

        struct data_header_info_t Data_Header_Info = f_s_Parser_Data_Header(Data, HEADER_SIZE);
        enum job_type_e Now_Job;
        for(;;)
        {
            Now_Job = f_e_RelayServer_Job_Process_Do(&Data_Header_Info, &Data);
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
                case FirmwareInfoRequest:
                case ProgramInfoRequest:
                case Finish:
                    break;
                default:
                    break; 
            }  
            if((Now_Job > 0 && Now_Job < 50))
            {
            }else{
                break;
            }
        }        
        Relay_safefree(Data);
    }else{
    }
    G_Clients_Info.task_num--;
    return 0;
}

#ifdef THREAD_TYPE_PROCESS_ON
    void *th_RelayServer_Job_Task(void* Input_Data)
    {

        if(Input_Data)
        {
            uint8_t *Data = (uint8_t*)Input_Data;
            struct data_header_info_t Data_Header_Info = f_s_Parser_Data_Header(Data, HEADER_SIZE);
            enum job_type_e Now_Job;
            for(;;)
            {
                Now_Job = f_e_RelayServer_Job_Process_Do(&Data_Header_Info, &Data);
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
                    case FirmwareInfoRequest:
                    case ProgramInfoRequest:
                    case Finish:
                        break;
                    default:
                        break; 
                }  
                if((Now_Job > 0 && Now_Job < 50))
                {
                }else{
                    break;
                }
            }        
            Relay_safefree(Data);
        }else{
        }
        G_Clients_Info.task_num--;
        return NULL;
    }   
#endif

void* th_RelayServer_TcpIp_Task_Server(void *socket_info)
{
#ifdef _DEBUG_MODE
    G_Recv_Count = 0;
    G_Send_Count = 0;
#endif
    int ret, i;
    struct socket_info_t *Socket_Info = (struct socket_info_t*)socket_info;
    struct Used_Data_Info_t *Data_Info = G_Data_Info;
    int Client_Socket;
    struct sockaddr_in  Client_Address;
    socklen_t adr_sz = sizeof(Client_Address);
    #if 0
    ret = listen(Socket_Info->Socket, 5);
    if(ret == -1)
    {
        return NULL;
    }
    #endif
    //pthread_mutex_init(&G_Clients_Info.mtx, NULL);
    int epoll_size = MAX_CLIENT_SIZE - 16;
    int epoll_event_count;
    G_epfd = epoll_create(epoll_size);
    struct epoll_event epoll_event;
    epoll_event.events = EPOLLIN;
    epoll_event.data.fd = Socket_Info->Socket;	
    epoll_ctl(G_epfd, EPOLL_CTL_ADD, Socket_Info->Socket, &epoll_event);
    int str_len;
    int client_is, client_count;
    int epoll_block_timer;
    long init_time = F_l_Timestamp();
    long now_time;
    uint8_t *push_data = malloc(1024);
    for(;;)
    {
        usleep(1000);
        if(G_Clients_Info.connected_client_num > 0)
        {
          if(Data_Info->Data_Count <= 0)
          { 
            F_Select_Timer(100 * 1000);
            epoll_block_timer = 10;
          }else{
            epoll_block_timer = 1000;
          }
        }else{
            epoll_block_timer = -1;
            G_Clients_Info.used_state = false;
        }
        epoll_event_count = epoll_wait(G_epfd, G_epoll_events, epoll_size, epoll_block_timer);
		if(epoll_event_count < 0)
		{
			break; 
		}
		for(i = 0; i < epoll_event_count % epoll_size; i++)
		{
			if(G_epoll_events[i].data.fd == Socket_Info->Socket)
			{
                if(G_Clients_Info.connected_client_num >= epoll_size)
                {
                    goto EPOLL_SERVER_LOOP_OUT;
                }else{
                    char *buf = malloc(TCP_RECV_BUFFER_SIZE);
                    memset(buf, 0x00, TCP_RECV_BUFFER_SIZE);
                    struct sockaddr_in client_addr;
                    socklen_t client_addr_len = sizeof(client_addr);
                    str_len = recvfrom(G_epoll_events[i].data.fd, buf, TCP_RECV_BUFFER_SIZE, 0, (struct sockaddr *)&(client_addr), &client_addr_len); 
                    Client_Socket = (client_addr.sin_addr.s_addr); // The last number of senders' IPV4 address.  
                    while(G_Clients_Info.used_state == true)
                    {
                        F_Select_Timer(1000);
                    }
                    G_Clients_Info.used_state = true;
                    for(client_is = 0; i < G_Clients_Info.connected_client_num; client_is++)
                    {
                        if(G_Clients_Info.socket[client_is] == Client_Socket)
                        {
                            G_Clients_Info.life_timer[client_is] = F_l_Timestamp() + SOCKET_TIMER;
                            G_Clients_Info.socket_message_seq[client_is] += 1;
                            G_Clients_Info.used_state = false;
                            break;
                        }else{
                            
                        }
                    }
                    if(G_Clients_Info.used_state == true)
                    {
                        G_Clients_Info.socket[client_is] = Client_Socket;
                        G_Clients_Info.life_timer[client_is] = F_l_Timestamp() + SOCKET_TIMER;
                        G_Clients_Info.socket_message_seq[client_is] = 0;
                        G_Clients_Info.connected_client_num = G_Clients_Info.connected_client_num + 1;
                        G_Clients_Info.used_state = false;
                    }
                    sendto(G_epoll_events[i].data.fd, buf, str_len, 0, (struct sockaddr *)&(client_addr), client_addr_len);
                    memset(push_data, 0x00, sizeof(uint8_t) * 1024);
                    sprintf(push_data, HEADER_PAD,                                                  //Client Data Protocol(Header:Hex_Sring,Payload:OCTETs)
                                                    0x0,                                            //:job_state(1)
                                                    0x1,                                            //protocol_type(1)
                                                    client_is,                                       //client_fd(8)
                                                    G_Clients_Info.socket_message_seq[client_is],   //message_seq(2)
                                                    str_len - 1);                                   //message_size(4);

                    memcpy(push_data + HEADER_SIZE, buf, str_len);                                               
                    G_Clients_Info.used_state = false;
                    size_t left_buf = F_i_RelayServer_Data_Push(Data_Info, (void *)push_data, str_len + HEADER_SIZE);
                    printf("Data_Info->Data_Count:%d, left_buf:%d\n", Data_Info->Data_Count, left_buf);
                    if(left_buf > 0)
                    {
#ifdef _DEBUG_MODE
                        G_Recv_Count++;
#endif
                        G_Clients_Info.task_running[client_is] = false;
                        F_Print_Debug(222 ,"Receive_Data:");
                        for(int i = 0;  i < str_len; i++)
                        {
                            printf("%02X", buf[i]);
                        }
                        printf("\n");
                        if(left_buf >= 0)
                        {
                        }
                    }else{
                    }
                }
                #if 0 
                if(Client_Socket >= 0)
                {                                
                    client_is = Client_Socket % epoll_size;
                    if(Client_Socket >= epoll_size){
                        if(G_Clients_Info.socket[client_is] != 0)
                        {
                            close(Client_Socket);
                            goto EPOLL_SERVER_LOOP_OUT;
                        }
                    }
                    ret = f_i_RelayServer_TcpIp_Setup_Socket(&Client_Socket, 0, true);
                    if(ret < 0)
                    {
                        goto EPOLL_SERVER_LOOP_OUT;
                    }
                    while(G_Clients_Info.used_state == true)
                    {
                        F_Select_Timer(1000);
                    }
                    G_Clients_Info.used_state = true;
                    if(G_Clients_Info.socket[client_is] == 0)
                    {
                        G_Clients_Info.socket[client_is] = Client_Socket;
                        G_Clients_Info.life_timer[client_is] = F_l_Timestamp() + SOCKET_TIMER;
                        G_Clients_Info.socket_message_seq[client_is] = 0;
                        G_Clients_Info.connected_client_num = G_Clients_Info.connected_client_num + 1;
                        G_Clients_Info.used_state = false;
                        epoll_event.events = EPOLLIN;
                        epoll_event.data.fd = Client_Socket;
                        epoll_ctl(G_epfd, EPOLL_CTL_ADD, Client_Socket, &epoll_event);
                    }else{
                        G_Clients_Info.used_state = false;
                        goto EPOLL_SERVER_LOOP_OUT;
                    }
                }
    #endif
                EPOLL_SERVER_LOOP_OUT:
                printf("");//For Goto EPOLL_SERVER_LOOP_OUT
			}else{
#if 0
                if(G_Clients_Info.connected_client_num > 0)
                {
                    char *buf = malloc(TCP_RECV_BUFFER_SIZE);
                    memset(buf, 0x00, TCP_RECV_BUFFER_SIZE);
                    //str_len = recvfrom(G_epoll_events[i].data.fd, buf, TCP_RECV_BUFFER_SIZE, 0, NULL, NULL);
                    //str_len = recv(G_epoll_events[i].data.fd, buf, TCP_RECV_BUFFER_SIZE, O_NONBLOCK);
                    client_count == 0;
                    client_is = G_epoll_events[i].data.fd % epoll_size;
                    if(client_is >= 0)
                    {
                        if(str_len > 0)
                        {
                                while(G_Clients_Info.used_state == true)
                                {
                                  F_Select_Timer(1000);
                                }
                                G_Clients_Info.used_state = true;
                                G_Clients_Info.socket_message_seq[client_is]++;
                                memset(push_data, 0x00, sizeof(uint8_t) * 1024);
                                sprintf(push_data, HEADER_PAD,                                                  //Client Data Protocol(Header:Hex_Sring,Payload:OCTETs)
                                                                0x0,                                            //:job_state(1)
                                                                0x1,                                            //protocol_type(1)
                                                                G_epoll_events[i].data.fd,                      //client_fd(8)
                                                                G_Clients_Info.socket_message_seq[client_is],   //message_seq(2)
                                                                str_len - 1);                                   //message_size(2);
                                strncat(push_data, buf, str_len);                                               //data(payload_size)
                                G_Clients_Info.used_state = false;
                                size_t left_buf = F_i_RelayServer_Data_Push(Data_Info, (void *)push_data, str_len + HEADER_SIZE);
                                printf("Data_Info->Data_Count - %d\n", Data_Info->Data_Count);
                                if(left_buf > 0)
                                {
#ifdef _DEBUG_MODE
                                    G_Recv_Count++;
#endif
                                    G_Clients_Info.task_running[client_is] = false;
                                    F_Print_Debug(222 ,"Receive_Data:");
                                    for(int i = 0;  i < str_len; i++)
                                    {
                                        printf("%02X", buf[i]);
                                    }
                                    printf("\n");
                                    if(left_buf >= 0)
                                    {
                                    }
                                }else{
                                }
                        }else if(str_len <= 0)
                        {
                            if(0)//G_Clients_Info.task_running[epoll_events[i].data.fd] = false)
                            {
                                epoll_ctl(G_epfd, EPOLL_CTL_DEL, G_epoll_events[i].data.fd, NULL);
                                close(G_epoll_events[i].data.fd);  
                            }
                        }
                    }
                    Relay_safefree(buf);
                }
            EPOLL_CLIENT_LOOP_OUT:
printf("");
#endif
            }
        }
#if 1
        now_time = F_l_Timestamp();
        if(init_time + (1000 * 1000) < now_time)
        {
            init_time = now_time;
            if(G_Clients_Info.connected_client_num > 0)
            {
                while(G_Clients_Info.used_state == true)
                {
                  F_Select_Timer(1000);
                }
                G_Clients_Info.used_state = true;
                for(int i = 0; i < MAX_CLIENT_SIZE; i++)
                {   
                    if(G_Clients_Info.socket[i] == Socket_Info->Socket)
                    {
                    }else if(G_Clients_Info.socket[i]  != 0)
                    {                            
                        if(G_Clients_Info.life_timer[i] <= F_l_Timestamp())
                        {
                            if(G_Clients_Info.socket_job_state[i] == -1)
                            {
                            }else{
                                memset(G_Clients_Info.client_data_info[i].ID, 0x00, 8);
                                memset(G_Clients_Info.client_data_info[i].Division, 0x00, 1); 
                                memset(G_Clients_Info.client_data_info[i].Version, 0x00, 8);
                                G_Clients_Info.life_timer[i] = 0; 
                                G_Clients_Info.task_running[i] = false;
                                G_Clients_Info.socket_message_seq[i] = 0;
                            }
                            if(G_Clients_Info.connected_client_num > 0 )
                            {
                                G_Clients_Info.connected_client_num = G_Clients_Info.connected_client_num - 1;
                            }else if(G_Clients_Info.connected_client_num < 0){
                                G_Clients_Info.connected_client_num = 0;
                            }
                            printf("G_Clients_Info.connected_client_num:%d\n", G_Clients_Info.connected_client_num );
                            epoll_ctl(G_epfd, EPOLL_CTL_DEL, G_Clients_Info.socket[i], NULL);
                            close(G_Clients_Info.socket[i]);  
                            G_Clients_Info.socket[i] = 0;
                        }
                    }
                }
                G_Clients_Info.used_state = false;
            }
        }
#endif
    }
    printf("While_Loop_Broken!%d\n", __LINE__);
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
            if(Retry_Count == 9)
            {
                close(*Server_Socket);
                return -1;
            }
            Retry_Count++;
            sleep(1);
        }else{
            char addr_str[40];
            inet_ntop(AF_INET, (void *)&Socket_Addr.sin_addr, addr_str, sizeof(addr_str));
            return 0;
        }
    }while(Retry_Count < 10);
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
void F_Print_Debug(enum debug_lever_e Debug_Level, const char *format, ...)
{
  if(Debug_Level == 222)
  {
    va_list arg;
#ifdef __DEBUG_TIME__
    struct timespec ts;
    struct tm tm_now;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r((time_t *)&ts.tv_sec, &tm_now);
#ifdef __DEBUG_DAY__
    prtinf("[%04u%02u%02u][%02u%02u%02u.%06ld]", tm_now.tm_year+1900, tm_now.tm_mon+1, tm_now.tm_mday, \
            tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, ts.tv_nsec / 1000);
#else
    prtinf("[%02u%02u%02u.%06ld]", tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, ts.tv_nsec / 1000);
#endif
#endif
#ifdef __DEBUG_FUNC__
    printf("[%s]", __func__);
#endif
#ifdef __DEBUG_LINE__
    printf("[%d]", __LINE__);
#endif
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
#if 1
    // Using_Timer
    int32_t TimerFd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec itval;
    struct timespec tv, tv_1;
    uint32_t usec = 100 * 1000;
    uint64_t *res = malloc(sizeof(uint64_t));
    clock_gettime(CLOCK_MONOTONIC, &tv); 
    itval.it_interval.tv_sec = 0;
    itval.it_interval.tv_nsec = (usec % 1000000) * 1e3;
    itval.it_value.tv_sec = tv.tv_sec + 1;
    itval.it_value.tv_nsec = 0;
    ret = timerfd_settime (TimerFd, TFD_TIMER_ABSTIME, &itval, NULL);
#else
    int epoll_size = 10;
    int epoll_event_count;
    struct epoll_event epoll_events[epoll_size];
	int epfd = epoll_create(epoll_size);
    epoll_event.events = EPOLLIN;
	epoll_event.data.fd = TimerFd;	epoll_ctl(epfd, EPOLL_CTL_ADD, TimerFd, &epoll_event);
#endif
    int tick_count_10ms = 0;
    for(;;)
    {        //epoll_wait(epfd, epoll_events, epoll_size, 10);
        ret = read(TimerFd, res, sizeof(uint64_t));
        if(G_TickTimer.G_100ms_Tick >= UINT32_MAX - 0x0F)
        {
            G_TickTimer.G_100ms_Tick = 0;
          }else{
            G_TickTimer.G_100ms_Tick++;
        }
        switch(G_TickTimer.G_100ms_Tick % 10)
        {
          case 0:
          {
              if(G_TickTimer.G_1000ms_Tick >= UINT32_MAX - 0x0F)
              {
                  G_TickTimer.G_1000ms_Tick = 0;
              }else{
                  G_TickTimer.G_1000ms_Tick++; 
              }
              break;
          }
          default:break;
        }
    }
    return NULL;
}
/* 
Brief:
Parameter[In]
Parameter[Out]
 */
enum job_type_e f_e_RelayServer_Job_Process_Do(struct data_header_info_t *Now_Header, uint8_t **Data)
{
    int ret;
    enum job_type_e Now_Job_State = Now_Header->Job_State;
    enum job_type_e After_Job_State;
    F_Print_Debug(222 ,"\nPress Enter Key ... Working [Job_Porcess_Do][Now State:%d]\n", Now_Header->Job_State);
    //getchar();
    switch(Now_Job_State)
    {
        case Initial: // Now_Job_State:0
            ret = f_s_RelayServer_Job_Process_Initial(Now_Header, *Data);
            break;
        case FirmwareInfoReport:// Now_Job_State:2
        case ProgramInfoReport: // Now_Job_State:7
            ret = f_i_RelayServer_Job_Process_InfoReport(Now_Header, *Data);
            break;
        case FirmwareInfoRequest: // Now_Job_State:3
        case ProgramInfoRequest:  // Now_Job_State:8
            ret = f_i_RelayServer_Job_Process_InfoRequest(Now_Header, Data);
            break;
        case FirmwareInfoResponse:// Now_Job_State:4
        case ProgramInfoResponse: // Now_Job_State:9
            ret = f_i_RelayServer_Job_Process_InfoResponse(Now_Header, Data);
            break;
        case FirmwareInfoIndication:// Now_Job_State:5
        case ProgramInfoIndication:// Now_Job_State:11
            ret = f_i_RelayServer_Job_Process_InfoIndication(Now_Header, Data);
            break;
        case Finish: // Now_Job_State:1
            ret = f_i_RelayServer_Job_Process_Finish(Now_Header, *Data);
            break;
        case HandOverReminingData:
            //f_s_RelayServer_Job_Process_HandOverReminingData()
            break;
        default:break;
    }
    if((ret > 0 && ret < 50))
    {
        After_Job_State = ret;
        G_Clients_Info.life_timer[Now_Header->Client_fd] = F_l_Timestamp() + TASK_TIMER;
    }else if(ret == 255)
    {
        After_Job_State = -1;
    }else{
        After_Job_State = 1;
    }
  
    Now_Header->Job_State = After_Job_State;
    G_Clients_Info.socket_job_state[Now_Header->Client_fd] = After_Job_State;
    return After_Job_State;
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
int f_s_RelayServer_Job_Process_Initial(struct data_header_info_t *Now_Header, uint8_t *Data)
{

     if(Data)
    {
        char *Payload = (Data + HEADER_SIZE); 

        if(Payload[0] == 0x44) // Check STX
        {
            switch((int)Payload[1])
            {
                case 1:
                    
                    if(Now_Header->Message_size >  (FIREWARE_HEADER_SIZE + FIREWARE_INFO_SIZE + 1)) //Will Make the Solution about the Over Recv Error.
                    {
                        Now_Header->Job_State = 1;
                    }else{
                        G_Clients_Info.client_data_info[Now_Header->Client_fd].Payload_Type = Fireware;
                        Now_Header->Job_State = 2;
                        Data[0] = *("2");
                    }
                    break;
                case 3:
                    if(Now_Header->Message_size > (PROGRAM_HEADER_SIZE + PROGRAM_INFO_SIZE + 1)) //Will Make the Over Recv Error Solution
                    {
                        Now_Header->Job_State = 1;
                    }
                    G_Clients_Info.client_data_info[Now_Header->Client_fd].Payload_Type = Program;
                    Now_Header->Job_State = 7;
                    Data[0] = *("7");
                    break;
                default:
                    return 1;
            }
            memcpy((G_Clients_Info.client_data_info[Now_Header->Client_fd].ID), Payload + 2, 8);
            memset((G_Clients_Info.client_data_info[Now_Header->Client_fd].Division), 0x0A, 1);
            memcpy((G_Clients_Info.client_data_info[Now_Header->Client_fd].Version), Payload + 10, 8);
        }else{
            Now_Header->Job_State = 1;
        }
    }
return Now_Header->Job_State;
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
int f_i_RelayServer_Job_Process_Finish(struct data_header_info_t *Now_Header, uint8_t *Data)
{
    F_Print_Debug(222 ,"\nNow Working Function %s\n", __func__);
    int ret;
    switch(Now_Header->Job_State)
    {
        case Finish:
            G_Clients_Info.used_state = true;
                if( G_Clients_Info.task_running[Now_Header->Client_fd] = true)
                {                         
                    G_Clients_Info.task_running[Now_Header->Client_fd] = false;
                    memset(G_Clients_Info.client_data_info[Now_Header->Client_fd].ID, 0x00, 8);
                    memset(G_Clients_Info.client_data_info[Now_Header->Client_fd].Division, 0x00, 1);
                    memset(G_Clients_Info.client_data_info[Now_Header->Client_fd].Version, 0x00, 8);
                    G_Clients_Info.life_timer[Now_Header->Client_fd] = 0;
                    G_Clients_Info.socket_message_seq[Now_Header->Client_fd] = 0;
                    G_Clients_Info.socket_job_state[Now_Header->Client_fd] = -1; 
                }
            G_Clients_Info.used_state = false;
                     break;
        default:
            break;
    }
    Now_Header->Job_State = -1;
    return Now_Header->Job_State;
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
        char *Payload = (Data + HEADER_SIZE); 
        if(Payload[0] == 0x44) // Check STX
        {
            switch(Now_Header->Job_State)
            {
                case FirmwareInfoReport:
                    if(Now_Header->Message_size == (FIREWARE_HEADER_SIZE + FIREWARE_INFO_SIZE + 1) && Payload[Now_Header->Message_size] == 0xAA)
                    {
                       
                        Now_Header->Job_State = 3;
                        Data[0] = *"3";
                        return Now_Header->Job_State;
                    }else{
                        return -3;
                    }
                    break;
                case ProgramInfoReport:
                    if(Now_Header->Message_size == (PROGRAM_HEADER_SIZE + PROGRAM_INFO_SIZE + 1) && Payload[Now_Header->Message_size] == 0xAA)
                    {
                        Now_Header->Job_State = 8;
                        Data[0] = *"8";
                        return Now_Header->Job_State;
                    }else{
                        return -8;
                    }
                default:
                    return 0;
            }          } 
    }else{
        return -1;
    }
    return 0;
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
int f_i_RelayServer_Job_Process_InfoRequest(struct data_header_info_t *Now_Header, uint8_t **Data)
{
    F_Print_Debug(222 ,"\nNow Working Function %s\n", __func__);
    if(Data)
    {
        char *Payload = (*Data + HEADER_SIZE);
        struct http_socket_info_t *http_socket_info = malloc(sizeof(struct http_socket_info_t));
        memset(http_socket_info, 0x00, sizeof(struct http_socket_info_t));
        uint8_t request_buf[HTTP_REQUEST_SIZE];
        memset(request_buf, 0x00, HTTP_REQUEST_SIZE);
        switch(Now_Header->Job_State)
        {
            case FirmwareInfoRequest:
                http_socket_info->request_len = f_i_RelayServer_HTTP_Payload(G_HTTP_Request_Info_Fireware, Payload, Now_Header->Message_size + 1, request_buf);
                if(http_socket_info->request_len > 0)
                {
                    http_socket_info->request = malloc(sizeof(uint8_t) * http_socket_info->request_len);
                    memset(http_socket_info->request, 0x00, sizeof(uint8_t) * http_socket_info->request_len);
                    memcpy(http_socket_info->request, request_buf, http_socket_info->request_len);
                }
                break;
            case ProgramInfoRequest:
                http_socket_info->request_len = f_i_RelayServer_HTTP_Payload(G_HTTP_Request_Info_Program, Payload, Now_Header->Message_size + 1, request_buf);
                if(http_socket_info->request_len > 0)
                {
                    http_socket_info->request = malloc(sizeof(uint8_t) * http_socket_info->request_len);
                    memset(http_socket_info->request, 0x00, sizeof(uint8_t) * http_socket_info->request_len);
                    memcpy(http_socket_info->request, request_buf, http_socket_info->request_len);
                }
                break;
            default:
                return -1;
        }       
        Now_Header->Job_State = f_i_RelayServer_HTTP_Task_Run(Now_Header, http_socket_info, Data);
        Relay_safefree(http_socket_info->request);
        Relay_safefree(http_socket_info);
    }else{
        return -1;
    }
    return Now_Header->Job_State;
}

struct MemoryStruct {
  char *memory;
  size_t size;
};
 
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
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
    F_Print_Debug(222 ,"\nNow Working Function %s\n", __func__);
    if(Data)
    {
        char *Payload = (*Data + HEADER_SIZE);
//* ADD 230906

        if(Now_Header->Message_size > 0)
        {
            char *url = malloc(Now_Header->Message_size);
            memset(url, 0x00, (Now_Header->Message_size));
            char *ptr = strtok(Payload, "\\");
            int p;
            memcpy(url, ptr, strlen(ptr));
            p = strlen(ptr);
            ptr = strtok(NULL, "\\");
            while(ptr)
            {
                memcpy(url + p, ptr, strlen(ptr));
                p += strlen(ptr);
                ptr = strtok(NULL, "\\");
            }
            char *URL = calloc((sizeof(char) * p) - 1, sizeof(char));
            memcpy(URL, url, p - 1);
            memset(url, 0x00, Now_Header->Message_size);
            Relay_safefree(url);
            struct MemoryStruct chunk;
            chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
            chunk.size = 0;    /* no data at this point */
            curl_global_init(CURL_GLOBAL_ALL);
            CURL *curl_handle = curl_easy_init();
            curl_easy_setopt(curl_handle, CURLOPT_URL, URL);
            curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
            curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
            curl_easy_perform(curl_handle);
            curl_easy_cleanup(curl_handle);
            curl_global_cleanup();
            Relay_safefree(URL);
            uint8_t *Http_Recv_data = malloc(sizeof(uint8_t) * (chunk.size + HEADER_SIZE));
            memset(Http_Recv_data, 0x00, sizeof(uint8_t) * (chunk.size + HEADER_SIZE));
            switch(Now_Header->Job_State)
            {
                case FirmwareInfoResponse:
                    Now_Header->Job_State = 0x5;
                    sprintf(Http_Recv_data, HEADER_PAD, 0x5, 0x0, Now_Header->Client_fd, Now_Header->Message_seq, chunk.size);
                    Now_Header->Message_size = chunk.size;
                    *Data[0] = *("5");
                    break;
                case ProgramInfoResponse:
                    Now_Header->Job_State = 0xA;
                    sprintf(Http_Recv_data, HEADER_PAD, 0xA, 0x0, Now_Header->Client_fd, Now_Header->Message_seq, chunk.size);
                    Now_Header->Message_size = chunk.size;
                    *Data[0] = *("A");
                    break;
                default:
                    return -1;
            }
            memcpy(Http_Recv_data + HEADER_SIZE, chunk.memory, chunk.size);
            Relay_safefree(chunk.memory);
            Relay_safefree(*Data);
            *Data = Http_Recv_data;
        }
    }else{
        return -1;
    }

    return Now_Header->Job_State;
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
int f_i_RelayServer_Job_Process_InfoIndication(struct data_header_info_t *Now_Header, uint8_t **Data)
{
    F_Print_Debug(222 ,"\nNow Working Function %s\n", __func__);
     if(Data)
    {
        char *Payload = *Data + HEADER_SIZE;
        int ret;
        switch(Now_Header->Job_State)
        {
            case FirmwareInfoIndication:
            case ProgramInfoIndication:
                if(Now_Header->Message_size <= 0)
                {
                    Now_Header->Job_State = 1;
                    int sock = socket(AF_INET, SOCK_DGRAM, 0);
                    struct sockaddr_in client_addr;
                    client_addr.sin_family = AF_INET;
                    client_addr.sin_addr.s_addr =  G_Clients_Info.socket[Now_Header->Client_fd];
                    client_addr.sin_port = htons(DEFAULT_UDP_PORT);
                    socklen_t client_addr_len = sizeof(client_addr);
                    ret = sendto(sock, Payload, 24, 0, (struct sockaddr *)&(client_addr), client_addr_len);
                    if(ret <= 0)
                    {
                    }else{

                    }
                    break;
                }else{
                    Now_Header->Job_State = 1;
                    int sock = socket(AF_INET, SOCK_DGRAM, 0);
                    struct sockaddr_in client_addr;
                    client_addr.sin_family = AF_INET;
                    client_addr.sin_addr.s_addr =  G_Clients_Info.socket[Now_Header->Client_fd];
                    client_addr.sin_port = htons(DEFAULT_UDP_PORT);
                    socklen_t client_addr_len = sizeof(client_addr);

                    struct data_div_hdr_t *div_hdr = malloc(sizeof(struct data_div_hdr_t));
                    div_hdr->STX = 0xAABBCCDD;
                    div_hdr->type = 0x0001;
                    div_hdr->div_len = 0x0200;
                    div_hdr->total_data_len = Now_Header->Message_size;
                    div_hdr->div_num = (div_hdr->total_data_len / div_hdr->div_len);
                    div_hdr->ecu_timer_left = 0;
                    div_hdr->ETX = 0xEEFE;
                    printf("DEBUG - [%s][%d]\n", __func__, __LINE__);
                    ret = sendto(sock, (void *)div_hdr, sizeof(struct data_div_hdr_t), 0, (struct sockaddr *)&(client_addr), client_addr_len);
                    free(div_hdr);
                    int p = 0;
                    while(0)
                    {
                        if((int)(Now_Header->Message_size / 100) >= 0)
                        {
                            ret = sendto(sock, Payload + (100 * p), 100, 0, (struct sockaddr *)&(client_addr), client_addr_len);
                        }else{
                            ret = sendto(sock, Payload + (100 * p), (Now_Header->Message_size - (100 * p)) % 100, 0, (struct sockaddr *)&(client_addr), client_addr_len);
                        }
                        p++;
                    }

                    if(ret <= 0)
                    {
                    }else{
                    }
                }
                break;
            default:
                return -1;
        }
    }else{
        return -1;
    }
    return Now_Header->Job_State;
}

int F_i_RelayServer_HTTP_Initial(uint8_t *G_HTTP_Request_Info, struct http_info_t *http_info)
{
    uint8_t *request = G_HTTP_Request_Info;
    if(http_info)
    {
        sprintf(request, "%s %s %s/%s\r\n", http_info->Request_Line.Method, http_info->Request_Line.To, http_info->Request_Line.What, http_info->Request_Line.Version);
        if(http_info->HOST){
            sprintf(request, "%s%s: %s:%s\r\n", request , "Host", http_info->HOST, http_info->PORT);
        }else{
            sprintf(request, "%s%s: %s:%s\r\n", request , "Host", DEFALUT_HTTP_SERVER_FIREWARE_URL, HTTP_HOST_PORT);
        }
        if(http_info->ACCEPT){
            sprintf(request, "%s%s: %s\r\n", request , "Accept", http_info->ACCEPT);
        }else{
            sprintf(request, "%s%s: %s\r\n", request , "Accept", DEFALUT_HTTP_ACCEPT);
        }
        if(http_info->CONTENT_TYPE){
            sprintf(request, "%s%s: %s\r\n", request , "Content-Type", http_info->CONTENT_TYPE);
        }else{
            sprintf(request, "%s%s: %s\r\n", request , "Content-Type", DEFALUT_HTTP_CONTENT_TYPE);
        }
    }else
    {
        sprintf(request, "%s %s %s/%s\r\n", DEFALUT_HTTP_METHOD, DEFALUT_HTTP_SERVER_FIREWARE_URL, "HTTP", DEFALUT_HTTP_VERSION);
        sprintf(request, "%s%s: %s\r\n", request , "Host", DEFALUT_HTTP_SERVER_FIREWARE_URL);
        sprintf(request, "%s%s: %s\r\n", request , "Accept", DEFALUT_HTTP_ACCEPT);
        sprintf(request, "%s%s: %s\r\n", request , "Content-Type", DEFALUT_HTTP_CONTENT_TYPE);
    }
    return 0;
}
size_t f_i_RelayServer_HTTP_Payload(uint8_t *G_HTTP_Request_Info, uint8_t *Body, size_t Body_Size, uint8_t *Http_Request)
{
    size_t request_len;
    if(G_HTTP_Request_Info){
        memcpy(Http_Request, G_HTTP_Request_Info, strlen(G_HTTP_Request_Info));
    }else{
        return -1;
    }
    if(Body)
    {
        if(Body_Size > 0)
        {
            sprintf(Http_Request, "%s%s: %d\r\n", Http_Request , "Content-Length", Body_Size);
        }
        sprintf(Http_Request, "%s\r\n", Http_Request);
        request_len = strlen(Http_Request) + Body_Size;
        memcpy(Http_Request + strlen(Http_Request), Body, Body_Size);
    }else {
        request_len = strlen(Http_Request) + Body_Size;
        return request_len;
    }
    return request_len;
}

int f_i_RelayServer_HTTP_Task_Run(struct data_header_info_t *Now_Header, struct http_socket_info_t *http_socket_info, uint8_t **out_data)
{
    F_Print_Debug(222 ,"\nNow Working Function %s\n", __func__);
    CURL *curl = curl_easy_init();
    switch(Now_Header->Job_State)
    {
        case FirmwareInfoRequest:
            curl_easy_setopt(curl, CURLOPT_URL, DEFALUT_HTTP_SERVER_FIREWARE_URL);
        case ProgramInfoRequest:            
            curl_easy_setopt(curl, CURLOPT_URL, DEFALUT_HTTP_SERVER_PROGRAM_URL);
        break;
        default:
            Now_Header->Job_State = 1;
            goto th_RelayServer_HTTP_Task_Receive_OUT;
            break;
    }
   
    int ret;
    CURLcode res;
    size_t buf_len = 0;
    char buf[HTTP_BUFFER_SIZE];
    int on = 1;
    curl_socket_t sockfd;     

    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        printf("Error: %s\n", curl_easy_strerror(res));
        return 1;
    }
    
    res = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);
    
    size_t nsent_total = 0;
   
    do 
    {
        size_t nsent;
        do {
            nsent = 0;
            
            res = curl_easy_send(curl, http_socket_info->request + nsent_total, http_socket_info->request_len - nsent_total, &nsent);
            nsent_total += nsent;

            if(res == CURLE_AGAIN && !f_i_RelayServer_HTTP_WaitOnSocket(sockfd, 0, HTTP_SOCKET_TIMEOUT)) {
                printf("Error: timeout.\n");
                return 1;
            }
        } while(res == CURLE_AGAIN);

        if(res != CURLE_OK) 
        {
            printf("Error: %s\n", curl_easy_strerror(res));
            return 1;
        }
    } while(nsent_total < http_socket_info->request_len);

    memset(buf, 0x00, HTTP_BUFFER_SIZE);
    buf_len = 0;
    for(;;) 
    {
            size_t nread;
            do {
                nread = 0;
                res = curl_easy_recv(curl, buf, sizeof(buf), &nread);

                if(res == CURLE_AGAIN && !f_i_RelayServer_HTTP_WaitOnSocket(sockfd, 1, HTTP_SOCKET_TIMEOUT)) {
                    printf("Error: timeout.\n");
                    return 1;
                }
                buf_len += nread;
            } while(res == CURLE_AGAIN);

            if(res != CURLE_OK) {
                printf("Error: %s\n", curl_easy_strerror(res));
                break;
            }

            if(nread == 0) {
                /* end of the response */
                break;
            }
        if(buf_len > 0)
        {
            int *Content_Length = malloc(sizeof(int));
            size_t len = sizeof(int);
            f_v_RelayServer_HTTP_Message_Parser(buf, "Content-Length: ", (void *)&Content_Length, &len);
            
            char *char_ret;
            size_t message_len = 0;
            f_v_RelayServer_HTTP_Message_Parser(buf, "idsUrl", (void *)&char_ret, &message_len);
            char *http_body = malloc(sizeof(char) * message_len);
            memcpy(http_body, char_ret, message_len);
            int http_body_len =  message_len;
            if(http_body_len > 0)
            {
                uint8_t *Http_Recv_data = malloc(sizeof(uint8_t) * (http_body_len + HEADER_SIZE));
                memset(Http_Recv_data, 0x00, sizeof(uint8_t) * (http_body_len + HEADER_SIZE));
                switch(Now_Header->Job_State)
                {
                    case FirmwareInfoRequest:
                        Now_Header->Job_State = 4;
                        sprintf(Http_Recv_data, HEADER_PAD, 0x4, 0x0, Now_Header->Client_fd, Now_Header->Message_seq, http_body_len);
                        Now_Header->Message_size = http_body_len;
                        break;
                    case ProgramInfoRequest:
                        Now_Header->Job_State = 9;
                        sprintf(Http_Recv_data, HEADER_PAD, 0x9, 0x0, Now_Header->Client_fd, Now_Header->Message_seq, http_body_len);
                        Now_Header->Message_size = http_body_len;
                        break;
                    default:
                        memset(http_body, 0x00, http_body_len);
                        Now_Header->Job_State = -1;
                        goto th_RelayServer_HTTP_Task_Receive_OUT;
                }
                memcpy(Http_Recv_data + HEADER_SIZE, http_body, http_body_len);        
                memset(http_body, 0x00, http_body_len);
                Relay_safefree(*out_data);
                *out_data = Http_Recv_data;
                goto th_RelayServer_HTTP_Task_Receive_OUT;
            }
        }
    }
    
th_RelayServer_HTTP_Task_Receive_OUT:
    /* always cleanup */
    memset(buf, 0x00, sizeof(buf));
    close(sockfd);
    curl_easy_cleanup(curl);
    return Now_Header->Job_State;
}

static void f_v_RelayServer_HTTP_Message_Parser(char *data_ptr, char *compare_word, void **ret, size_t *ret_len)
{ 
    int ptr_right = 0;
    int compare_word_len = strlen(compare_word);
    if(ret == NULL)
    {
        return;
    }
    while(data_ptr[ptr_right])
    {
        if(strncmp(data_ptr + ptr_right,  compare_word, compare_word_len) == 0)
        {
            char *ptr = strtok(data_ptr + ptr_right, "\r\n");
            *ret = ptr;
            if(*ret_len == 0)
            {
                strtok(ptr, "\"");
                strtok(NULL, "\"");
                ptr = strtok(NULL, "\"");
                *ret = ptr;
               size_t char_len = 0;
                char_len = strlen(ptr);
                *ret_len = char_len;
                return;
            }else{
                int test = atoi(ptr);
                memcpy(*ret, &test, *ret_len);
                return;
            }
            break;
        }
        ptr_right++;
    }
    *ret_len = 0;
}

int f_i_RelayServer_HTTP_WaitOnSocket(int sockfd, int for_recv, long timeout_ms)
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
extern long F_l_Timestamp()
{
	long out_time = 0;
	struct timespec tv;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tv); 
    out_time = (int)(tv.tv_sec);
    out_time = (out_time* 1e6) + (tv.tv_nsec / 1e3);
	return out_time;
}

size_t F_i_RelayServer_Data_Push(struct Used_Data_Info_t *Data_Info,  uint8_t *Data, size_t Data_size)
{    if(Data)
    {
        if(F_RelayServer_Data_isAvaialbe(Data_Info))
        {
            pthread_mutex_lock(&Data_Info->mtx);
            Data_Info->Data_Pointer_List[Data_Info->Data_Count] = malloc(sizeof(uint8_t) * Data_size);
            memcpy(Data_Info->Data_Pointer_List[Data_Info->Data_Count], Data, Data_size);
            Data_Info->Data_Size_List[Data_Info->Data_Count] = Data_size;
            Data_Info->Data_Count =  Data_Info->Data_Count + 1;
            pthread_mutex_unlock(&Data_Info->mtx);
            return Data_Info->Data_Count;
        }else{
            return Data_Info->Data_Count;
        }
    }else{
        return 0;
    }
}

void *F_v_RelayServer_Data_Pop(struct Used_Data_Info_t *Data_Info, size_t *out_size)
{     size_t data_size = 0;
    void *out_data;
    if(F_RelayServer_Data_isEmpty(Data_Info))
    {
        pthread_mutex_lock(&Data_Info->mtx);
        data_size = data_size;
        out_data = out_data;
        pthread_mutex_unlock(&Data_Info->mtx);
        return NULL;
    }else{
        pthread_mutex_lock(&Data_Info->mtx);
        if(Data_Info->Data_Count > 0)
        {
            *out_size = Data_Info->Data_Size_List[0];
            out_data = malloc(sizeof(uint8_t) * (*out_size));
            memcpy(out_data, Data_Info->Data_Pointer_List[0], *out_size);
            Relay_safefree(Data_Info->Data_Pointer_List[0]);
            memmove(&Data_Info->Data_Pointer_List[0], &Data_Info->Data_Pointer_List[1], USED_DATA_LIST_SIZE - 1);
            memmove(&Data_Info->Data_Size_List[0], &Data_Info->Data_Size_List[1], USED_DATA_LIST_SIZE - 1);
            Data_Info->Data_Count = Data_Info->Data_Count - 1;
            switch(Data_Info->type)
            {
                case INT_32: //int32Data_Count
                {                          break;
                }
                case UINT_8: //uint8 or char
                {                    break;
                }
                case OCTET_STRING: //OCTET_STRING
                {
                    break;
                }
                default: break;
            }
        }else{
        }
        pthread_mutex_unlock(&Data_Info->mtx);
             return (void *)out_data;
    }
}

bool F_RelayServer_Data_isAvaialbe(struct Used_Data_Info_t *Data_Info)
{
    bool ret;
    pthread_mutex_lock(&Data_Info->mtx);
    if(Data_Info->Data_Count <  USED_DATA_LIST_SIZE)
    {
        ret = true;
    }else{
        ret = false;
    }
    pthread_mutex_unlock(&Data_Info->mtx);
    return ret;
}

bool F_RelayServer_Data_isEmpty(struct Used_Data_Info_t *Data_Info)
{
    bool ret;
    pthread_mutex_lock(&Data_Info->mtx);
    if(Data_Info->Data_Count <= 0)
    {
        Data_Info->Data_Count  == 0;
        ret = true;
    }else{
        ret = false;
    }
    pthread_mutex_unlock(&Data_Info->mtx);
    return ret;
}

void F_Select_Timer(int time_out)
{  
  if(time_out <=0 )
  {
  }else{
    struct timeval tv;
    tv.tv_sec = (int)((time_out % 1000000) / 1000000);
    tv.tv_usec = (time_out % 1000000);
    select(0, NULL, 0, 0, &tv);
  }
  return;
}

void F_Signal_Handler(int s_signal)
{
 switch(s_signal)
 {
    case SIGSEGV:
        g_break_listen = 1;
        (void)fprintf(stdout, "SIGSEGV segment fault!\n");
        //(void)raise(s_signal);
        break;
    case SIGPIPE:
        g_break_listen = 1;
        (void)fprintf(stdout, "SIGPIPE Socket broken!\n");
        //(void)raise(s_signal);
        break;
    case 0x000000002:
        (void)fprintf(stdout, "SIGINT (%08XH)\n", s_signal);
        exit(0);
    case 0x00000000F:
        (void)fprintf(stdout, "Oprating Process Kill (%08XH)\n", s_signal);
        exit(0);
    default:
        g_break_listen = 1;
        (void)fprintf(stdout, "unknown signal ! (%08XH)\n", s_signal);
        break;
 }
 sleep(1);
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
                for(int i = 0; i < 8; i++)
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