
#define DEFAULT_NUBO_ADDRESS "192.168.0.10"
#define DEFAULT_NUBO_PORT "8888"

enum nubo_connection_state{
    GW_SLEEP_CONNECTIONING_NUBO = 0,
	
    GW_TRYING_CONNECTION_NUBO = 10,
    GW_TRYING_CONNECTION_NUBO_REPEAT_1,
    GW_TRYING_CONNECTION_NUBO_REPEAT_2,
    GW_TRYING_CONNECTION_NUBO_REPEAT_3,
    GW_TRYING_CONNECTION_NUBO_REPEAT_4,
    GW_TRYING_CONNECTION_NUBO_REPEAT_5,

    GW_SEND_REPLY_TO_NUBO = 40,
    GW_CONNECTED_BY_NUBO = 50,
    GW_WAITING_REPLY_ACK_0,
    GW_NO_REPLY_ACK_1,
    GW_NO_REPLY_ACK_2,
    GW_NO_REPLY_ACK_3,
    GW_NO_REPLY_ACK_4,
    GW_NO_REPLY_ACK_5;
};

struct nubo_recv_task_info_t
{
    int *task_info_state;
    int sock;
    struct sockaddr_in server_addr;
    socklen_t server_addr_len;
    enum nubo_connection_state state;
    char ACK[4];
    uint32_t lift_time;
};



static void *f_th_RelayServer_NUBO_Client_Task(void *d)
{
    struct nubo_recv_task_info_t *nubo_info = (struct nubo_recv_task_info_t*)d;
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
    int timer_op_1s = ((rand() % 9) + 0);
                
    for(;;)
    {      
        ret = read(TimerFd, &res, sizeof(uint64_t));
        switch(timer_100ms_tick % 10)
        {
            default:break;
            case timer_op_1s:
            {
                srand(time(NULL));//Random 값의 Seed 값 변경
                usleep(((rand() % 20) + 4) * 1000) // 매초 + 4~20ms의 랜덤값을 갖는 시간에 동작
                switch(nubo_info->state)
                {
                    default:break;
                    case GW_SLEEP_CONNECTIONING_NUBO:
                    {
                        if(!nubo_info->task_info_state)//Task  생성 시 socket 정보를 입력 안함;
                        {
                            nubo_info->task_info_state = malloc(sizeof(int));
                            nubo_info->task_info_state = 2;

                            nubo_info->sock = socket(PF_INET, SOCK_DGRAM, 0);
                            
                            memset(&nubo_info->serv_adr, 0, sizeof(nubo_info->serv_adr));
                            nubo_info->serv_adr.sin_family = AF_INET;
                            nubo_info->serv_adr.sin_addr.s_addr = inet_addr(DEFAULT_NUBO_ADDRESS);
                            nubo_info->serv_adr.sin_port = htons(atoi(DEFAULT_NUBO_PORT));
                        }else if(nubo_info->task_info_state == 1){
                            printf("!!\n");
                        }
                        //f_i_RelayServer_TcpIp_Setup_Socket(&sock, 50, true);
                        struct linger solinger = { 1, 0 };      /* Socket FD close when the app down. */
                        if (setsockopt(nubo_info->sock, SOL_SOCKET, SO_LINGER, &solinger, sizeof(struct linger)) == SO_ERROR) {
                            perror("setsockopt(SO_LINGER)");
                        }
                        struct timeval sock_tv;                  /* Socket Send/Recv Block Timer */               
                        sock_tv.tv_sec = (int)(50 / 1000);
                        sock_tv.tv_usec = (50 % 1000) * 1000; 
                        if (setsockopt(nubo_info->sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&sock_tv, sizeof(struct timeval)) == SO_ERROR) {
                            perror("setsockopt(SO_RCVTIMEO)");
                        }
                        if (setsockopt(nubo_info->sock, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&sock_tv, sizeof(struct timeval)) == SO_ERROR) {
                            perror("setsockopt(SO_SNDTIMEO)");
                        }
                        nubo_info->state = 10;
                        break;
                    }
                    case GW_TRYING_CONNECTION_NUBO:
                    case GW_TRYING_CONNECTION_NUBO_REPEAT_1:
                    case GW_TRYING_CONNECTION_NUBO_REPEAT_2:
                    case GW_TRYING_CONNECTION_NUBO_REPEAT_3:
                    case GW_TRYING_CONNECTION_NUBO_REPEAT_4:
                    {
                        ret = sendto(nubo_info->sock , nubo_info->ACK, 4, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));
                        if(ret > 0)
                        {
                            nubo_info->state = GW_CONNECTED_BY_NUBO;
                        }else{
                            nubo_info->state++;
                        }
                        break;
                    }
                    case GW_WAITING_REPLY_ACK_0:
                    case GW_NO_REPLY_ACK_1:
                    case GW_NO_REPLY_ACK_2:
                    case GW_NO_REPLY_ACK_3:
                    case GW_NO_REPLY_ACK_4:
                    {
                        struct sockaddr_in from_adr;
                        socklen_t from_adr_sz;
                        ret = recvfrom(nubo_info->sock , nubo_info->ACK, 4, 0, (struct sockaddr*)&from_adr, &from_adr_sz);
                        if(ret == 0)
                        {
                            nubo_info->state++;
                        }else(ret > 0)
                        {
                            nubo_info->state = GW_CONNECTED_BY_NUBO; 
                        }
                    }
                    case GW_CONNECTED_BY_NUBO:
                    { 
                        if(DNM_Req_Signal || DNM_Done_Signal)
                        {
                            if(DNM_Req_Signal)
                            {
                                ret = sendto(nubo_info->sock , DNM_Req_Signal, Signal_len, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));
                            }else{
                                ret = sendto(nubo_info->sock , DNM_Done_Signal, Signal_len, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));
                            }
                            
                            if(ret > 0)
                            {
                            else{
                                nubo_info->state = GW_TRYING_CONNECTION_NUBO;
                            }
                        } 
                        }
                        nubo_info->life_time++;
                        if(nubo_info->life_time % 5 == 4)
                        {
                            nubo_info->ACK[4] = (char)((nubo_info->life_time / 5) % 0xFF);
                            ret = sendto(nubo_info->sock , nubo_info->ACK, 4, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));
                            if(ret > 0)
                            {
                                nubo_info->state = GW_WAITING_REPLY_ACK_0;
                                
                            }else{
                                nubo_info->state = GW_TRYING_CONNECTION_NUBO;
                            }
                        } 

                        break;
                    }
                    case GW_NO_REPLY_ACK_5:
                    {
                        ret = recvfrom(nubo_info->sock , nubo_info->ACK, 4, 0, (struct sockaddr*)&from_adr, &from_adr_sz);
                        if(ret > 0)
                        {
                            nubo_info->state = GW_CONNECTED_BY_NUBO; 
                        }else{
                            nubo_info->state = GW_TRYING_CONNECTION_NUBO;
                        }
                        break;
                    }
                     case GW_TRYING_CONNECTION_NUBO_REPEAT_5:
                    {
                         ret = sendto(nubo_info->sock , nubo_info->ACK, 4, 0, (struct sockaddr*)&nubo_info->serv_adr, sizeof(nubo_info->serv_adr));
                        if(ret > 0)
                        {
                            nubo_info->state = GW_CONNECTED_BY_NUBO;
                        }else{
                            nubo_info->state = 0;
                        }
                        break;
                    }
                }

                if(timer_100ms_tick >= UINT32_MAX - 0xFF)//256마다 0으로 리셋 (timer_100ms_tick = 256 -> 0)
                {
                    timer_100ms_tick = 0;
                }else{
                    timer_100ms_tick++; 
                }
                break;
            }
        }
    }
    if(nubo_info->task_info_state == 2)
    {
        nubo_info->task_info_state = 0;
        free(nubo_info->task_info_state);
    }

    return NULL;
}