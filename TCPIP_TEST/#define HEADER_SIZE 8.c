#define HEADER_SIZE 8
enum payload_type_e
{
    Fireware,
    Program,
};

struct client_data_info_t 
{
    uint8_t ID[8];
    uint8_t Version[8];
    enum payload_type_e Payload_Type;
    size_t  Payload_Size;
}

struct clients_info_t
{
    pthread_mutex_t mtx;
    int connected_client_num;
    int socket[MAX_CLIENT_SIZE];
    enum job_type_e socket_job_state[MAX_CLIENT_SIZE];
    uint32_t socket_message_seq[MAX_CLIENT_SIZE];

    struct client_data_info_t client_data_info[MAX_CLIENT_SIZE];

}

struct data_header_info_t
{
    uint8_t Job_State;
    uint8_t Protocol_Type;
    uint16_t Client_fd;
    uint16_t Message_seq;
    uint16_t Message_size;
};

int f_i_RelayServer_Job_Process_JobFinish(struct data_header_info_t *Now_Hader, uint8_t *Data, int Client_is)
{
    if(Data)
    {
        int ret;
        switch(Now_Hader->Job_State)
        {
            case JobFinish:
                memset(G_Clients_Info.client_data_info[Client_is].ID, 0x00, 8);
                memset(G_Clients_Info.client_data_info[Client_is].Version, 0x00, 8);
                G_Clients_Info.socket_message_seq[Client_is] = 0;
                close(G_Clients_Info.socket[Client_is]);
                connected_client_num--;
            default:
                return -1;
        }
    }
    return 0;
}

int f_i_RelayServer_Job_Process_FirmwareInfoIndication(struct data_header_info_t *Now_Hader, uint8_t *Data)
{
    if(Data)
    {
        char *Payload = Data + HEADER_SIZE;
        int ret;
        switch(Now_Hader->Job_State)
        {
            case FirmwareInfoIndication:
            case ProgramInfoIndication:
                if(Now_Hader->Message_size <= 0)
                {
                    ret = send(ow_Hader->Client_fd, Payload, 20);
                    free(Data);
                    Now_Hader->Job_State = 1;
                    char *out_data = malloc(sizeof(uint8_t) * HEADER_SIZE);
                    sprintf(out_data, "%01X%01X%02X%02X%02X", 0x1, 0x0, Now_Hader->Client_fd, Now_Hader->Message_seq);
                    Data = out_data;
                    break;
                }else{
                    ret = send(ow_Hader->Client_fd, Payload, Now_Hader->Message_size);
                    free(Data);
                    Now_Hader->Job_State = 1;
                    char *out_data = malloc(sizeof(uint8_t) * HEADER_SIZE);
                    sprintf(out_data, "%01X%01X%02X%02X%02X", 0x1, 0x0, Now_Hader->Client_fd, Now_Hader->Message_seq);
                    Data = out_data;
                }
                break;
            default:
                return -1;
        }
    }
    return 0;
}

int f_i_RelayServer_Job_Process_FirmwareInfoResponse(struct data_header_info_t *Now_Hader, uint8_t *Data)
{
    if(Data)
    {
        switch(Now_Hader->Job_State)
        {
            case FirmwareInfoResponse:
                //Recv the Data From PC_Server with HTTP Protocol
                free(Data);
                char *out_data = malloc(sizeof(uint8_t) * (HEADER_SIZE + recv_data_size));
                Now_Hader->Job_State = 5;
                sprintf(out_data, "%01X%01X%02X%02X%02X", 0x5, 0x0, Now_Hader->Client_fd, Now_Hader->Message_seq, recv_data_size, recv_data);
                Data = out_data;
                break;
            case ProgramInfoResponse:
                //Recv the Data From PC_Server with HTTP Protocol
                free(Data);
                Now_Hader->Job_State = 0xA;
                char *out_data = malloc(sizeof(uint8_t) * (HEADER_SIZE + recv_data_size));
                sprintf(out_data, "%01X%01X%02X%02X%02X%s", 0xA, 0x0, Now_Hader->Client_fd, Now_Hader->Message_seq, recv_data_size, recv_data);
                Data = out_data;
                break;
            default:
                return -1;
        }
    }
    return 0;
}

int f_i_RelayServer_Job_Process_FirmwareInfoRequest(struct data_header_info_t *Now_Hader, uint8_t *Data)
{
    if(Data)
    {
        switch(Now_Hader->Job_State)
        {
            case FirmwareInfoRequest:
                //Send the Data To PC_Server with HTTP Protocol
                Now_Hader->Job_State = 4;
                free(Data);
                char *out_data = malloc(sizeof(uint8_t) * HEADER_SIZE);
                sprintf(out_data, "%01X%01X%02X%02X%02X", 0x4, 0x0, Now_Hader->Client_fd, Now_Hader->Message_seq, 0x00);
                Data = out_data;
                break;
            case ProgramInfoRequest:
                //Send the Data To PC_Server with HTTP Protocol
                Now_Hader->Job_State = 9;
                free(Data);
                char *out_data = malloc(sizeof(uint8_t) * HEADER_SIZE);
                sprintf(out_data, "%01X%01X%02X%02X%02X", 0x4, 0x0, Now_Hader->Client_fd, Now_Hader->Message_seq, 0x00);
                Data = out_data;
            default:
                return -1;
        }     
    }
    return 0;
}

int f_i_RelayServer_Job_Process_FirmwareInfoReport(struct data_header_info_t *Now_Hader, uint8_t *Data)
{
    if(Data)
    {
        char *Payload = (Data + HEADER_SIZE); 
        if(Payload[0] == 0x44) // Check STX
        {
            switch(Now_Hader->Job_State)
            {
                case FirmwareInfoReport:
                    if(Now_Hader.Message_size == 18 && Payload[Now_Hader.Message_size] == 0xAA)
                    {
                        Now_Hader->Job_State = 3;
                        Data[0] = "3";
                        return Now_Hader->Job_State;
                    }else{
                         return -3;
                    }
                    break;
                case ProgramInfoReport:
                    if(Now_Hader.Message_size == 18 && Payload[Now_Hader.Message_size] == 0xAA)
                    {
                        Now_Hader->Job_State = 8;
                        Data[0] = "8";
                        return Now_Hader->Job_State;
                    }else{
                         return -8;
                    }
                default:
                    return 0;
            }     
        } 
    }
    return 0;
}

struct client_data_info_t f_s_RelayServer_Job_Process_JobInitial(struct data_header_info_t *Now_Hader, uint8_t *Data, int *err)
{
    if(Data)
    {
        char *Payload = (Data + HEADER_SIZE); 
        struct client_data_info_t out_data;
        if(Payload[0] == 0x44) // Check STX
        {
            switch((int)Payload[1])
            {
                case 1:
                    if(Now_Hader.Message_size > 18) //Will Make the Over Recv Error Solution
                    {

                    }
                    out_data.Payload_Type = Fireware;
                    Now_Hader->Job_State = 2;
                    Data[0] = "2";
                    break;
                case 3:
                    if(Now_Hader.Message_size > 18) //Will Make the Over Recv Error Solution
                    {

                       
                    }
                    out_data.Payload_Type = Program;
                    Now_Hader->Job_State = 7;
                    Data[0] = "7";
                    break;
                default:
                    return 0;

            }
            memcpy(&(out_data.ID), Payload, 8);
            memcpy(&(out_data.Version), Payload + 8, 8);
        }
    }
    return out_data;
}
#define HEADER_SIZE 8
enum payload_type_e
{
    Fireware,
    Program,
};

struct client_data_info_t 
{
    uint8_t ID[8];
    uint8_t Version[8];
    enum payload_type_e Payload_Type;
    size_t  Payload_Size;
}

struct clients_info_t
{
    pthread_mutex_t mtx;
    int connected_client_num;
    int socket[MAX_CLIENT_SIZE];
    enum job_type_e socket_job_state[MAX_CLIENT_SIZE];
    uint32_t socket_message_seq[MAX_CLIENT_SIZE];

    struct client_data_info_t client_data_info[MAX_CLIENT_SIZE];

}

struct data_header_info_t
{
    uint8_t Job_State;
    uint8_t Protocol_Type;
    uint16_t Client_fd;
    uint16_t Message_seq;
    uint16_t Message_size;
};

struct client_data_info_t f_s_RelayServer_Job_Process_JobInitial(struct data_header_info_t *Now_Hader, uint8_t *Data, int *err);
int f_i_RelayServer_Job_Process_FirmwareInfoReport(struct data_header_info_t *Now_Hader, uint8_t *Data);
int f_i_RelayServer_Job_Process_FirmwareInfoRequest(struct data_header_info_t *Now_Hader, uint8_t *Data);
int f_i_RelayServer_Job_Process_FirmwareInfoResponse(struct data_header_info_t *Now_Hader, uint8_t *Data);
int f_i_RelayServer_Job_Process_FirmwareInfoIndication(struct data_header_info_t *Now_Hader, uint8_t *Data);
int f_i_RelayServer_Job_Process_JobFinish(struct data_header_info_t *Now_Hader, uint8_t *Data, int Client_is);

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
    int mTime = usec / 1000;
    setsockopt(TimerFd, SOL_SOCKET, SO_RCVTIMEO, (char*)&mTime, sizeof( mTime));

    clock_gettime(CLOCK_MONOTONIC, &tv); 
    itval.it_interval.tv_sec = 0;
    itval.it_interval.tv_nsec = (usec % 1000000) * 1e3;
    itval.it_value.tv_sec = tv.tv_sec + 1;
    itval.it_value.tv_nsec = 0;
    ret = timerfd_settime (TimerFd, TFD_TIMER_ABSTIME, &itval, NULL);
    uint32_t tick_count_10ms = 0;
    while(1)
    {   
        ret = read(TimerFd, &res, sizeof(res), MSG_WAITALL);
        
        G_TickTimer.G_10ms_Tick = tick_count_10ms;
        switch(tick_count_10ms % 10)
        {
            case 0:
                //printf("G_TickTimer.G_100ms_Tick:%d\n", G_TickTimer.G_100ms_Tick);
                G_TickTimer.G_100ms_Tick++;
                break;
            default: break;
        }
        switch(tick_count_10ms % 100)
        {
            case 0:
                //printf("G_TickTimer.G_1000ms_Tick:%d\n", G_TickTimer.G_1000ms_Tick);
                G_TickTimer.G_1000ms_Tick++;
                break;
            default:break;
        }
       
        tick_count_10ms++; 
    }
}