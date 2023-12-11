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

#include <stdarg.h>

/* Util IPV6_Task */
#include <sys/ioctl.h>
#include <linux/socket.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <./memory_allocation_include.h>
#include <./memory_allocation_api.h>
#include <./memory_allocation_param.h>

#define DeviceName "eth0"

struct socket_info_t
{
    //Sokket_Info
    enum socket_type_e Socket_Type;
    int Socket;
    char *Device_Name;
    char Device_IPv4_Address[40];
    int Port;
    struct sockaddr_in Socket_Addr;
};
/* 
Brief:
Parameter[In]
Parameter[Out]
    socket_info_t
 */
struct socket_info_t F_s_RelayServer_TcpIp_Initial_Server(char *Device_Name, int *Port, int *err)
{
    int ret = 0;
    
    //Check Argurements
    if(!Device_Name || !Port)
    {
        F_RealyServer_Print_Debug(0, "[Error][F_i_RelayServer_TcpIp_Server_Initial] No Input Argurements.(Server_Socket:%p, Device_Name:%p, Port:%p)\n", Server_Socket, Device_Name, Port);
        *err = -1;
        return;
    }else{
        struct socket_info_t Socket_Info;
        Socket_Info.Socket_Type = SERVER_SOCKET;
        Socket_Info.Device_Name = Device_Name;
        Socket_Info.Port = *Port;
    }

    //Getting the Ethernet Device IP Address  
    ret = F_i_RelayServer_TcpIp_Get_Address(Socket_Info.Device_Name, Socket_Info.Device_IPv4_Address);
    if(ret < 0)
    {
        F_RealyServer_Print_Debug(0,"[Error][F_i_RelayServer_TcpIp_Get_Address] Return_Value:%d\n", ret);
        *err = -1;
        return;
    }
    *Server_Socket = socket(AF_INET, SOCK_STREAM, 0);
    //Socket_Setup
    ret = f_i_RelayServer_TcpIp_Setup_Socket(Socket_Info.Socket, 500, true);
    if(ret < 0)
    {
        F_RealyServer_Print_Debug(0,"[Error][f_i_RelayServer_TcpIp_Socket_Setup] Return_Value:%d\n", ret);
        *err = -1;
        return;
    }

    memset(&Socket_Info.socket_addr, 0x00, sizeof(Socket_Info.socket_addr));  
	Socket_Info.socket_addr.sin_family = AF_INET;  
	Socket_Info.socket_addr.sin_addr.s_addr = inet_addr(Socket_Info.Device_IPv4_Address);
	Socket_Info.socket_addr.sin_port = htons(Socket_Info.Port)

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
int F_i_RelayServer_TcpIp_Get_Address(chat *Device_Name, char Output_IPv4Adrress[40])
{
    int ret = 0;

    //Check Argurement
    if(!Device_Name)
    {
        F_RealyServer_Print_Debug(0, "[Error][F_i_RelayServer_TcpIp_Get_Address] No Input Argurements.(Device_Name:%p)\n", Device_Name);
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
		F_RealyServer_Print_Debug(1, "%s IP Address is %s\n", Device_Name, Output_IPv4Adrress);
	}
    ret = f_i_RelayServer_TcpIp_Setup_Socket(&socket, 0, true);
	close(IP_Parsing_Socket);

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
void F_RealyServer_Print_Debug(enum debug_lever_e Debug_Level, const char *Strin g, const char *format, ...)
{

  if(Debug_Level >= G_Debug_Level)
  {
    va_list arg;
    struct timespec ts;
    struct tm tm_now;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r((time_t *)&ts.tv_sec, &tm_now);
    fprintf(stderr, "[%04u%02u%02u.%02u%02u%02u.%06ld][%s] ", tm_now.tm_year+1900, tm_now.tm_mon+1, tm_now.tm_mday,
            tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, ts.tv_nsec / 1000, String);

    va_start(arg, format);
    vprintf(format, arg);
    va_end(arg);
  }else{
    return;
  }
}

pthread_t F_i_RelayServer_TcpIp_Task_Run(struct socket_info_t *Socket_Info)
{
    int ret;   
    ret = f_i_RelayServer_TcpIp_Bind(&Socket_Info->Socket, &Socket_Info->Socket_Addr);
    if(ret < 0)
    {
        return (pthread_t)ret;
    }else{

        pthread_t th_id;
        pthread_create(&(th_id), Th_RelayServer_TcpIp_Task_Server, NULL,(void*)&Socket_Info);
        pthread_detach(th_id); 
    }

    return th_id;
}
void* Th_RelayServer_TcpIp_Task_Server(void *data)
{
    int ret;
    struct socket_info_t *Socket_Info = (struct socket_info_t*)data;

    ret = listen(Socket_Info->Socket, 5);
    if(ret < 0)
    {
        F_RealyServer_Print_Debug(0,"[Error][Th_RelayServer_TcpIp_Task_Server][listen] Return_Value:%d\n", ret);
        return;
    }

    int epoll_size = 10;
    int epoll_count;
    struct epoll_event *epoll_events= malloc(sizeof(struct epoll_event)*epoll_size);

	int epfd = epoll_create(epoll_size);
    if(epfd <= 0)
    {
        F_RealyServer_Print_Debug(0,"[Error][Th_RelayServer_TcpIp_Task_Server][epoll_create] Return_Value:%d\n", epfd);
        return;
    }
	struct epoll_event epoll_event;
    epoll_event.events = EPOLLIN;
	epoll_event.data.fd = Socket_Info->Socket;	
	epoll_ctl(epfd, EPOLL_CTL_ADD, Socket_Info->Socket, &epoll_event);

    while(1)
    {
        

    }

    


}
int f_i_RelayServer_TcpIp_Bind(int *Server_Socket, struct sockaddr_in Socket_Addr)
{
    int ret;
    int Retry_Max = 10;

    do
    {
        ret = bind(Server_Socket, (struct sockaddr*)&(Socket_Addr), sizeof(Socket_Addr));
        if(ret < 0 ) 
        {
            F_RealyServer_Print_Debug(0, "[Error][f_i_RelayServer_TcpIp_Bind][Return_Value:%d]", ret);
            if(Retry_Count == 9)
            {
                close(Server_Socket);
                return -1;
            }
            Retry_Count++
        }else{
            char addr_str[40];
            inet_ntop(AF_INET, (void *)&Socket_Addr.sin_addr, addr_str, sizeof(addr_str));
            F_RealyServer_Print_Debug(1, "[Sucess][f_i_RelayServer_TcpIp_Bind] 
            Server_Socket:%d;
            Ip:Port:%s:%d\n", 
            *Server_Socket, addr_str, Socket_Addr.sin_port);
            return 0;
        }
    }while(Retry_Count < 10);
        
}

void *th_tcpip_server_epoll_run(void *data)
{
    (void *) data;

    int ret; /* Return_Value */
    int Epoll_Event_Max = 5;
    int Epoll_File_Descriptor;
    int Timer_File_Descriptor;

    struct epoll_event Structure_Epoll_Event_List[5Epoll_Event_Max];
    struct epoll_event structure_Epoll_Event;

    unsigned int Timer_Interval_Value;
    struct itimerspec Structure_Interval_Time_Value;
    struct timeval Time_Value;

    Timer_Interval_Value = 1000 * 1000;

    ret = timerfd_settime(Timer_File_Descriptor, TFD_TIMER_ABSTIME &Structure_Interval_Time_Value, NULL);
    
    Epoll_File_Descriptor = epoll_creat(Epoll_Event_Max);
    while(1)
    {

    }

}


int f_i_RelayServer_TcpIp_Setup_Socket(int *Socket, int Timer, bool Linger)
{
    
    if(!Socket || Timer <= 0)
    {
        F_RealyServer_Print_Debug(0, "[Error][f_i_RelayServer_TcpIp_Socket_Setup][No Input Argurements.](Socket:%p, Timer:%d)\n", Socket, Timer);
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
        tv.tv_sec = 0;
        tv.tv_usec = (Timer % 1000) * 1000; 
        if (setsockopt(*Socket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv,sizeof(struct timeval)) == SO_ERROR) {
            perror("setsockopt(SO_RCVTIMEO)");
            return -2;
        }
        if (setsockopt(*Socket, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&tv,sizeof(struct timeval)) == SO_ERROR) {
            perror("setsockopt(SO_SNDTIMEO)");
            return -1;
        }
    }

}