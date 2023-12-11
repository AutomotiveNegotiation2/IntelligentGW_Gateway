#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>

#define BUF_SIZE 100
#define EPOLL_SIZE 50
void error_handling(char *buf);
void* th_server_0(void *d);
void* th_server_1(void *d);
#define Device_IP_0 "192.168.0.2"
#define Device_IP_1 "192.168.2.4"

struct epoll_event *ep_events_0;
struct epoll_event *ep_events_1;
int event_cnt_0, event_cnt_1;
int serv_sock_0, serv_sock_1;
int main(int argc, char *argv[])
{
	pthread_t server_0, server_1;
	pthread_create(&server_0, NULL, th_server_0, NULL);
	
	//pthread_create(&server_1, NULL, th_server_1, NULL);
	pthread_join(server_0, NULL);
	//pthread_join(server_1, NULL);
	
	while(1)
	{
		sleep(1);
	}
	return 0;
}

void *th_server_0(void *d)
{
	int serv_sock, clnt_sock;
	struct sockaddr_in serv_adr, clnt_adr;
	socklen_t adr_sz;
	int str_len, i;
	char buf[BUF_SIZE];

	struct epoll_event event;
	int epfd, event_cnt;

	serv_sock=socket(PF_INET, SOCK_STREAM, 0);
	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family=AF_INET;
	serv_adr.sin_addr.s_addr=htonl(INADDR_ANY);
	serv_adr.sin_port=htons((8800));
	
	char Device_IP_Address[40];
	inet_ntop(AF_INET, (void *)&serv_adr.sin_addr, Device_IP_Address, sizeof(struct sockaddr));
	printf("IP Address is %s\n", Device_IP_Address);
	
	if(bind(serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr))==-1)
		error_handling("bind() error");
	if(listen(serv_sock, 5)==-1)
		error_handling("listen() error");

	epfd=epoll_create(EPOLL_SIZE);
	ep_events_0=malloc(sizeof(struct epoll_event)*EPOLL_SIZE);

	event.events=EPOLLIN;
	event.data.fd=serv_sock;	
	epoll_ctl(epfd, EPOLL_CTL_ADD, serv_sock, &event);
	serv_sock_0 = serv_sock;
	while(1)
	{
		event_cnt=epoll_wait(epfd, ep_events_0, EPOLL_SIZE, -1);
		event_cnt_0 = event_cnt;
		if(event_cnt==-1)
		{
			puts("epoll_wait() error");
			break;
		}

		for(i=0; i<event_cnt; i++)
		{
			if(ep_events_0[i].data.fd==serv_sock)
			{
				adr_sz=sizeof(clnt_adr);
				clnt_sock=
					accept(serv_sock, (struct sockaddr*)&clnt_adr, &adr_sz);
				event.events=EPOLLIN;
				event.data.fd=clnt_sock;
				epoll_ctl(epfd, EPOLL_CTL_ADD, clnt_sock, &event);
				printf("connected client: %d \n", clnt_sock);
			}
			else
			{
					str_len=read(ep_events_0[i].data.fd, buf, BUF_SIZE);
					if(str_len==0)    // close request!
					{
						epoll_ctl(
							epfd, EPOLL_CTL_DEL, ep_events_0[i].data.fd, NULL);
						close(ep_events_0[i].data.fd);
						printf("closed client: %d \n", ep_events_0[i].data.fd);
					}
					else
					{
						write(ep_events_0[i].data.fd, buf, str_len);    // echo!
						for(int j=0; j<event_cnt_1; j++)
						{
							if(ep_events_1[j].data.fd==serv_sock_1)
							{
							}
							else
							{
								write(ep_events_1[j].data.fd, buf, str_len);    // echo!
							}
						}
						
					}
	
			}
		}
	}
	close(serv_sock);
	close(epfd);
}

void *th_server_1(void *d)
{
	int serv_sock, clnt_sock;
	struct sockaddr_in serv_adr, clnt_adr;
	socklen_t adr_sz;
	int str_len, i;
	char buf[BUF_SIZE];

	struct epoll_event *ep_events;
	struct epoll_event event;
	int epfd, event_cnt;

	serv_sock=socket(PF_INET, SOCK_STREAM, 0);
	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family=AF_INET;
	serv_adr.sin_addr.s_addr=inet_addr(Device_IP_1);
	serv_adr.sin_port=htons((8800));
	
	char Device_IP_Address[40];
	inet_ntop(AF_INET, (void *)&serv_adr.sin_addr, Device_IP_Address, sizeof(struct sockaddr));
	printf("IP Address is %s\n", Device_IP_Address);
	
	if(bind(serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr))==-1)
		error_handling("bind() error");
	if(listen(serv_sock, 5)==-1)
		error_handling("listen() error");

	epfd=epoll_create(EPOLL_SIZE);
	ep_events_1=malloc(sizeof(struct epoll_event)*EPOLL_SIZE);

	event.events=EPOLLIN;
	event.data.fd=serv_sock;	
	epoll_ctl(epfd, EPOLL_CTL_ADD, serv_sock, &event);
	serv_sock_1 = serv_sock;
	while(1)
	{
		event_cnt=epoll_wait(epfd, ep_events_1, EPOLL_SIZE, -1);
		event_cnt_1 = event_cnt;
		if(event_cnt==-1)
		{
			puts("epoll_wait() error");
			break;
		}
		for(i=0; i<event_cnt; i++)
		{
			if(ep_events_1[i].data.fd==serv_sock)
			{
				adr_sz=sizeof(clnt_adr);
				clnt_sock=
					accept(serv_sock, (struct sockaddr*)&clnt_adr, &adr_sz);
				event.events=EPOLLIN;
				event.data.fd=clnt_sock;
				epoll_ctl(epfd, EPOLL_CTL_ADD, clnt_sock, &event);
				printf("connected client: %d \n", clnt_sock);
			}
			else
			{

					str_len=read(ep_events_1[i].data.fd, buf, BUF_SIZE);
					if(str_len==0)    // close request!
					{
						epoll_ctl(
							epfd, EPOLL_CTL_DEL, ep_events_1[i].data.fd, NULL);
						close(ep_events_1[i].data.fd);
						printf("closed client: %d \n", ep_events_1[i].data.fd);
					}
					else
					{
						write(ep_events_1[i].data.fd, buf, str_len);    // echo!
						for(int j=0; j<event_cnt_0; j++)
						{
							if(ep_events_0[j].data.fd==serv_sock_0)
							{
							}
							else
							{
								write(ep_events_0[j].data.fd, buf, str_len);    // echo!
							}
						}
					}
	
			}
		}
	}
	close(serv_sock);
	close(epfd);
}
void error_handling(char *buf)
{
	fputs(buf, stderr);
	fputc('\n', stderr);
	exit(1);
}