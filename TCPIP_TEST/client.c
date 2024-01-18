#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

//440141424344313233344546474835363738FFFFFFAA


#define IPADDRESS "192.168.0.102"
#define PORT 4000
#define BUF_SIZE 1024
void error_handling(char *message);
void sigint_handler( int signo);
int sock;
void* th_reading(void *d);
char test_dump[] = {0x44, 0x01, 0x00,0x00,0x00,0x17, 0x31,0x32,0x33,0x34,0x45,0x46,0x47,0x48, 0x41,0x42,0x43,0x44,0x35,0x36,0x37,0x38,0xAA};
struct add_info_t
{
	char *ip_address;
	int port;
};
int main(int argc, char *argv[])
{
	pthread_t reading;
	if(argc!=3) {
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}	
	struct add_info_t add;
	add.ip_address = argv[1];
	add.port = atoi(argv[2]);
	pthread_create(&reading, NULL, th_reading, &add);
	pthread_join(reading, NULL);
	return 0;
}

void* th_reading(void *d)
{	
	struct add_info_t *add = (struct add_info_t*)d;
	char *message = malloc(sizeof(char) * BUF_SIZE);
	int str_len;
	struct sockaddr_in serv_adr;
	sock=socket(AF_INET, SOCK_DGRAM, 0);   
	
	if(sock==-1)
		error_handling("socket() error");

	printf("address:%s:%d\n", add->ip_address, add->port);
	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family=AF_INET;
	serv_adr.sin_addr.s_addr=inet_addr(add->ip_address);
	serv_adr.sin_port=htons(add->port);

	int read_th_on = 0;
	
	int recv_count = 0;
	printf("Press Enter Key ... Send A ECU Infomation to Secure Gateway");
	getchar();

	if(str_len > 0)
	{
		printf("Send Data       ... ");
		for(int i = 0; i < 23; i++)
		{
			printf("%02X", test_dump[i]);
		}
		printf("\n");
	}
	
	while(1)
	{
		printf("Press Enter Key ... Send A UDP DATAGRAM");
		getchar();
		str_len = sendto(sock, test_dump, strlen(test_dump), 0,\
						(struct sockaddr*)&serv_adr, sizeof(serv_adr));
	
	}

	free(message);
	close(sock);
}

void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}

void sigint_handler( int signo)
{

   return;
}
