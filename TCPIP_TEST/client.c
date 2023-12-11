#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#define IPADDRESS "192.168.0.2"
#define PORT 8800
#define BUF_SIZE 1024
void error_handling(char *message);
void sigint_handler( int signo);
int sock;
void* th_reading(void *d);
char test_dump[] = {0x44,0x01,0x41,0x42,0x43,0x44,0x31,0x32,0x33,0x34,0x45,0x46,0x47,0x48,0x35,0x36,0x37,0x38,0xAA};
int main(int argc, char *argv[])
{
	
	if(argc!=3) {
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}	

	int interval = atoi(argv[1]);
	int num = atoi(argv[2]);
	pthread_t reading[1024];
	int count = 0;
	for(int j = 0; j < num; j++)
	{
		printf("Press Enter Key ... START TEST SCENARIO!");
		getchar();
		pthread_create(&reading[count % 1024], NULL, th_reading, argv);
		count++;
		usleep(interval * 1000);
	}
	pthread_join(reading[count % 1024 - 1], NULL);
	
	return 0;
}

void* th_reading(void *argv)
{	
	char *message = malloc(sizeof(char) * BUF_SIZE);
	int str_len;
	struct sockaddr_in serv_adr;
	sock=socket(PF_INET, SOCK_STREAM, 0);   
	
	if(sock==-1)
		error_handling("socket() error");
	
	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family=RoundAF_INET;
	serv_adr.sin_addr.s_addr=inet_addr(IPADDRESS);
	serv_adr.sin_port=htons(PORT);
	
	printf("Press Enter Key ... Connect Secure Gateway");
	getchar();
	if(connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1)
		error_handling("connect() error!");
	
	int read_th_on = 0;
	
	int recv_count = 0;
	printf("Press Enter Key ... Send A ECU Infomation to Secure Gateway");
	getchar();

	str_len = write(sock, test_dump, strlen(test_dump));
	if(str_len > 0)
	{
		printf("Send Data       ... ");
		for(int i = 0; i < strlen(test_dump); i++)
		{
			printf("%02X", test_dump[i]);
		}
		printf("\n");
	}
	
	while(1)
	{
		memset(message, 0x00, BUF_SIZE);
		str_len = read(sock, message, BUF_SIZE-1);
		if(str_len > 0)
		{
			if(str_len > 10)
			{
				recv_count++;
			}
		}
		if(recv_count >= 1)
		{
			printf("Close Socket : [%d]\n", sock);
			break;
		}
		usleep(1 * 1000);
	}
	printf("Press Enter Key ... Reading the Receive Data Form Secure Gateway");
	getchar();
	if(str_len > 0)
	{
		printf("Receive Data    ... ");
		for(int i = 0; i < str_len; i++)
		{
			printf("%C", message[i]);
		}
		printf("\n");
	}
	memset(message, 0x00, BUF_SIZE);
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
