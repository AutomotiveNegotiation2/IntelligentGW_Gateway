#define URL "https://self-api.wtest.biz/v1/system/verCheck.php"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

void f_v_RelayServer_HTTP_Message_Parser(char *data_ptr, char *compare_word, void **ret, size_t *ret_len);
/* Auxiliary function that waits on the socket. */
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
 
int main(void)
{
    CURL *curl;
    
    char data[] = {0x44, 0x01, 0x41, 0x42, 0x43, 0x44, 0x31, 0x32, 0x33, 0x34, 0x45, 0x46, 0x47, 0x48, 0x35, 0x36, 0x37, 0x38, 0xAA, 0x11, 0x12};
    
    if(gethostbyname("https://self-api.wtest.biz/v1/system/verCheck.php"))
    {
        herror("gethostbyname");
    }
    char *request = malloc(sizeof(char) * 10240);
    sprintf(request, "%s %s %s\r\n", "POST", URL, "HTTP/1.1");

    sprintf(request, "%s%s: %s\r\n",request , "Host", "https://self-api.wtest.biz/v1/system/verCheck.php");
    sprintf(request, "%s%s: %s\r\n",request , "Accept", "*/*");

    sprintf(request, "%s%s: %s\r\n",request , "Content-Type", "Application/octet-stream");
    sprintf(request, "%s%s: %d\r\n",request , "Content-Length", sizeof(data));
    sprintf(request, "%s\r\n", request);
    size_t request_len = strlen(request);
    memcpy(request + strlen(request), data, sizeof(data));
    request_len += sizeof(data);

    curl = curl_easy_init();
    if(curl) 
    {
        CURLcode res;
        curl_socket_t sockfd;
        size_t nsent_total = 0;

        curl_easy_setopt(curl, CURLOPT_URL, URL);
        curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
        res = curl_easy_perform(curl);

        if(res != CURLE_OK) {
            printf("Error: %s\n", curl_easy_strerror(res));
            return 1;
        }
        
        res = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);
        if(res != CURLE_OK) {
            printf("Error: %s\n", curl_easy_strerror(res));
            return 1;
        }

        printf("Sending request.\n");

        do 
        {
            size_t nsent;
            do {
                nsent = 0;
                
                res = curl_easy_send(curl, request + nsent_total, request_len - nsent_total, &nsent);
                nsent_total += nsent;

                if(res == CURLE_AGAIN && !wait_on_socket(sockfd, 0, 60000L)) {
                    printf("Error: timeout.\n");
                    return 1;
                }
            } while(res == CURLE_AGAIN);

            if(res != CURLE_OK) {
            printf("Error: %s\n", curl_easy_strerror(res));
            return 1;
            }

            printf("Sent %lu bytes.\n", (unsigned long)nsent);

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
            printf("\nReceived %lu bytes.\n", (unsigned long)nread);
            int *Content_Length = malloc(sizeof(int));
            size_t len = sizeof(int);
            f_v_RelayServer_HTTP_Message_Parser(buf, "Content-Length: ", (void *)Content_Length, &len);
            if(len > 0)
            {   
                printf("Content_Length:%d\n", *Content_Length);
            }
            char *char_ret;
            size_t message_len = 0;
            f_v_RelayServer_HTTP_Message_Parser(buf, "idsUrl", (void *)&char_ret, &message_len);
            char *url = malloc(sizeof(char) * message_len);
            memcpy(url, char_ret, message_len);
            printf("message_len:%d\n", message_len);
            for(int i = 0; i < message_len; i++)
            {
                printf("%c", url[i]);
            }
            printf("\n");
            
        }
       
        /* always cleanup */
        curl_easy_cleanup(curl);

    }
    return 0;
}

void f_v_RelayServer_HTTP_Message_Parser(char *data_ptr, char *compare_word, void **ret, size_t *ret_len)
{
    int ptr_right = 0;
    int compare_word_len = strlen(compare_word);
    if(ret == NULL)
    {
        return;
    }
    while(data_ptr[ptr_right])
    {
        //printf("%c", data_ptr[ptr_right]);
        if(strncmp(data_ptr + ptr_right,  compare_word, compare_word_len) == 0)
        {
            char *ptr = strtok(data_ptr + ptr_right, "\r\n");
            strtok(ptr, "\":\"");
            ptr = strtok(NULL, "\":\"");
            *ret = ptr;
            if(*ret_len == 0)
            {
               size_t char_len = 0;
               while(ptr[char_len] != 34)
               {
                    char_len++;
               }
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