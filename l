[33mcommit ff3d76d03bfcea0315b965c2f1000639adf5591c[m
Author: eggandi <eggandyou@gmail.com>
Date:   Thu Feb 15 16:52:31 2024 +0900

    240215_V0

[1mdiff --git a/TCPIP_20231226_v0/example/Http_Test.c b/TCPIP_20231226_v0/example/Http_Test.c[m
[1mindex 4dee173..ef74d2e 100644[m
[1m--- a/TCPIP_20231226_v0/example/Http_Test.c[m
[1m+++ b/TCPIP_20231226_v0/example/Http_Test.c[m
[36m@@ -40,10 +40,6 @@[m [mint main(void)[m
     [m
     char data[] = {0x44, 0x01, 0x41, 0x42, 0x43, 0x44, 0x31, 0x32, 0x33, 0x34, 0x45, 0x46, 0x47, 0x48, 0x35, 0x36, 0x37, 0x38, 0xAA, 0x11, 0x12};[m
     [m
[31m-    if(gethostbyname("https://self-api.wtest.biz/v1/system/verCheck.php"))[m
[31m-    {[m
[31m-        herror("gethostbyname");[m
[31m-    }[m
     char *request = malloc(sizeof(char) * 10240);[m
     sprintf(request, "%s %s %s\r\n", "POST", URL, "HTTP/1.1");[m
 [m
