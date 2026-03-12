#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

#define PACKET_SIZE 4096

int main(void) {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in dest;
    char packet[PACKET_SIZE];

    WSAStartup(MAKEWORD(2, 2), &wsa);
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    dest.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.100", &dest.sin_addr);

    memset(packet, 0, PACKET_SIZE);
    /* ICMP type 8 (echo request), code 0 */
    packet[0] = 8;
    packet[1] = 0;
    strcpy(packet + 8, "whoami");

    while (1) {
        sendto(sock, packet, 8 + (int)strlen("whoami"), 0,
               (struct sockaddr *)&dest, sizeof(dest));
        Sleep(5000);
    }
    closesocket(sock);
    WSACleanup();
    return 0;
}
#else
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PACKET_SIZE 4096
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0

unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for(sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int main() {
    int sock;
    char packet[PACKET_SIZE];
    struct iphdr *ip = (struct iphdr *)packet;
    struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in dest;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    dest.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.100", &dest.sin_addr);

    while(1) {
        memset(packet, 0, PACKET_SIZE);

        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = getpid();
        icmp->un.echo.sequence = 1;
        icmp->checksum = 0;

        char *data = packet + sizeof(struct iphdr) + sizeof(struct icmphdr);
        strcpy(data, "whoami");

        int packet_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + strlen(data);
        icmp->checksum = checksum((unsigned short *)icmp,
            sizeof(struct icmphdr) + strlen(data));

        sendto(sock, packet, packet_len, 0,
               (struct sockaddr *)&dest, sizeof(dest));
        sleep(5);
    }

    return 0;
}
#endif
