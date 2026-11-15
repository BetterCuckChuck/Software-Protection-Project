#include <stdio.h>
#include <string.h>

static void printHexCharLine(char c) {
    printf("%02x\n", c);
}

static void bad(void) {
    int data = -1;
    if (fscanf(stdin, "%d", &data)) {}
    printHexCharLine((char)data);
}

static void good(void) {
    printHexCharLine(0x7a);
}

int main(int argc, char *argv[]) {
    const char *mode = (argc > 1) ? argv[1] : "both";

    if (strcmp(mode, "bad") != 0) {
        puts("Calling good()...");
        good();
        puts("Finished good()");
    }

    if (strcmp(mode, "good") != 0) {
        puts("Calling bad()...");
        bad();
        puts("Finished bad()");
    }

    return 0;
}
