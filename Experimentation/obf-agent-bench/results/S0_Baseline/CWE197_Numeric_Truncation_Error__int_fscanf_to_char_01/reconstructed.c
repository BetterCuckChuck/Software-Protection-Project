#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printLine(const char *line) {
    if (line != NULL) {
        puts(line);
    }
}

void printHexCharLine(char charHex) {
    printf("%02x\n", charHex);
}

void good(void) {
    int data = 0x7a;
    printHexCharLine((char)data);
}

void bad(void) {
    int data = -1;
    fscanf(stdin, "%d", &data);
    printHexCharLine((char)data);
}

int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "bad") != 0) {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }
    if (argc < 2 || strcmp(argv[1], "good") != 0) {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }
    return 0;
}
