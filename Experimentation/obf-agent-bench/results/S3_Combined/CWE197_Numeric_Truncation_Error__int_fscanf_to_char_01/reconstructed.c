#include <stdio.h>
#include <string.h>

void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

void printHexCharLine(char charHex) {
    printf("%02x\n", charHex);
}

void goodG2B(void) {
    char data = 0x7a;
    printHexCharLine(data);
}

void good(void) {
    goodG2B();
}

void bad(void) {
    int data = -1;
    fscanf(stdin, "%d", &data);
    printHexCharLine((char)data);
}

int main(int argc, char *argv[]) {
    const char *action = (argc < 2) ? "both" : argv[1];

    if (strcmp(action, "bad") != 0) {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }

    if (strcmp(action, "good") != 0) {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
