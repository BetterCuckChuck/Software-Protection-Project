#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

static void printHexCharLine(char charHex) {
    printf("%02x\n", charHex);
}

static void good(void) {
    short data = 0x7a;
    char result = (char)data;
    printHexCharLine(result);
}

static void bad(void) {
    short data = -1;
    (void)!fscanf(stdin, "%hd", &data);
    char result = (char)data;
    printHexCharLine(result);
}

int main(int argc, char *argv[]) {
    char *action;

    if (argc < 2) {
        action = "both";
    } else {
        action = argv[1];
    }

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
