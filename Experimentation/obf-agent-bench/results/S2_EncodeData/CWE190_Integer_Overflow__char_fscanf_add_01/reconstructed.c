#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void printLine(const char *line) {
    printf("%s\n", line);
}

static void printHexCharLine(char charHex) {
    printf("%02x\n", charHex);
}

static void goodG2B(void) {
    char data = 2;
    char result = data + 1;
    printHexCharLine(result);
}

static void goodB2G(void) {
    char data = ' ';
    fscanf(stdin, "%c", &data);
    if (data < 127) {
        char result = data + 1;
        printHexCharLine(result);
    } else {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

static void good(void) {
    goodG2B();
    goodB2G();
}

static void bad(void) {
    char data = ' ';
    fscanf(stdin, "%c", &data);
    char result = data + 1;
    printHexCharLine(result);
}

int main(int argc, char *argv[]) {
    const char *mode = (argc < 2) ? "both" : argv[1];

    if (strcmp(mode, "bad") != 0) {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }

    if (strcmp(mode, "good") != 0) {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
