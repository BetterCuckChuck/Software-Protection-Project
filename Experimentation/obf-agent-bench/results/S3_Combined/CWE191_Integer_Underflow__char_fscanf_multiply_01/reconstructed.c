#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

void printHexCharLine(char charHex) {
    printf("%02x\n", charHex);
}

static void bad(void) {
    char data = ' ';
    fscanf(stdin, "%c", &data);
    if (data < 0) {
        char result = data * 2;
        printHexCharLine(result);
    }
}

static void goodG2B(void) {
    char data = -2;
    if (data < 0) {
        char result = data * 2;
        printHexCharLine(result);
    }
}

static void goodB2G(void) {
    char data = ' ';
    fscanf(stdin, "%c", &data);
    if (data < 0) {
        if (data > (CHAR_MIN / 2)) {
            char result = data * 2;
            printHexCharLine(result);
        } else {
            printLine("data value is too small to perform multiplication.");
        }
    }
}

static void good(void) {
    goodG2B();
    goodB2G();
}

int main(int argc, char *argv[]) {
    const char *mode;

    if (argc > 1) {
        mode = argv[1];
    } else {
        mode = "both";
    }

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
