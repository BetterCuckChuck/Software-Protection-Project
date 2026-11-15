#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int globalArgc = 0;
char **globalArgv = NULL;

static void printLine(const char *line) {
    if (line != NULL) {
        puts(line);
    }
}

static void printHexCharLine(char charHex) {
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
    globalArgc = argc;
    globalArgv = argv;

    char *arg;
    if (argc < 2) {
        arg = "both";
    } else {
        arg = argv[1];
    }

    if (strcmp(arg, "bad") == 0) {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    } else if (strcmp(arg, "good") == 0) {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    } else {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
