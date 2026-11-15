#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printHexCharLine(char charHex) {
    printf("%02x\n", charHex);
}

void printLine(const char *line) {
    if (line != NULL) {
        puts(line);
    }
}

static void goodG2B(void) {
    char data;
    data = ' ';
    data = 2;
    char result = data * data;
    printHexCharLine(result);
}

static void goodB2G(void) {
    char data;
    data = ' ';
    if (fscanf(stdin, "%c", &data) == 1) {}
    if (abs((int)data) <= 11) {
        char result = data * data;
        printHexCharLine(result);
    } else {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

void good(void) {
    goodG2B();
    goodB2G();
}

void bad(void) {
    char data;
    data = ' ';
    if (fscanf(stdin, "%c", &data) == 1) {}
    char result = data * data;
    printHexCharLine(result);
}

int main(int argc, char *argv[]) {
    char *instruction;
    if (argc > 1) {
        instruction = argv[1];
    } else {
        instruction = "both";
    }

    if (strcmp(instruction, "bad") != 0) {
        puts("Calling good()...");
        good();
        puts("Finished good()");
    }

    if (strcmp(instruction, "good") != 0) {
        puts("Calling bad()...");
        bad();
        puts("Finished bad()");
    }

    return 0;
}
