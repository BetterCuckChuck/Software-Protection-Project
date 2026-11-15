#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void printLine(const char *line) {
    if (line != NULL) {
        puts(line);
    }
}

void printUnsignedLine(unsigned int uNumber) {
    printf("%u\n", uNumber);
}

static void goodG2B(void) {
    unsigned int data = 0;
    data = 2;
    data++;
    printUnsignedLine(data);
}

static void goodB2G(void) {
    unsigned int data = 0;
    fscanf(stdin, "%u", &data);
    if (data < UINT_MAX) {
        data++;
        printUnsignedLine(data);
    } else {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

void good(void) {
    goodG2B();
    goodB2G();
}

void bad(void) {
    unsigned int data = 0;
    fscanf(stdin, "%u", &data);
    data++;
    printUnsignedLine(data);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        puts("Calling good()...");
        good();
        puts("Finished good()");
        puts("Calling bad()...");
        bad();
        puts("Finished bad()");
    } else {
        if (strcmp(argv[1], "bad") != 0) {
            puts("Calling good()...");
            good();
            puts("Finished good()");
        }
        if (strcmp(argv[1], "good") != 0) {
            puts("Calling bad()...");
            bad();
            puts("Finished bad()");
        }
    }
    return 0;
}
