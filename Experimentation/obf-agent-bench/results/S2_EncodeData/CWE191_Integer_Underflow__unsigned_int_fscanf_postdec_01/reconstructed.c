#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

static void printUnsignedLine(unsigned int line) {
    printf("%u\n", line);
}

static void goodG2B(void) {
    unsigned int data = 4294967294U;
    unsigned int result = data - 1;
    printUnsignedLine(result);
}

static void goodB2G(void) {
    unsigned int data = 0;
    (void)!fscanf(stdin, "%u", &data);
    if (data > 0) {
        unsigned int result = data - 1;
        printUnsignedLine(result);
    } else {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

static void good(void) {
    goodG2B();
    goodB2G();
}

static void bad(void) {
    unsigned int data = 0;
    (void)!fscanf(stdin, "%u", &data);
    unsigned int result = data - 1;
    printUnsignedLine(result);
}

int main(int argc, char *argv[]) {
    char *mode;
    if (argc < 2) {
        mode = "both";
    } else {
        mode = argv[1];
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
