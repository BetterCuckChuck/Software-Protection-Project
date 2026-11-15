#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

static void printUnsignedLine(unsigned int unsignedNumber) {
    printf("%u\n", unsignedNumber);
}

static void goodG2B(void) {
    unsigned int data = 4294967293U;
    printUnsignedLine(data);
}

static void goodB2G(void) {
    unsigned int data = 0;
    if (fscanf(stdin, "%u", &data) != 1) {
        data = 0;
    }
    if (data == 0) {
        printLine("data value is too large to perform arithmetic safely.");
    } else {
        data = data - 1;
        printUnsignedLine(data);
    }
}

static void good(void) {
    goodG2B();
    goodB2G();
}

static void bad(void) {
    unsigned int data = 0;
    if (fscanf(stdin, "%u", &data) != 1) {
        data = 0;
    }
    data = data - 1;
    printUnsignedLine(data);
}

int main(int argc, char *argv[]) {
    const char *arg = "both";
    if (argc >= 2) {
        arg = argv[1];
    }

    if (strcmp(arg, "bad") != 0) {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }

    if (strcmp(arg, "good") != 0) {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
