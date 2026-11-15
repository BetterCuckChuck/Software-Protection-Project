#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

void printIntLine(int intNumber) {
    printf("%d\n", intNumber);
}

static void goodG2B(void) {
    short data = 2;
    short result = data + 1;
    printIntLine(result);
}

static void goodB2G(void) {
    short data = 0;
    fscanf(stdin, "%hd", &data);
    if (data < SHRT_MAX) {
        short result = data + 1;
        printIntLine(result);
    } else {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

void good(void) {
    goodG2B();
    goodB2G();
}

void bad(void) {
    short data = 0;
    fscanf(stdin, "%hd", &data);
    short result = data + 1;
    printIntLine(result);
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
