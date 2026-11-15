#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static void printLine(const char *line) {
    if (line != NULL) {
        puts(line);
    }
}

static void goodG2B(void) {
    int data = 2;
    printf("%d\n", data * data);
}

static void goodB2G(void) {
    int data = 0;
    fscanf(stdin, "%d", &data);
    if (data == INT_MIN || abs(data) > 46339) {
        printLine("data value is too large to perform arithmetic safely.");
    } else {
        printf("%d\n", data * data);
    }
}

static void good(void) {
    goodG2B();
    goodB2G();
}

static void bad(void) {
    int data = 0;
    fscanf(stdin, "%d", &data);
    printf("%d\n", data * data);
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
