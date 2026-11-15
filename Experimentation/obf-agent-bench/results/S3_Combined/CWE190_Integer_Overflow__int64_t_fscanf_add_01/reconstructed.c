#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

static void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

static void bad(void) {
    int64_t data = 0;
    (void)!fscanf(stdin, "%ld", &data);
    printf("%ld\n", data + 1);
}

static void goodG2B(void) {
    int64_t data = 2;
    printf("%ld\n", data + 1);
}

static void goodB2G(void) {
    int64_t data = 0;
    (void)!fscanf(stdin, "%ld", &data);
    if (data < LLONG_MAX) {
        printf("%ld\n", data + 1);
    } else {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

static void good(void) {
    goodG2B();
    goodB2G();
}

int main(int argc, char *argv[]) {
    const char *action = "both";
    if (argc > 1) {
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
