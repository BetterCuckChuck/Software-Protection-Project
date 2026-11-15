#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

void printLongLine(long longInt) {
    printf("%ld\n", longInt);
}

static void goodG2B(void) {
    long data = -2L;
    long result = data - 1L;
    printLongLine(result);
}

static void goodB2G(void) {
    long data = 0L;
    (void)!fscanf(stdin, "%ld", &data);
    if (data == LONG_MIN) {
        printLine("data value is too large to perform subtraction.");
    } else {
        long result = data - 1L;
        printLongLine(result);
    }
}

static void good(void) {
    goodG2B();
    goodB2G();
}

static void bad(void) {
    long data = 0L;
    (void)!fscanf(stdin, "%ld", &data);
    long result = (long)((unsigned long)data - 1UL);
    printLongLine(result);
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
