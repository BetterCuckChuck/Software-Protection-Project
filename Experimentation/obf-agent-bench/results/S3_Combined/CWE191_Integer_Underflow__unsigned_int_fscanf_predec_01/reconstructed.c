#include <stdio.h>
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
    (void)!fscanf(stdin, "%u", &data);
    if (data > 0) {
        data--;
        printUnsignedLine(data);
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
    data--;
    printUnsignedLine(data);
}

int main(int argc, char *argv[]) {
    const char *action;

    if (argc > 1) {
        action = argv[1];
    } else {
        action = "both";
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
