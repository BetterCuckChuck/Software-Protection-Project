#include <stdio.h>
#include <string.h>

static void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

static void printHexCharLine(char c) {
    printf("%02x\n", (int)c);
}

static void bad(void) {
    char data = ' ';
    if (fscanf(stdin, "%c", &data) <= 0) {
    }
    char result = data + 1;
    printHexCharLine(result);
}

static void goodG2B(void) {
    char data = 2;
    char result = data + 1;
    printHexCharLine(result);
}

static void goodB2G(void) {
    char data = ' ';
    if (fscanf(stdin, "%c", &data) <= 0) {
    }
    if (data < 127) {
        char result = data + 1;
        printHexCharLine(result);
    } else {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

static void good(void) {
    goodG2B();
    goodB2G();
}

int main(int argc, char *argv[]) {
    const char *mode;
    if (argc > 1) {
        mode = argv[1];
    } else {
        mode = "both";
    }

    if (strcmp(mode, "bad") == 0) {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    } else if (strcmp(mode, "good") == 0) {
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
