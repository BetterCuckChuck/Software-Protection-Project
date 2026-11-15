#include <stdio.h>
#include <string.h>

void printLine(const char *line) {
    if (line != NULL) {
        puts(line);
    }
}

void printUnsignedLine(unsigned int unsignedNumber) {
    printf("%u\n", unsignedNumber);
}

static void goodG2B(void) {
    unsigned int data = 0;
    data = (unsigned int)-2;
    data--;
    printUnsignedLine(data);
}

static void goodB2G(void) {
    unsigned int data = 0;
    fscanf(stdin, "%u", &data);
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
    fscanf(stdin, "%u", &data);
    data--;
    printUnsignedLine(data);
}

int main(int argc, char *argv[]) {
    const char *mode = (argc < 2) ? "both" : argv[1];

    if (strcmp(mode, "bad") != 0) {
        puts("Calling good()...");
        good();
        puts("Finished good()");
    }

    if (strcmp(mode, "good") != 0) {
        puts("Calling bad()...");
        bad();
        puts("Finished bad()");
    }

    return 0;
}
