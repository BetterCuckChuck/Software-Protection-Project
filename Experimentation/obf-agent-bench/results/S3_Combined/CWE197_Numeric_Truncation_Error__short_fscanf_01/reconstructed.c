#include <stdio.h>
#include <string.h>

static void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

static void printHexCharLine(char charHex) {
    printf("%02x\n", charHex);
}

static void bad(void) {
    short data = -1;
    if (fscanf(stdin, "%hd", &data) <= 0) {
    }
    printHexCharLine((char)data);
}

static void good1(void) {
    printHexCharLine(0x7a);
}

int main(int argc, char *argv[]) {
    const char *mode;

    if (argc < 2) {
        mode = "both";
    } else {
        mode = argv[1];
    }

    if (strcmp(mode, "bad") != 0) {
        printLine("Calling good()...");
        good1();
        printLine("Finished good()");
    }

    if (strcmp(mode, "good") != 0) {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
