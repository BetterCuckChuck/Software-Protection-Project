#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

static void printShortLine(short val) {
    printf("%hd\n", val);
}

static void good(void) {
    int data = 122;
    printShortLine((short)data);
}

static void bad(void) {
    int data = -1;
    if (fscanf(stdin, "%d", &data) <= 0) {
        // proceed with default value
    }
    printShortLine((short)data);
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
