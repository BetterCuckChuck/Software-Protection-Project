#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printLine(const char *line) {
    if (line != NULL) {
        printf("%s\n", line);
    }
}

void printShortLine(short val) {
    printf("%hd\n", (int)val);
}

void good(void) {
    printShortLine(122);
}

void bad(void) {
    int data = -1;
    if (fscanf(stdin, "%d", &data) == 1) {
    }
    printShortLine((short)data);
}

int main(int argc, char *argv[]) {
    const char *arg = (argc < 2) ? "both" : argv[1];

    if (strcmp(arg, "bad") == 0) {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    } else if (strcmp(arg, "good") == 0) {
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
