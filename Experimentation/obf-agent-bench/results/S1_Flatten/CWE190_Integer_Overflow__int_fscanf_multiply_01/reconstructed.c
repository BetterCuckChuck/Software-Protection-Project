#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int globalArgc = 0;
char **globalArgv = NULL;

void printLine(const char *line) {
    if (line != NULL) {
        puts(line);
    }
}

void printIntLine(int intNumber) {
    printf("%d\n", intNumber);
}

void bad(void) {
    int data = 0;
    if (fscanf(stdin, "%d", &data) != 1) {
        /* ignore */
    }
    if (data > 0) {
        printf("%d\n", (int)((unsigned int)data * 2));
    }
}

void good(void) {
    printf("%d\n", 4);
    int data = 0;
    if (fscanf(stdin, "%d", &data) != 1) {
        /* ignore */
    }
    if (data > 0) {
        if (data <= 1073741822) {
            printf("%d\n", data * 2);
        } else {
            puts("data value is too large to perform arithmetic safely.");
        }
    }
}

int main(int argc, char *argv[]) {
    globalArgc = argc;
    globalArgv = argv;

    const char *mode = "both";
    if (argc >= 2) {
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
