#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int globalArgc = 0;
char **globalArgv = NULL;
char **globalEnvp = NULL;

static void printLine(const char *line) {
    if (line != NULL) {
        puts(line);
    }
}

static void printShortLine(short val) {
    printf("%hd\n", val);
}

static void bad(void) {
    int data = -1;
    if (fscanf(stdin, "%d", &data) != 1) {
        // keep unread value
    }
    printShortLine((short)data);
}

static void good(void) {
    printShortLine(0x7a);
}

int main(int argc, char *argv[], char *envp[]) {
    globalArgc = argc;
    globalArgv = argv;
    globalEnvp = envp;

    const char *arg = (argc > 1) ? argv[1] : "both";

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
