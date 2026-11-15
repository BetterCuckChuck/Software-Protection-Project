#include <stdio.h>
#include <string.h>

void printLine(const char *line) {
    if (line != NULL) {
        puts(line);
    }
}

void printHexCharLine(char charHex) {
    printf("%02x\n", charHex);
}

void good(void) {
    char data;

    /* goodG2B */
    data = 2;
    char result = data + 1;
    printHexCharLine(result);

    /* goodB2G */
    data = ' ';
    fscanf(stdin, "%c", &data);
    if (data != 0x7f) {
        char res = data + 1;
        printHexCharLine(res);
    } else {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

void bad(void) {
    char data = ' ';
    fscanf(stdin, "%c", &data);
    char result = data + 1;
    printHexCharLine(result);
}

int main(int argc, char *argv[]) {
    const char *action = (argc > 1) ? argv[1] : "both";

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
