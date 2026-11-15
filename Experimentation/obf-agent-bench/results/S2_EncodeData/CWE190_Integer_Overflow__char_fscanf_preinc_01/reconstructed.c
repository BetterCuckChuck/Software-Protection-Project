#include <stdio.h>
#include <string.h>

static void printLine(const char *line)
{
    if (line != NULL) {
        printf("%s\n", line);
    }
}

static void printHexCharLine(char c)
{
    printf("%02x\n", c);
}

static void goodG2B(void)
{
    char data = 2;
    char result = data + 1;
    printHexCharLine(result);
}

static void goodB2G(void)
{
    char data = ' ';
    if (fscanf(stdin, "%c", &data)) {}
    if (data < 127) {
        char result = data + 1;
        printHexCharLine(result);
    } else {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

static void good(void)
{
    goodG2B();
    goodB2G();
}

static void bad(void)
{
    char data = ' ';
    if (fscanf(stdin, "%c", &data)) {}
    char result = data + 1;
    printHexCharLine(result);
}

int main(int argc, char *argv[])
{
    int run_good = 1;
    int run_bad = 1;

    if (argc >= 2) {
        if (strcmp(argv[1], "bad") == 0) {
            run_good = 0;
        } else if (strcmp(argv[1], "good") == 0) {
            run_bad = 0;
        }
    }

    if (run_good) {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }
    if (run_bad) {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
