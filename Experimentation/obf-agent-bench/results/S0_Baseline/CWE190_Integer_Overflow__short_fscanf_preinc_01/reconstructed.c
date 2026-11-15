#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printLine(const char *line)
{
    if (line != NULL) {
        puts(line);
    }
}

void printIntLine(int intNumber)
{
    printf("%d\n", intNumber);
}

void bad(void)
{
    short data = 0;
    fscanf(stdin, "%hd", &data);
    short result = data + 1;
    printIntLine(result);
}

static void goodG2B(void)
{
    short data = 2;
    short result = data + 1;
    printIntLine(result);
}

static void goodB2G(void)
{
    short data = 0;
    fscanf(stdin, "%hd", &data);
    if (data < 0x7fff) {
        short result = data + 1;
        printIntLine(result);
    } else {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

void good(void)
{
    goodG2B();
    goodB2G();
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    } else {
        if (strcmp(argv[1], "bad") != 0) {
            printLine("Calling good()...");
            good();
            printLine("Finished good()");
        }
        if (strcmp(argv[1], "good") != 0) {
            printLine("Calling bad()...");
            bad();
            printLine("Finished bad()");
        }
    }
    return 0;
}
