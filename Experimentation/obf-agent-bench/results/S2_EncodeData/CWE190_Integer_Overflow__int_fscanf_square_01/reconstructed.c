#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void printLine(const char *line)
{
    if (line != NULL) {
        printf("%s\n", line);
    }
}

void printIntLine(int intNumber)
{
    printf("%d\n", intNumber);
}

static void goodG2B(void)
{
    int data = 2;
    int result = data * data;
    printIntLine(result);
}

static void goodB2G(void)
{
    int data = 0;
    fscanf(stdin, "%d", &data);
    if (data != INT_MIN && abs(data) < 46340) {
        int result = data * data;
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

void bad(void)
{
    int data = 0;
    fscanf(stdin, "%d", &data);
    int result = (int)((unsigned int)data * (unsigned int)data);
    printIntLine(result);
}

int main(int argc, char *argv[])
{
    const char *action;

    if (argc < 2) {
        action = "both";
    } else {
        action = argv[1];
    }

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
