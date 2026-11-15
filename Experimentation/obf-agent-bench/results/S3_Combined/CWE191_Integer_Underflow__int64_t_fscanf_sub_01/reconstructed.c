#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

static void printLine(const char *line)
{
    if (line != NULL)
    {
        printf("%s\n", line);
    }
}

static void printLongLongLine(int64_t longNumber)
{
    printf("%ld\n", (long)longNumber);
}

void bad(void)
{
    int64_t data = 0;
    if (fscanf(stdin, "%ld", (long *)&data) != 1)
    {
        data = 0;
    }
    int64_t result = data - 1;
    printLongLongLine(result);
}

static void goodG2B(void)
{
    int64_t data = -2;
    int64_t result = data - 1;
    printLongLongLine(result);
}

static void goodB2G(void)
{
    int64_t data = 0;
    if (fscanf(stdin, "%ld", (long *)&data) != 1)
    {
        data = 0;
    }
    if (data > LONG_MIN)
    {
        int64_t result = data - 1;
        printLongLongLine(result);
    }
    else
    {
        printLine("data value is too large to perform subtraction.");
    }
}

void good(void)
{
    goodG2B();
    goodB2G();
}

int main(int argc, char *argv[])
{
    const char *action;

    if (argc < 2)
    {
        action = "both";
    }
    else
    {
        action = argv[1];
    }

    if (strcmp(action, "bad") == 0)
    {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }
    else if (strcmp(action, "good") == 0)
    {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }
    else
    {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
