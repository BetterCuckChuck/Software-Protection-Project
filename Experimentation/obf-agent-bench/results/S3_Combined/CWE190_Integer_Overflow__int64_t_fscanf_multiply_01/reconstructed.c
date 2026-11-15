#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

static void printLine(const char *line)
{
    if (line != NULL)
    {
        printf("%s\n", line);
    }
}

static void printLongLongLine(int64_t value)
{
    printf("%ld\n", (long)value);
}

static void bad(void)
{
    int64_t data = 0;
    if (fscanf(stdin, "%ld", &data) <= 0) {}
    if (data > 0)
    {
        int64_t result = (int64_t)((uint64_t)data * 2);
        printLongLongLine(result);
    }
}

static void goodG2B(void)
{
    int64_t data = 2;
    if (data > 0)
    {
        int64_t result = (int64_t)((uint64_t)data * 2);
        printLongLongLine(result);
    }
}

static void goodB2G(void)
{
    int64_t data = 0;
    if (fscanf(stdin, "%ld", &data) <= 0) {}
    if (data > 0)
    {
        if (data < LLONG_MAX / 2)
        {
            int64_t result = (int64_t)((uint64_t)data * 2);
            printLongLongLine(result);
        }
        else
        {
            printLine("data value is too large to perform arithmetic safely.");
        }
    }
}

static void good(void)
{
    goodG2B();
    goodB2G();
}

int main(int argc, char *argv[])
{
    if (argc > 1)
    {
        if (strcmp(argv[1], "bad") == 0)
        {
            printLine("Calling bad()...");
            bad();
            printLine("Finished bad()");
        }
        else if (strcmp(argv[1], "good") == 0)
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
