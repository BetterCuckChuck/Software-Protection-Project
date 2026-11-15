#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

void printLine(const char *line)
{
    if (line != NULL)
    {
        printf("%s\n", line);
    }
}

void printLongLongLine(int64_t value)
{
    printf("%ld\n", value);
}

static void goodG2B(void)
{
    int64_t data = 2LL;
    if (data > 0)
    {
        int64_t result = data * 2;
        printLongLongLine(result);
    }
}

static void goodB2G(void)
{
    int64_t data = 0;
    if (fscanf(stdin, "%ld", &data) != 1)
    {
        data = 0;
    }
    if (data > 0)
    {
        if (data < LLONG_MAX / 2)
        {
            int64_t result = data * 2;
            printLongLongLine(result);
        }
        else
        {
            printLine("data value is too large to perform arithmetic safely.");
        }
    }
}

void good(void)
{
    goodG2B();
    goodB2G();
}

void bad(void)
{
    int64_t data = 0;
    if (fscanf(stdin, "%ld", &data) != 1)
    {
        data = 0;
    }
    if (data > 0)
    {
        int64_t result = data * 2;
        printLongLongLine(result);
    }
}

int main(int argc, char *argv[])
{
    const char *mode = "both";
    if (argc >= 2)
    {
        mode = argv[1];
    }

    if (strcmp(mode, "bad") != 0)
    {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }
    if (strcmp(mode, "good") != 0)
    {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
