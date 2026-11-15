#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static void printLine(const char *line)
{
    printf("%s\n", line);
}

static void printLongLine(long longLine)
{
    printf("%ld\n", longLine);
}

static void goodG2B(void)
{
    long data;
    data = 2L;
    {
        long result = data + 1;
        printLongLine(result);
    }
}

static void goodB2G(void)
{
    long data = 0L;
    fscanf(stdin, "%ld", &data);
    if (data < LONG_MAX)
    {
        long result = data + 1;
        printLongLine(result);
    }
    else
    {
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
    long data = 0L;
    fscanf(stdin, "%ld", &data);
    {
        long result = data + 1;
        printLongLine(result);
    }
}

int main(int argc, char *argv[])
{
    const char *action = (argc > 1) ? argv[1] : "both";

    if (strcmp(action, "bad") != 0)
    {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }

    if (strcmp(action, "good") != 0)
    {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
