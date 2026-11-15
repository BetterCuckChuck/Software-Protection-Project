#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
    }
}

void printLongLine(long longNumber)
{
    printf("%ld\n", longNumber);
}

void bad(void)
{
    long data = 0L;
    fscanf(stdin, "%ld", &data);
    printLongLine(data - 1);
}

static void goodG2B(void)
{
    long data = 0L;
    data = -2;
    printLongLine(data - 1);
}

static void goodB2G(void)
{
    long data = 0L;
    fscanf(stdin, "%ld", &data);
    if (data > LONG_MIN)
    {
        printLongLine(data - 1);
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
    const char *mode = (argc > 1) ? argv[1] : "both";

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
