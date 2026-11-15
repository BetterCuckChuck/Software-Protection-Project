#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma GCC diagnostic ignored "-Wunused-result"

static void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
    }
}

static void printLongLine(long longIntNumber)
{
    printf("%ld\n", longIntNumber);
}

static void goodG2B(void)
{
    long data;
    data = 0L;
    data = 2;
    {
        long result = data + 1;
        printLongLine(result);
    }
}

static void goodB2G(void)
{
    long data;
    data = 0L;
    fscanf(stdin, "%ld", &data);
    if (data < 0x7fffffffffffffffL)
    {
        long result = data + 1;
        printLongLine(result);
    }
    else
    {
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
    long data;
    data = 0L;
    fscanf(stdin, "%ld", &data);
    {
        long result = data + 1;
        printLongLine(result);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        puts("Calling good()...");
        good();
        puts("Finished good()");
        puts("Calling bad()...");
        bad();
        puts("Finished bad()");
    }
    else
    {
        if (strcmp(argv[1], "bad") != 0)
        {
            puts("Calling good()...");
            good();
            puts("Finished good()");
        }
        if (strcmp(argv[1], "good") != 0)
        {
            puts("Calling bad()...");
            bad();
            puts("Finished bad()");
        }
    }
    return 0;
}
