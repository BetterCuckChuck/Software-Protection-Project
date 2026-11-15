#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

static void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
    }
}

static void printLongLongLine(int64_t longLongIntNumber)
{
    printf("%ld\n", longLongIntNumber);
}

static void goodG2B(void)
{
    int64_t data;
    data = 0LL;
    data = 2;
    if (data > 0)
    {
        int64_t result = data * 2;
        printLongLongLine(result);
    }
}

static void goodB2G(void)
{
    int64_t data;
    data = 0LL;
    fscanf(stdin, "%ld", &data);
    if (data > 0)
    {
        if (data < (LLONG_MAX / 2))
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

static void good(void)
{
    goodG2B();
    goodB2G();
}

static void bad(void)
{
    int64_t data;
    data = 0LL;
    fscanf(stdin, "%ld", &data);
    if (data > 0)
    {
        int64_t result = data * 2;
        printLongLongLine(result);
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
