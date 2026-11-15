#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
    }
}

static void printLongLine(long longInt)
{
    printf("%ld\n", longInt);
}

static void goodG2B(void)
{
    long data = 2;
    printLongLine(data + 1);
}

static void goodB2G(void)
{
    long data = 0;
    fscanf(stdin, "%ld", &data);
    if (data != 0x7fffffffffffffffL)
    {
        printLongLine(data + 1);
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
    long data = 0;
    fscanf(stdin, "%ld", &data);
    printLongLine(data + 1);
}

int main(int argc, char *argv[])
{
    const char *mode;
    if (argc > 1)
    {
        mode = argv[1];
    }
    else
    {
        mode = "both";
    }

    if (strcmp(mode, "bad") != 0)
    {
        puts("Calling good()...");
        good();
        puts("Finished good()");
    }

    if (strcmp(mode, "good") != 0)
    {
        puts("Calling bad()...");
        bad();
        puts("Finished bad()");
    }

    return 0;
}
