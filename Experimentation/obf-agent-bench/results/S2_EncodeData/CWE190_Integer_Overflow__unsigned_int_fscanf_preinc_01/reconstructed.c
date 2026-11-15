#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void printLine(const char *line)
{
    printf("%s\n", line);
}

void printUnsignedLine(unsigned int line)
{
    printf("%u\n", line);
}

static void goodG2B(void)
{
    unsigned int data = 2;
    unsigned int result = data + 1;
    printUnsignedLine(result);
}

static void goodB2G(void)
{
    unsigned int data = 0;
    fscanf(stdin, "%u", &data);
    if (data < UINT_MAX)
    {
        unsigned int result = data + 1;
        printUnsignedLine(result);
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
    unsigned int data = 0;
    fscanf(stdin, "%u", &data);
    unsigned int result = data + 1;
    printUnsignedLine(result);
}

int main(int argc, char *argv[])
{
    char *mode = (argc < 2) ? "both" : argv[1];

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
