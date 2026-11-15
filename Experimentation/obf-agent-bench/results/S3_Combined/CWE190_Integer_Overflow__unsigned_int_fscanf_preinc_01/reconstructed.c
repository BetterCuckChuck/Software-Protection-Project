#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static void printLine(const char *line)
{
    if (line != NULL)
    {
        printf("%s\n", line);
    }
}

static void printUnsignedLine(unsigned int unsignedNumber)
{
    printf("%u\n", unsignedNumber);
}

static void bad(void)
{
    unsigned int data = 0;
    (void)!fscanf(stdin, "%u", &data);
    unsigned int result = data + 1;
    printUnsignedLine(result);
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
    (void)!fscanf(stdin, "%u", &data);
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

static void good(void)
{
    goodG2B();
    goodB2G();
}

int main(int argc, char *argv[])
{
    const char *action;

    if (argc >= 2)
    {
        action = argv[1];
    }
    else
    {
        action = "both";
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
