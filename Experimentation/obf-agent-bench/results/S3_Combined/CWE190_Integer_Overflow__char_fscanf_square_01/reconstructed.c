#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <math.h>

static void printLine(const char *line)
{
    if (line != NULL)
    {
        printf("%s\n", line);
    }
}

static void printHexCharLine(char charHex)
{
    printf("%02x\n", charHex);
}

static void goodG2B(void)
{
    char data = ' ';
    data = 2;
    char result = data * data;
    printHexCharLine(result);
}

static void goodB2G(void)
{
    char data = ' ';
    fscanf(stdin, "%c", &data);
    if (abs((long)data) <= (long)sqrt((double)CHAR_MAX))
    {
        char result = data * data;
        printHexCharLine(result);
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
    char data = ' ';
    fscanf(stdin, "%c", &data);
    char result = data * data;
    printHexCharLine(result);
}

int main(int argc, char *argv[])
{
    const char *action;

    if (argc > 1)
    {
        action = argv[1];
    }
    else
    {
        action = "both";
    }

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
