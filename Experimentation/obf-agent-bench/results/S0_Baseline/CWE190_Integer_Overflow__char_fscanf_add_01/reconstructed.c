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

void printHexCharLine(char charHex)
{
    printf("%02x\n", (char)charHex);
}

static void bad(void)
{
    char data;
    data = ' ';
    fscanf(stdin, "%c", &data);
    {
        char result = data + 1;
        printHexCharLine(result);
    }
}

static void goodG2B(void)
{
    char data;
    data = ' ';
    data = 2;
    {
        char result = data + 1;
        printHexCharLine(result);
    }
}

static void goodB2G(void)
{
    char data;
    data = ' ';
    fscanf(stdin, "%c", &data);
    if (data < CHAR_MAX)
    {
        char result = data + 1;
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

int main(int argc, char *argv[])
{
    if (argc > 1)
    {
        if (strcmp(argv[1], "bad") != 0)
        {
            printLine("Calling good()...");
            good();
            printLine("Finished good()");
        }
        if (strcmp(argv[1], "good") != 0)
        {
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
