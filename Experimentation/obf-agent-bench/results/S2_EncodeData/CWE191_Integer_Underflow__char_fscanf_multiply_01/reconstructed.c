#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#pragma GCC diagnostic ignored "-Wunused-result"

void printLine(const char *line)
{
    if (line != NULL)
    {
        printf("%s\n", line);
    }
}

void printHexCharLine(char charHex)
{
    printf("%02x\n", charHex);
}

static void goodG2B(void)
{
    char data;
    data = ' ';
    data = -2;
    if (data < 0)
    {
        char result = data * 2;
        printHexCharLine(result);
    }
}

static void goodB2G(void)
{
    char data;
    data = ' ';
    fscanf(stdin, "%c", &data);
    if (data < 0)
    {
        if (data > (CHAR_MIN / 2))
        {
            char result = data * 2;
            printHexCharLine(result);
        }
        else
        {
            printLine("data value is too small to perform multiplication.");
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
    char data;
    data = ' ';
    fscanf(stdin, "%c", &data);
    if (data < 0)
    {
        char result = data * 2;
        printHexCharLine(result);
    }
}

int main(int argc, char *argv[])
{
    const char *str;

    if (argc < 2)
    {
        str = "both";
    }
    else
    {
        str = argv[1];
    }

    if (strcmp(str, "bad") != 0)
    {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }

    if (strcmp(str, "good") != 0)
    {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
