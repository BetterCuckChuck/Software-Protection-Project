#pragma GCC diagnostic ignored "-Wunused-result"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    char data = ' ';
    data = 2;
    char result = data * data;
    printHexCharLine(result);
}

static void goodB2G(void)
{
    char data = ' ';
    fscanf(stdin, "%c", &data);
    if (abs((int)(signed char)data) <= 11)
    {
        char result = data * data;
        printHexCharLine(result);
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
    char data = ' ';
    fscanf(stdin, "%c", &data);
    char result = data * data;
    printHexCharLine(result);
}

int main(int argc, char *argv[])
{
    const char *arg = (argc < 2) ? "both" : argv[1];

    if (strcmp(arg, "bad") != 0)
    {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }

    if (strcmp(arg, "good") != 0)
    {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
