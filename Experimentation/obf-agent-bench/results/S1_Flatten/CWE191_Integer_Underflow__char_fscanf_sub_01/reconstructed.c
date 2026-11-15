#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
    }
}

static void printHexCharLine(char charHex)
{
    printf("%02x\n", charHex);
}

static void goodG2B(void)
{
    char data;
    data = ' ';
    data = -2;
    {
        char result = (char)(data - 1);
        printHexCharLine(result);
    }
}

static void goodB2G(void)
{
    char data;
    data = ' ';
    fscanf(stdin, "%c", &data);
    if (data > CHAR_MIN)
    {
        char result = (char)(data - 1);
        printHexCharLine(result);
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

void bad(void)
{
    char data;
    data = ' ';
    fscanf(stdin, "%c", &data);
    {
        char result = (char)(data - 1);
        printHexCharLine(result);
    }
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
