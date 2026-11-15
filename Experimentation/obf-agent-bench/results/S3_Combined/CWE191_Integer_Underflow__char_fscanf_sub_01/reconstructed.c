#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

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

void bad(void)
{
    char data;
    data = ' ';
    if (fscanf(stdin, "%c", &data)) {}
    {
        char result = data - 1;
        printHexCharLine(result);
    }
}

static void goodG2B(void)
{
    char data;
    data = ' ';
    data = -2;
    {
        char result = data - 1;
        printHexCharLine(result);
    }
}

static void goodB2G(void)
{
    char data;
    data = ' ';
    if (fscanf(stdin, "%c", &data)) {}
    if (data > CHAR_MIN)
    {
        char result = data - 1;
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

int main(int argc, char *argv[])
{
    const char *action = "both";
    if (argc > 1)
    {
        action = argv[1];
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
