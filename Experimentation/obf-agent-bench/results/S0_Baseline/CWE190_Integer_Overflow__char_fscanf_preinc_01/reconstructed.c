#pragma GCC diagnostic ignored "-Wunused-result"
#include <stdio.h>
#include <string.h>

void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
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
    if (data < 0x7f)
    {
        char result = data + 1;
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
