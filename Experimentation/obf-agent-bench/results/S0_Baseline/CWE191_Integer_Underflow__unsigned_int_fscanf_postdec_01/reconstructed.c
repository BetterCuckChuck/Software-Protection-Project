#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
    }
}

void printUnsignedLine(unsigned int u)
{
    printf("%u\n", u);
}

void bad(void)
{
    unsigned int data;
    data = 0;
    fscanf(stdin, "%u", &data);
    data--;
    printUnsignedLine(data);
}

static void goodG2B(void)
{
    unsigned int data;
    data = 0;
    data = (unsigned int)-2;
    data--;
    printUnsignedLine(data);
}

static void goodB2G(void)
{
    unsigned int data;
    data = 0;
    fscanf(stdin, "%u", &data);
    if (data > 0)
    {
        data--;
        printUnsignedLine(data);
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
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }
    else
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
    return 0;
}
