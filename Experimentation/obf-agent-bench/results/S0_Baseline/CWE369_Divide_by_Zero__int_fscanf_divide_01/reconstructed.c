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

void printIntLine(int intNumber)
{
    printf("%d\n", intNumber);
}

void bad(void)
{
    int data = -1;
    if (fscanf(stdin, "%d", &data)) {}
    printIntLine(100 / data);
}

static void goodG2B(void)
{
    int data = -1;
    data = 7;
    printIntLine(100 / data);
}

static void goodB2G(void)
{
    int data = -1;
    if (fscanf(stdin, "%d", &data)) {}
    if (data != 0)
    {
        printIntLine(100 / data);
    }
    else
    {
        printLine("This would result in a divide by zero");
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
