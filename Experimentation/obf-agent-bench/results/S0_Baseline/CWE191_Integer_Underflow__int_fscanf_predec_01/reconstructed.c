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

void printIntLine(int intNumber)
{
    printf("%d\n", intNumber);
}

static void goodG2B(void)
{
    int data = -2;
    int result = data - 1;
    printIntLine(result);
}

static void goodB2G(void)
{
    int data = 0;
    if (fscanf(stdin, "%d", &data)) {}
    if (data > INT_MIN)
    {
        int result = data - 1;
        printIntLine(result);
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
    int data = 0;
    if (fscanf(stdin, "%d", &data)) {}
    int result = data - 1;
    printIntLine(result);
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
