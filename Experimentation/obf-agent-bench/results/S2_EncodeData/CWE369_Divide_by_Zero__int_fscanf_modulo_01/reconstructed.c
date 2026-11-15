#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void printLine(const char *line)
{
    printf("%s\n", line);
}

static void printIntLine(int intNumber)
{
    printf("%d\n", intNumber);
}

static void goodG2B(void)
{
    printIntLine(2);
}

static void goodB2G(void)
{
    int data = -1;
    fscanf(stdin, "%d", &data);
    if (data != 0)
    {
        printIntLine(100 % data);
    }
    else
    {
        printLine("This would result in a divide by zero");
    }
}

static void good(void)
{
    goodG2B();
    goodB2G();
}

static void bad(void)
{
    int data = -1;
    fscanf(stdin, "%d", &data);
    printIntLine(100 % data);
}

int main(int argc, char *argv[])
{
    const char *mode = "both";
    if (argc > 1)
    {
        mode = argv[1];
    }

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
