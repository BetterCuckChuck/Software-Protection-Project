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

static void printIntLine(int intNumber)
{
    printf("%d\n", intNumber);
}

static void bad(void)
{
    int data = 0;
    fscanf(stdin, "%d", &data);
    {
        int result = data - 1;
        printIntLine(result);
    }
}

static void goodG2B(void)
{
    int data = 0;
    data = -2;
    {
        int result = data - 1;
        printIntLine(result);
    }
}

static void goodB2G(void)
{
    int data = 0;
    fscanf(stdin, "%d", &data);
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

static void good(void)
{
    goodG2B();
    goodB2G();
}

int main(int argc, char *argv[])
{
    const char *action;

    if (argc < 2)
    {
        action = "both";
    }
    else
    {
        action = argv[1];
    }

    if (strcmp(action, "bad") != 0)
    {
        printLine("Calling good()...");
        good();
        printLine("Finished good()");
    }

    if (strcmp(action, "good") != 0)
    {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }

    return 0;
}
