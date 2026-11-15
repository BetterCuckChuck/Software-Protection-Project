#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static void printLine(const char *line)
{
    if (line != NULL)
    {
        printf("%s\n", line);
    }
}

static void printIntLine(int intNumber)
{
    printf("%d\n", intNumber);
}

static void bad(void)
{
    int data = 0;
    if (fscanf(stdin, "%d", &data) == 1)
    {
        if (data > 0)
        {
            int result = (int)((unsigned int)data * 2);
            printIntLine(result);
        }
    }
}

static void goodG2B(void)
{
    int data = 2;
    if (data > 0)
    {
        int result = (int)((unsigned int)data * 2);
        printIntLine(result);
    }
}

static void goodB2G(void)
{
    int data = 0;
    if (fscanf(stdin, "%d", &data) == 1)
    {
        if (data > 0)
        {
            if (data < (INT_MAX / 2))
            {
                int result = (int)((unsigned int)data * 2);
                printIntLine(result);
            }
            else
            {
                printLine("data value is too large to perform arithmetic safely.");
            }
        }
    }
}

static void good(void)
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
