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

void printIntLine(int intNumber)
{
    printf("%d\n", intNumber);
}

void bad(void)
{
    int data = -1;
    if (fscanf(stdin, "%d", &data) <= 0)
    {
        /* ignore error */
    }
    printIntLine(100 / data);
}

static void goodG2B(void)
{
    int data = 7;
    printIntLine(100 / data);
}

static void goodB2G(void)
{
    int data = -1;
    if (fscanf(stdin, "%d", &data) <= 0)
    {
        /* ignore error */
    }
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
    char *mode;
    if (argc < 2)
    {
        mode = "both";
    }
    else
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
