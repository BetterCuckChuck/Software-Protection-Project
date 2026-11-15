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
    short data = 0;
    (void)!fscanf(stdin, "%hd", &data);
    short result = (short)(data + 1);
    printIntLine(result);
}

static void goodG2B(void)
{
    short data = 2;
    short result = (short)(data + 1);
    printIntLine(result);
}

static void goodB2G(void)
{
    short data = 0;
    (void)!fscanf(stdin, "%hd", &data);
    if (data < 32767)
    {
        short result = (short)(data + 1);
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

int main(int argc, char *argv[])
{
    const char *arg;
    if (argc >= 2)
    {
        arg = argv[1];
    }
    else
    {
        arg = "both";
    }

    if (strcmp(arg, "bad") == 0)
    {
        printLine("Calling bad()...");
        bad();
        printLine("Finished bad()");
    }
    else if (strcmp(arg, "good") == 0)
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
