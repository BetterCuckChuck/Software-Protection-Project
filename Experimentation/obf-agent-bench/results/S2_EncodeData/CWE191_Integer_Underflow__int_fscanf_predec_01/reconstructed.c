#include <stdio.h>
#include <string.h>
#include <limits.h>

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
    int data = -2;
    int result = data - 1;
    printIntLine(result);
}

static void goodB2G(void)
{
    int data = 0;
    if (fscanf(stdin, "%d", &data)) {}
    if (data == INT_MIN)
    {
        printLine("data value is too large to perform arithmetic safely.");
    }
    else
    {
        int result = data - 1;
        printIntLine(result);
    }
}

static void good(void)
{
    goodG2B();
    goodB2G();
}

static void bad(void)
{
    int data = 0;
    if (fscanf(stdin, "%d", &data)) {}
    int result = data - 1;
    printIntLine(result);
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
