#include <stdio.h>
#include <string.h>

void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
    }
}

void printShortLine(short b)
{
    printf("%hd\n", b);
}

void bad(void)
{
    int data = -1;
    if (fscanf(stdin, "%d", &data) == 1) {}
    printShortLine((short)data);
}

void goodG2B(void)
{
    int data = 122;
    printShortLine((short)data);
}

void good(void)
{
    goodG2B();
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
