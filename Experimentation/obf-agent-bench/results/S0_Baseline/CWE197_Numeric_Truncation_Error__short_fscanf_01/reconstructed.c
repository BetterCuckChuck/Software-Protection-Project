#include <stdio.h>
#include <string.h>

void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
    }
}

void printHexCharLine(char charHex)
{
    printf("%02x\n", (int)charHex);
}

void bad(void)
{
    short data;
    data = -1;
    fscanf(stdin, "%hd", &data);
    printHexCharLine((char)data);
}

void good(void)
{
    short data;
    data = -1;
    data = 0x7a;
    printHexCharLine((char)data);
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
