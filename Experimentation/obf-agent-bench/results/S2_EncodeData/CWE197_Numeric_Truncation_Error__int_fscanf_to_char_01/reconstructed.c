#include <stdio.h>
#include <string.h>

static void printLine(const char *line)
{
    if (line != NULL)
    {
        printf("%s\n", line);
    }
}

static void printHexCharLine(char charHex)
{
    printf("%02x\n", charHex);
}

static void goodG2B(void)
{
    int data = 122;
    char charHex = (char)data;
    printHexCharLine(charHex);
}

void good(void)
{
    goodG2B();
}

void bad(void)
{
    int data = -1;
    fscanf(stdin, "%d", &data);
    char charHex = (char)data;
    printHexCharLine(charHex);
}

int main(int argc, char *argv[])
{
    const char *mode = (argc < 2) ? "both" : argv[1];

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
