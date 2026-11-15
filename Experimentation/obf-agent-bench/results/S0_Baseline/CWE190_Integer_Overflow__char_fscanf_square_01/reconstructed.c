#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
    }
}

void printHexCharLine(char charHex)
{
    printf("%02x\n", charHex);
}

void CWE190_Integer_Overflow__char_fscanf_square_01_bad(void)
{
    char data;
    data = ' ';
    fscanf(stdin, "%c", &data);
    {
        char result = data * data;
        printHexCharLine(result);
    }
}

static void goodG2B(void)
{
    char data;
    data = ' ';
    data = 2;
    {
        char result = data * data;
        printHexCharLine(result);
    }
}

static void goodB2G(void)
{
    char data;
    data = ' ';
    fscanf(stdin, "%c", &data);
    if (abs((long)data) <= (long)sqrt((double)CHAR_MAX))
    {
        char result = data * data;
        printHexCharLine(result);
    }
    else
    {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

void CWE190_Integer_Overflow__char_fscanf_square_01_good(void)
{
    goodG2B();
    goodB2G();
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printLine("Calling good()...");
        CWE190_Integer_Overflow__char_fscanf_square_01_good();
        printLine("Finished good()");
        printLine("Calling bad()...");
        CWE190_Integer_Overflow__char_fscanf_square_01_bad();
        printLine("Finished bad()");
    }
    else
    {
        if (strcmp(argv[1], "bad") != 0)
        {
            printLine("Calling good()...");
            CWE190_Integer_Overflow__char_fscanf_square_01_good();
            printLine("Finished good()");
        }
        if (strcmp(argv[1], "good") != 0)
        {
            printLine("Calling bad()...");
            CWE190_Integer_Overflow__char_fscanf_square_01_bad();
            printLine("Finished bad()");
        }
    }
    return 0;
}
