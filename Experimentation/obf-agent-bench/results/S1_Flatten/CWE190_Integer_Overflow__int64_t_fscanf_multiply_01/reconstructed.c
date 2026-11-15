#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

int globalArgc = 0;
char **globalArgv = NULL;
char **globalEnvp = NULL;

void printLine(const char *line)
{
    if (line != NULL)
    {
        puts(line);
    }
}

void printLongLongLine(int64_t longLongIntNumber)
{
    printf("%ld\n", longLongIntNumber);
}

void bad(void)
{
    int64_t data = 0;
    if (fscanf(stdin, "%ld", &data) != 1) {}
    if (data > 0)
    {
        int64_t result = data * 2;
        printLongLongLine(result);
    }
}

static void goodG2B(void)
{
    int64_t data = 2;
    if (data > 0)
    {
        int64_t result = data * 2;
        printLongLongLine(result);
    }
}

static void goodB2G(void)
{
    int64_t data = 0;
    if (fscanf(stdin, "%ld", &data) != 1) {}
    if (data > 0)
    {
        if (data < LLONG_MAX / 2)
        {
            int64_t result = data * 2;
            printLongLongLine(result);
        }
        else
        {
            printLine("data value is too large to perform arithmetic safely.");
        }
    }
}

void good(void)
{
    goodG2B();
    goodB2G();
}

int main(int argc, char *argv[], char *envp[])
{
    globalArgc = argc;
    globalArgv = argv;
    globalEnvp = envp;

    const char *mode = "both";
    if (argc >= 2)
    {
        mode = argv[1];
    }

    if (strcmp(mode, "bad") != 0)
    {
        puts("Calling good()...");
        good();
        puts("Finished good()");
    }

    if (strcmp(mode, "good") != 0)
    {
        puts("Calling bad()...");
        bad();
        puts("Finished bad()");
    }

    return 0;
}
