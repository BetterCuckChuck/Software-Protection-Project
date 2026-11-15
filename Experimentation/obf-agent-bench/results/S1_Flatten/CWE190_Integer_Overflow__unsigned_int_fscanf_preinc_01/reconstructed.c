#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#pragma GCC diagnostic ignored "-Wunused-result"

void goodG2B(void)
{
    unsigned int data = 2;
    unsigned int result = data + 1;
    printf("%u\n", result);
}

void goodB2G(void)
{
    unsigned int data = 0;
    fscanf(stdin, "%u", &data);
    if (data < UINT_MAX)
    {
        unsigned int result = data + 1;
        printf("%u\n", result);
    }
    else
    {
        puts("data value is too large to perform arithmetic safely.");
    }
}

void good(void)
{
    goodG2B();
    goodB2G();
}

void bad(void)
{
    unsigned int data = 0;
    fscanf(stdin, "%u", &data);
    unsigned int result = data + 1;
    printf("%u\n", result);
}

int main(int argc, char *argv[])
{
    const char *mode = (argc >= 2) ? argv[1] : "both";

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
