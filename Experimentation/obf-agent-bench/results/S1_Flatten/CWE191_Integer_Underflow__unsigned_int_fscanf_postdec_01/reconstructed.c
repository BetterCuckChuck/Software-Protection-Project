#include <stdio.h>
#include <string.h>

static void goodG2B(void)
{
    unsigned int data = (unsigned int)-2;
    unsigned int result = data - 1;
    printf("%u\n", result);
}

static void goodB2G(void)
{
    unsigned int data = 0;
    if (fscanf(stdin, "%u", &data) <= 0) {
        // ignore
    }
    if (data > 0) {
        unsigned int result = data - 1;
        printf("%u\n", result);
    } else {
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
    if (fscanf(stdin, "%u", &data) <= 0) {
        // ignore
    }
    unsigned int result = data - 1;
    printf("%u\n", result);
}

int main(int argc, char *argv[])
{
    const char *action;

    if (argc > 1) {
        action = argv[1];
    } else {
        action = "both";
    }

    if (strcmp(action, "bad") != 0) {
        puts("Calling good()...");
        good();
        puts("Finished good()");
    }

    if (strcmp(action, "good") != 0) {
        puts("Calling bad()...");
        bad();
        puts("Finished bad()");
    }

    return 0;
}
