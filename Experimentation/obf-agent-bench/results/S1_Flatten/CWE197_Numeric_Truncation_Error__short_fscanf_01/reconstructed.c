#include <stdio.h>
#include <string.h>

static void bad(void)
{
    short data = -1;
    if (fscanf(stdin, "%hd", &data)) {}
    printf("%02x\n", (int)(char)data);
}

static void good(void)
{
    printf("%02x\n", 0x7a);
}

int main(int argc, char **argv)
{
    const char *action;

    if (argc < 2) {
        action = "both";
    } else {
        action = argv[1];
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
