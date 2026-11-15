#include <stdio.h>
#include <string.h>

void good(void)
{
    printf("%d\n", 2);
    int data = -1;
    if (fscanf(stdin, "%d", &data)) {}
    if (data != 0) {
        printf("%d\n", 100 % data);
    } else {
        puts("This would result in a divide by zero");
    }
}

void bad(void)
{
    int data = -1;
    if (fscanf(stdin, "%d", &data)) {}
    printf("%d\n", 100 % data);
}

int main(int argc, char *argv[])
{
    const char *mode = (argc < 2) ? "both" : argv[1];

    if (strcmp(mode, "bad") != 0) {
        puts("Calling good()...");
        good();
        puts("Finished good()");
    }
    if (strcmp(mode, "good") != 0) {
        puts("Calling bad()...");
        bad();
        puts("Finished bad()");
    }

    return 0;
}
