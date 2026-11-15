#include <stdio.h>
#include <string.h>

static void good(void) {
    short data = 0;
    printf("%d\n", 3);
    if (fscanf(stdin, "%hd", &data) <= 0) {
        // ignore input error
    }
    if (data < 0x7fff) {
        short result = data + 1;
        printf("%d\n", (int)result);
    } else {
        puts("data value is too large to perform arithmetic safely.");
    }
}

static void bad(void) {
    short data = 0;
    if (fscanf(stdin, "%hd", &data) <= 0) {
        // ignore input error
    }
    short result = data + 1;
    printf("%d\n", (int)result);
}

int main(int argc, char *argv[]) {
    const char *mode = "both";
    if (argc >= 2) {
        mode = argv[1];
    }

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
