#include <stdio.h>
#include <string.h>

static void print_line(const char *str) {
    if (str != NULL) {
        printf("%s\n", str);
    }
}

static void bad(void) {
    unsigned int val = 0;
    fscanf(stdin, "%u", &val);
    val = val - 1;
    printf("%u\n", val);
}

static void good(void) {
    printf("%u\n", 4294967293U);
    unsigned int val = 0;
    fscanf(stdin, "%u", &val);
    if (val != 0) {
        val = val - 1;
        printf("%u\n", val);
    } else {
        print_line("data value is too large to perform arithmetic safely.");
    }
}

int main(int argc, char *argv[]) {
    const char *target = (argc >= 2) ? argv[1] : "both";

    if (strcmp(target, "bad") != 0) {
        print_line("Calling good()...");
        good();
        print_line("Finished good()");
    }

    if (strcmp(target, "good") != 0) {
        print_line("Calling bad()...");
        bad();
        print_line("Finished bad()");
    }

    return 0;
}
