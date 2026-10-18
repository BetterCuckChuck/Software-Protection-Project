#include <stdio.h>
#include <string.h>
#include <assert.h>

/**
 * @brief Apply the ROT13 cipher to a null-terminated string in-place.
 * @param s String to be rotated.
 */
void rot13(char *s) {
    for (int i = 0; s[i] != '\0'; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z') {
            s[i] = 'A' + ((s[i] - 'A' + 13) % 26);
        } else if (s[i] >= 'a' && s[i] <= 'z') {
            s[i] = 'a' + ((s[i] - 'a' + 13) % 26);
        }
    }
}

/**
 * @brief Self-test implementations for rot13 cipher.
 */
static void test(void) {
    char test_01[] = "The more I C, the less I see.";
    rot13(test_01);
    assert(strcmp(test_01, "Gur zber V P, gur yrff V frr.") == 0);

    char test_02[] = "Which witch switched the Swiss wristwatches?";
    rot13(test_02);
    assert(strcmp(test_02, "Juvpu jvgpu fjvgpurq gur Fjvff jevfgjngpurf?") == 0);

    char test_03[] = "Juvpu jvgpu fjvgpurq gur Fjvff jevfgjngpurf?";
    rot13(test_03);
    assert(strcmp(test_03, "Which witch switched the Swiss wristwatches?") == 0);

    printf("All tests have successfully passed!\n");
}

int main(void) {
    test();
    return 0;
}
