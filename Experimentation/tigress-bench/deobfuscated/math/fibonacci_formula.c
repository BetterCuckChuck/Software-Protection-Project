/**
 * @file
 * @brief Finding Fibonacci number of any `n` number using Binet's closed form formula
 */

#include <assert.h>
#include <math.h>
#include <stdio.h>

/**
 * @param n index of number in Fibonacci sequence
 * @returns nth value of Fibonacci sequence for all n >= 0
 */
int fib(unsigned int n) {
    float seq = (float)((1.0 / sqrt(5.0) * pow((1.0 + sqrt(5.0)) / 2.0, (double)(n + 1))) -
                        (1.0 / sqrt(5.0) * pow((1.0 - sqrt(5.0)) / 2.0, (double)(n + 1))));
    return (int)seq;
}

/**
 * @brief Self-test implementations
 */
static void test(void) {
    assert(fib(0) == 1);
    assert(fib(1) == 1);
    assert(fib(2) == 2);
    assert(fib(3) == 3);
    assert(fib(4) == 5);
    assert(fib(5) == 8);
    assert(fib(6) == 13);
    assert(fib(7) == 21);
    assert(fib(8) == 34);
    assert(fib(9) == 55);
    assert(fib(10) == 89);

    printf("All tests have successfully passed!\n");
}

/**
 * @brief Main function
 */
int main(void) {
    test();

    for (int i = 0; i <= 10; i++) {
        printf("%d. fibonacci number is: %d\n", i, fib(i));
    }
    return 0;
}
