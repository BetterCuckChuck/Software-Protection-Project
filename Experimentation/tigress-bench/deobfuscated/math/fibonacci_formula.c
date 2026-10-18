#include <assert.h>
#include <math.h>
#include <stdio.h>

int fib(int n) {
    float res = (pow((1 + sqrt(5)) / 2, n + 1) / sqrt(5)) -
                (pow((1 - sqrt(5)) / 2, n + 1) / sqrt(5));
    return (int)res;
}

void test(void) {
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

int main(void) {
    test();
    for (int i = 0; i < 11; i++) {
        printf("%d. fibonacci number is: %d\n", i, fib(i));
    }
    return 0;
}
