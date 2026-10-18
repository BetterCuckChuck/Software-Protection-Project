#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int gcd;
    int x;
    int y;
} extended_euclidean_result_t;

extended_euclidean_result_t extended_euclidean_algorithm(int a, int b) {
    int x = 0, y = 1, x_prev = 1, y_prev = 0, gcd = 1;
    if (abs(a) < abs(b)) {
        int tmp = a;
        a = b;
        b = tmp;
    }

    while (b > 0) {
        div_t div_result = div(a, b);
        gcd = b;
        b = div_result.rem;
        a = gcd;

        int tmp = x;
        x = x_prev - div_result.quot * x;
        x_prev = tmp;

        tmp = y;
        y = y_prev - div_result.quot * y;
        y_prev = tmp;
    }

    extended_euclidean_result_t result = {gcd, x_prev, y_prev};
    return result;
}

void single_test(int a, int b, int gcd, int x, int y) {
    extended_euclidean_result_t result = extended_euclidean_algorithm(a, b);
    assert(result.gcd == gcd);
    assert(result.x == x);
    assert(result.y == y);
}

int main(void) {
    single_test(40, 27, 1, -2, 3);
    single_test(71, 41, 1, -15, 26);
    single_test(48, 18, 6, -1, 3);
    single_test(99, 303, 3, -16, 49);
    single_test(14005, 3507, 1, -305, 1218);
    printf("All tests have successfully passed!\n");
    return 0;
}
