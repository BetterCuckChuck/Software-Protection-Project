#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>

bool isPrime(int x) {
    if (x == 2) {
        return true;
    }
    if (x < 2 || x % 2 == 0) {
        return false;
    }

    double squareRoot = sqrt(x);
    for (int i = 3; i <= squareRoot; i += 2) {
        if (x % i == 0) {
            return false;
        }
    }
    return true;
}

void test(void) {
    int primers[] = {2,  3,  5,  7,  11, 13, 17, 19, 23, 29, 31, 37, 41,
                     43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97};
    for (size_t i = 0, n = sizeof(primers) / sizeof(primers[0]); i < n; i++) {
        assert(isPrime(primers[i]));
    }

    int NonPrimers[] = {-1, 0, 1, 4, 6, 8, 9, 10};
    for (size_t i = 0, n = sizeof(NonPrimers) / sizeof(NonPrimers[0]); i < n;
         i++) {
        assert(!isPrime(NonPrimers[i]));
    }
}

int main(void) {
    test();
    return 0;
}
