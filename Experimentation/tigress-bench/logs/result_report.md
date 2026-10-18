# Benchmark Evaluation Result Report
- **Timestamp (UTC)**: `2026-10-18T14:49:48.619228+00:00`
- **Attacker Model**: `gemini-3.8-flash`
- **Obfuscation**: Tigress (`InitOpaque`, `Flatten`, `EncodeArithmetic`, `CleanUp`) + `gcc -O2 -s` + `strip --strip-all`
- **Allowed Tools**: Static (`objdump`), Dynamic (`gdb`)

## 1. Executive Summary
| Metric | Value |
| :--- | :--- |
| **Total Targets Evaluated** | 10 (5 `math`, 5 `cipher`) |
| **Targets Successfully Recovered & Verified** | **10 / 10 (100.0%)** |
| **Total Agent Tool Invocations** | 55 |
| **Static Analysis (`objdump`) Commands** | 33 |
| **Dynamic Analysis (`gdb`) Commands** | 1 |

## 2. Per-Program Verification Scorecard
| Category | Program | Final Verdict | Verification Attempts | Original LOC | Recovered LOC | Last Validation Message |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `math` | `armstrong_number` | **PASS** | 4 | 65 | 47 | Compiled cleanly and passed all test suite checks. |
| `math` | `euclidean_algorithm_extended` | **PASS** | 4 | 154 | 53 | Compiled cleanly and passed all test suite checks. |
| `math` | `fibonacci_formula` | **PASS** | 4 | 59 | 32 | Compiled cleanly and passed all test suite checks. |
| `math` | `palindrome` | **PASS** | 4 | 40 | 21 | Compiled cleanly and passed all test suite checks. |
| `math` | `prime` | **PASS** | 4 | 71 | 40 | Compiled cleanly and passed all test suite checks. |
| `cipher` | `affine` | **PASS** | 4 | 207 | 92 | Compiled cleanly and passed all test suite checks. |
| `cipher` | `hash_adler32` | **PASS** | 4 | 54 | 30 | Compiled cleanly and passed all test suite checks. |
| `cipher` | `hash_crc32` | **PASS** | 4 | 58 | 31 | Compiled cleanly and passed all test suite checks. |
| `cipher` | `hash_djb2` | **PASS** | 4 | 50 | 26 | Compiled cleanly and passed all test suite checks. |
| `cipher` | `rot13` | **PASS** | 3 | 60 | 34 | Compiled cleanly and passed all test suite checks. |

## 3. Recovered C Source Code
### `math/armstrong_number.c`
~~~c
#include <stdio.h>

int power(int x, unsigned int y) {
    if (y == 0)
        return 1;
    int half = power(x, y / 2);
    if (y % 2 == 0)
        return half * half;
    return x * half * half;
}

int order(int x) {
    int n = 0;
    while (x > 0) {
        n++;
        x = x / 10;
    }
    return n;
}

int is_armstrong(int x) {
    int n = order(x);
    int temp = x;
    int sum = 0;
    while (temp != 0) {
        int r = temp % 10;
        sum += power(r, n);
        temp = temp / 10;
    }
    return (sum == x) ? 1 : 0;
}

int main(void) {
    int x = 153;
    if (is_armstrong(x) == 1)
        printf("True\n");
    else
        printf("False\n");

    x = 1253;
    if (is_armstrong(x) == 1)
        printf("True\n");
    else
        printf("False\n");

    return 0;
}
~~~

### `math/euclidean_algorithm_extended.c`
~~~c
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
~~~

### `math/fibonacci_formula.c`
~~~c
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
~~~

### `math/palindrome.c`
~~~c
#include <assert.h>
#include <stdbool.h>

bool isPalindrome(int number) {
    int reversedNumber = 0;
    int originalNumber = number;
    while (number != 0) {
        int remainder = number % 10;
        reversedNumber = reversedNumber * 10 + remainder;
        number /= 10;
    }
    return originalNumber == reversedNumber;
}

int main(void) {
    assert(isPalindrome(0));
    assert(isPalindrome(1));
    assert(isPalindrome(12321));
    assert(!isPalindrome(1234));
    return 0;
}
~~~

### `math/prime.c`
~~~c
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
~~~

### `cipher/affine.c`
~~~c
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALPHABET_SIZE 95
#define Z95_CONVERSION_CONSTANT 32

typedef struct {
    int a;
    int b;
} affine_key_t;

int modular_multiplicative_inverse(unsigned int a, unsigned int m) {
    int x = 0, y = 1;
    a = a % m;
    if (a == 0) {
        return 0;
    }
    while (a != 0) {
        div_t div_result = div(m, a);
        m = a;
        a = div_result.rem;
        int next = x - (y * div_result.quot);
        x = y;
        y = next;
    }
    return x;
}

affine_key_t inverse_key(affine_key_t key) {
    affine_key_t inverse;
    inverse.a = modular_multiplicative_inverse(key.a, ALPHABET_SIZE);
    inverse.a += ALPHABET_SIZE;
    inverse.a %= ALPHABET_SIZE;
    inverse.b = -(key.b % ALPHABET_SIZE) + ALPHABET_SIZE;
    return inverse;
}

void affine_encrypt(char *s, affine_key_t key) {
    for (int i = 0; s[i] != '\0'; i++) {
        int c = (int)s[i] - Z95_CONVERSION_CONSTANT;
        c *= key.a;
        c += key.b;
        c %= ALPHABET_SIZE;
        s[i] = (char)(c + Z95_CONVERSION_CONSTANT);
    }
}

void affine_decrypt(char *s, affine_key_t key) {
    affine_key_t inverse = inverse_key(key);
    for (int i = 0; s[i] != '\0'; i++) {
        int c = (int)s[i] - Z95_CONVERSION_CONSTANT;
        c += inverse.b;
        c *= inverse.a;
        c %= ALPHABET_SIZE;
        s[i] = (char)(c + Z95_CONVERSION_CONSTANT);
    }
}

void test_string(const char *s, const char *ciphertext, int a, int b) {
    char *copy = malloc((strlen(s) + 1) * sizeof(char));
    strcpy(copy, s);

    affine_key_t key = {a, b};

    affine_encrypt(copy, key);
    assert(strcmp(copy, ciphertext) == 0);

    affine_decrypt(copy, key);
    assert(strcmp(copy, s) == 0);

    free(copy);
}

int main(void) {
    test_string("Hello!", "&3ddy2", 7, 11);
    test_string("TheAlgorithms/C", "DNC}=jHS2zN!7;E", 67, 67);
    test_string("0123456789", "840,($ {ws", 91, 88);
    test_string("7W@;cdeRT9uL", "JDfa*we?z&bL", 77, 76);
    test_string("~Qr%^-+++$leM", "r'qC0$sss;Ahf", 8, 90);
    test_string("The quick brown fox jumps over the lazy dog",
                "K7: .*6<4 =-0(1 90' 5*2/, 0):- +7: 3>%& ;08", 94, 0);
    test_string(
        "One-1, Two-2, Three-3, Four-4, Five-5, Six-6, Seven-7, Eight-8, "
        "Nine-9, Ten-10",
        "H&60>\\2*uY0q\\2*p4660E\\2XYn40x\\2XDB60L\\2VDI0 "
        "\\2V6B6&0S\\2%D=p;0'\\2tD&60Z\\2*6&0>j",
        51, 18);
    printf("All tests have successfully passed!\n");
    return 0;
}
~~~

### `cipher/hash_adler32.c`
~~~c
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

uint32_t adler32(const char *s) {
    uint32_t a = 1;
    uint32_t b = 0;
    const uint32_t MODADLER = 65521;

    size_t i = 0;
    while (s[i] != '\0') {
        a = (a + s[i]) % MODADLER;
        b = (b + a) % MODADLER;
        i++;
    }
    return (b << 16) | a;
}

void test_adler32(void) {
    assert(adler32("Hello World") == 403375133);
    assert(adler32("Hello World!") == 474547262);
    assert(adler32("Hello world") == 413860925);
    assert(adler32("Hello world!") == 487130206);
    printf("Tests passed\n");
}

int main(void) {
    test_adler32();
    return 0;
}
~~~

### `cipher/hash_crc32.c`
~~~c
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

uint32_t crc32(const char *s) {
    uint32_t crc = 0xffffffff;
    size_t i = 0;
    while (s[i] != '\0') {
        uint8_t byte = s[i];
        crc = crc ^ byte;
        for (uint8_t j = 8; j > 0; --j) {
            uint32_t mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
        i++;
    }
    return ~crc;
}

void test_crc32(void) {
    assert(crc32("Hello World") == 1243066710);
    assert(crc32("Hello World!") == 472456355);
    assert(crc32("Hello world") == 2346098258);
    assert(crc32("Hello world!") == 461707669);
    printf("Tests passed\n");
}

int main(void) {
    test_crc32();
    return 0;
}
~~~

### `cipher/hash_djb2.c`
~~~c
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

uint64_t djb2(const char *s) {
    uint64_t hash = 5381;
    size_t i = 0;
    while (s[i] != '\0') {
        hash = ((hash << 5) + hash) + s[i];
        i++;
    }
    return hash;
}

void test_djb2(void) {
    assert(djb2("Hello World") == 13827776004929097857ULL);
    assert(djb2("Hello World!") == 13594750393630990530ULL);
    assert(djb2("Hello world") == 13827776004967047329ULL);
    assert(djb2("Hello world!") == 13594750394883323106ULL);
    printf("Tests passed\n");
}

int main(void) {
    test_djb2();
    return 0;
}
~~~

### `cipher/rot13.c`
~~~c
#include <assert.h>
#include <stdio.h>
#include <string.h>

void rot13(char *s) {
    for (int i = 0; s[i]; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z') {
            s[i] = 'A' + ((s[i] - 'A' + 13) % 26);
        } else if (s[i] >= 'a' && s[i] <= 'z') {
            s[i] = 'a' + ((s[i] - 'a' + 13) % 26);
        }
    }
}

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
~~~
