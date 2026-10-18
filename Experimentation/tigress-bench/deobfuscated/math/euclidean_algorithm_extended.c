#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Structure holding the values resulting from the extended Euclidean algorithm
 */
typedef struct euclidean_result
{
    int gcd;   /**< the greatest common divisor */
    int x, y;  /**< values such that ax + by = gcd(a, b) */
} euclidean_result_t;

/**
 * Gives queue-like behavior to an array of two ints, pushing an element
 * onto the end and pushing one off the front.
 */
static inline void xy_push(int arr[2], int newval)
{
    arr[1] = arr[0];
    arr[0] = newval;
}

/**
 * Calculates the value of x or y and pushes into the small queue.
 */
static inline void calculate_next_xy(int quotient, int prev[2])
{
    int next = prev[1] - (prev[0] * quotient);
    xy_push(prev, next);
}

/**
 * Performs the extended Euclidean algorithm on integer inputs a and b.
 */
euclidean_result_t extended_euclidean_algorithm(int a, int b)
{
    int previous_remainder = 1;
    int previous_x_values[2] = {0, 1};
    int previous_y_values[2] = {1, 0};
    div_t div_result;
    euclidean_result_t result;

    /* swap values of a and b if |a| < |b| */
    if (abs(a) < abs(b))
    {
        a ^= b;
        b ^= a;
        a ^= b;
    }

    div_result.rem = b;

    while (div_result.rem > 0)
    {
        div_result = div(a, b);

        previous_remainder = b;

        a = b;
        b = div_result.rem;

        calculate_next_xy(div_result.quot, previous_x_values);
        calculate_next_xy(div_result.quot, previous_y_values);
    }

    result.gcd = previous_remainder;
    result.x = previous_x_values[1];
    result.y = previous_y_values[1];

    return result;
}

/**
 * Performs one single check on the result of the algorithm.
 */
static inline void single_test(int a, int b, int gcd, int x, int y)
{
    euclidean_result_t result = extended_euclidean_algorithm(a, b);
    assert(result.gcd == gcd);
    assert(result.x == x);
    assert(result.y == y);
}

/**
 * Performs tests on known results.
 */
static void test(void)
{
    single_test(40, 27, 1, -2, 3);
    single_test(71, 41, 1, -15, 26);
    single_test(48, 18, 6, -1, 3);
    single_test(99, 303, 3, -16, 49);
    single_test(14005, 3507, 1, -305, 1218);

    printf("All tests have successfully passed!\n");
}

int main(void)
{
    test();
    return 0;
}
