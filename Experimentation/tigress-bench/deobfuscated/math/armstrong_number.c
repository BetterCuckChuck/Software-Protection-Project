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
