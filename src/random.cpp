#include "uncheat.h"

ucl::big_int ucl::RSA::random(ucl::big_int n) {
    static ucl::big_int x = 123456789;
    static ucl::big_int y = 362436069;
    static ucl::big_int z = 521288629;
    n = n ^ (n << 7); n = n ^ (n >> 9);
    static ucl::big_int w = n ^ 2463534242;
    ucl::big_int t, m;
    m = n % 10;

    for (int i = 0; i < m; i++) {
        t = x ^ (x << 11);
        x = y; y = z; z = w;
        w = (w ^ (w >> 19)) ^ (t ^ (t >> 8));
    }
    return w;
}

ucl::safe_int ucl::rand(int n) {
    static int x = 123456789;
    static int y = 362436069;
    static int z = 521288629;
    n = n ^ (n << 7); n = n ^ (n >> 9);
    static int w = n ^ 2463534242;
    int t, m;
    m = n % 10;

    for (int i = 0; i < m; i++) {
        t = x ^ (x << 11);
        x = y; y = z; z = w;
        w = (w ^ (w >> 19)) ^ (t ^ (t >> 8));
    }
    if (w < 0) w *= -1;

    return static_cast<safe_int>(w);
}
