#include "uncheat.h"

#define MAX_P 1000000

ucl::big_int ucl::RSA::exgcd(ucl::big_int a, ucl::big_int b) {
    ucl::big_int x1 = 0, y1 = 1, r1 = b;
    ucl::big_int x2 = 1, y2 = 0, r2 = a;
    ucl::big_int x;
    ucl::big_int qq, rr;
    ucl::big_int xx, yy;
    
    while (1) {
        qq = r1 / r2;
        rr = r1 % r2;

        xx = x1 - qq * x2;
        yy = y1 - qq * y2;

        if (rr == 0) {
            x = x2;
            break;
        }

        x1 = x2; y1 = y2; r1 = r2;
        x2 = xx; y2 = yy; r2 = rr;
    }
    while (x <= 0) x += b;

    return x;
}

ucl::big_int ucl::RSA::gcd(ucl::big_int x, ucl::big_int y) {
    while (1) {
        if (y == 0) return x;
        x = x % y;
        if (x == 0) return y;
        y = y % x;
    }
}

ucl::big_int ucl::RSA::lcm(ucl::big_int a, ucl::big_int b) {
    return a * b / gcd(a, b);
}

ucl::big_int ucl::RSA::mulmod(ucl::big_int a, ucl::big_int n, ucl::big_int m) {
    a %= m;
    if (a < 0) a += m;
    ucl::big_int mu = 0;
    while (n >= 1) {
        if (n & 1 == 1) mu = (a + mu) % m;
        a = a * 2 % m;
        n = n / 2;
    }
    return mu;
}

ucl::big_int ucl::RSA::modPow(ucl::big_int a, ucl::big_int k, ucl::big_int x) {
    a %= x;
    if (a < 0) a += x;
    ucl::big_int pw = 1;
    while (k >= 1) {
        if (k & 1 == 1) pw = mulmod(a, pw, x);
        a = mulmod(a, a, x);
        k = k / 2;
    }
    return pw;
}

ucl::big_int ucl::RSA::modinv(const ucl::big_int &a, const ucl::big_int &m) {
    ucl::big_int j = 1, i = 0, b = m, c = a, x, y;
    while (c != 0) {
        x = b / c;
        y = b - x*c;
        b = c;
        c = y;
        y = j;
        j = i - j*x;
        i = y;
    }
    if (i < 0) i += m;
    return i;
}

ucl::big_int ucl::RSA::crt(ucl::big_int &p, ucl::big_int &q, ucl::big_int &c, ucl::big_int &d) {
    ucl::big_int m1, m2, dp, dq, qinv, m, h;
    qinv = modinv(q, p);

    dp = d % (p-1);
    dq = d % (q-1);

    m1 = modPow(c, dp, p);
    m2 = modPow(c, dq, q);

    h = qinv * (m1 - m2);
    m = m2 + h * q;
    return m;
}

ucl::big_int ucl::RSA::sqrt(double x) {
    double s, last;

    if (x > 1.0) s = x;
    else s = 1.0;

    do {
        last = s;
        s = (x / s + s) * 0.5;
    } while (s < last);

    return static_cast<int>(last);
}

bool ucl::RSA::isPrime(ucl::big_int a) {
    if (a % 2 == 0 || a <= 2) return false;
    for (int i = 3; i <= sqrt(a); i += 2) if (a % i == 0) return false;
    return true;
}

void ucl::RSA::PrimeNum() {
    ucl::big_int tmp;
    randseed = 0x12345678 ^ GetTickCount();
    while (1) {
        p = random(randseed) % MAX_P;
        q = random(randseed) % MAX_P;
        if (p >= 500000 && q >= 500000) break;
    }
    while (1) {
        if (!isPrime(p)) p++;
        else break;
    }
    while (1) {
        if (!isPrime(q)) q++;
        else break;
    }
    if (p < q) {
        tmp = p;
        p = q;
        q = tmp;
    }
}

ucl::big_int ucl::RSA::rsa_c(int num) {
    ucl::big_int crypto;
    PrimeNum();
    u = p * q;
    l = lcm(p-1, q-1);
    e = 65537;
    while (gcd(e, l) != 1) e += 2;
    d = exgcd(e, l);
    if (d & 1 == 0) d += 1;
    else if (d < 0) d = -1 * d;
    while ((e * d % l) != 1) d += 2;
    crypto = modPow(num, e, u);
    return crypto;
}

int ucl::RSA::rsa_d(ucl::big_int num) {
    return static_cast<int>(crt(p, q, num, d));
}
