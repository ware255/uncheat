#include <random>
#include "uncheat.h"

#define MAX_P 10000000

ucl::big_int ucl::RSA::random(ucl::big_int n) {
    std::random_device rnd;
    std::mt19937_64 mt(rnd()^n);
    std::uniform_int_distribution<> rand(500000, MAX_P);
    return rand(mt);
}

ucl::safe_int ucl::rand(int n) {
    std::mt19937 mt;
    std::random_device rnd;
    mt.seed(rnd()^n);
    return static_cast<safe_int>(mt() % (MAX_P / 10));
}
