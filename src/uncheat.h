#ifndef _UNCHEAT_H_
#define _UNCHEAT_H_

#include <type_traits>
#include <cstdio>

#include <windows.h>
//#include <winuser.h>
//#include <winternl.h>
//#include <tlhelp32.h>

template<int... I>
struct Indexes { using type = Indexes<I..., sizeof...(I)>; };

template<int N>
struct Make_Indexes { using type = typename Make_Indexes<N-1>::type::type; };

template<>
struct Make_Indexes<0> { using type = Indexes<>; };

constexpr char time[] = __TIME__;
constexpr int DTI(char c) { return c - '0'; }
const int seed = ( DTI(time[7])                                              +
                  (DTI(time[6]) * 10    != 0 ? DTI(time[6]) * 10    : 41   ) +
                   DTI(time[4]) * 60                                         +
                   DTI(time[3]) * 600                                        +
                  (DTI(time[1]) * 3600  != 0 ? DTI(time[1]) * 3600  : 6987 ) +
                  (DTI(time[0]) * 36000 != 0 ? DTI(time[0]) * 36000 : 65087)) ^ 0x12345678;

template<int N>
struct MetaRandomGenerator {
private:
    static constexpr unsigned a = 16807;                        // 7^5
    static constexpr unsigned m = 2147483647;                   // 2^31 - 1

    static constexpr unsigned s = MetaRandomGenerator<N - 1>::value;
    static constexpr unsigned lo = a * (s & 0xFFFF);            // Multiply lower 16 bits by 16807
    static constexpr unsigned hi = a * (s >> 16);               // Multiply higher 16 bits by 16807
    static constexpr unsigned lo2 = lo + ((hi & 0x7FFF) << 16); // Combine lower 15 bits of hi with lo's upper bits
    static constexpr unsigned hi2 = hi >> 15;                   // Discard lower 15 bits of hi
    static constexpr unsigned lo3 = lo2 + hi;

public:
    static constexpr unsigned max = m;
    static constexpr unsigned value = lo3 > m ? lo3 - m : lo3;
};

template<>
struct MetaRandomGenerator<0> {
    static constexpr unsigned value = seed;
};

template<int N, int M>
struct MetaRandom {
    static const int value = MetaRandomGenerator<N + 1>::value % M;
};

template<typename Indexes, int K>
struct MetaString;

template<int... I, int K>
struct MetaString<Indexes<I...>, K> {
    constexpr __forceinline MetaString(const char* str)
    : buffer_ {static_cast<char>(K), encrypt(str[I], I)...} {}

    inline const char* decrypt() {
        for (size_t i = 0; i < sizeof...(I); ++i) buffer_[i + 1] = decrypt(buffer_[i + 1], static_cast<int>(i));
        buffer_[sizeof...(I) + 1] = 0;
        return buffer_ + 1;
    }

private:
    constexpr char key() const { return buffer_[0]; }
    constexpr char encrypt(char c, int d) const { return c ^ static_cast<char>(key() + d % (1 + key())); }
    constexpr char decrypt(char c, int d) const { return encrypt(c, d); }

private:
    char buffer_[sizeof...(I) + 2];
};

template<int N>
struct MetaRandomChar {
    static const char value = static_cast<char>(1 + MetaRandom<N, 0x7F - 1>::value);
};

#define uc(str) (MetaString<Make_Indexes<sizeof(str) - 1>::type, MetaRandomChar<__COUNTER__>::value>(str).decrypt())

#define SHA1_SIZE   (40 + 1)
#define SHA256_SIZE (64 + 1)

#define ROTR(x,n)   ((x >> n | x << (32 -n)))
#define SHR(x,n)    ((x >> n))
#define Ch(x,y,z)   ((x & y) ^ (~x & z))
#define Maj(x,y,z)  ((x & y) ^ (x & z) ^ (y & z))
#define SIGMA0(x)   ((ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22)))
#define SIGMA1(x)   ((ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25)))
#define sigma0(x)   ((ROTR(x,  7) ^ ROTR(x, 18) ^  SHR(x,  3)))
#define sigma1(x)   ((ROTR(x, 17) ^ ROTR(x, 19) ^  SHR(x, 10)))
#define CircularShift(bits,word) (((word)<<(bits)) | ((word)>>(32-bits)))

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

struct sha256 {
    unsigned int state[8];
    unsigned char buffer[64];
    unsigned long long n_bits;
    unsigned char buffer_counter;
};

namespace ucl {

using big_int = long long;

class SHA1 {
private:
    unsigned int f(int t, unsigned int B, unsigned int C, unsigned int D);
    unsigned int K(int t);
    void SHA1ProcessBlock(unsigned int *W, unsigned int *H);
public:
    void sha1(const char *src, char dst[]);
};

class RSA {
private:
    big_int randseed, e;
    big_int u, p, q, l, d;
protected:
    big_int random(big_int);
    big_int sqrt(double);
    bool isPrime(big_int);
    big_int exgcd(big_int, big_int);
    big_int gcd(big_int, big_int);
    big_int lcm(big_int, big_int);
    big_int mulmod(big_int, big_int, big_int);
    big_int modPow(big_int, big_int, big_int);
    big_int modinv(const big_int &, const big_int &);
    big_int crt(big_int &, big_int &, big_int &, big_int &);
    void PrimeNum();
    big_int rsa_c(int);
    int rsa_d(ucl::big_int);
};

class safe_int : private RSA {
private:
    int n, w;
    big_int t;
    int mod(int a, int b) { return a % b; }//a - a / b * b; }
public:
    explicit safe_int(int num = 0) : n(num), t(rsa_c(num)) {}
    int get() { return n; }
    safe_int &operator+=(const safe_int &r) {
        w = rsa_d(t); w += r.n; n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator+=(int r) {
        w = rsa_d(t); w += r; n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator-=(const safe_int &r) {
        w = rsa_d(t); w -= r.n; n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator-=(int r) {
        w = rsa_d(t); w -= r; n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator*=(const safe_int &r) {
        w = rsa_d(t); w *= r.n; n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator*=(int r) {
        w = rsa_d(t); w *= r; n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator/=(const safe_int &r) {
        w = rsa_d(t); w /= r.n; n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator/=(int r) {
        w = rsa_d(t); w /= r; n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator^=(const safe_int &r) {
        w = rsa_d(t); w ^= r.n; n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator^=(int r) {
        w = rsa_d(t); w ^= r; n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator%=(const safe_int &r) {
        w = rsa_d(t); w = mod(n, r.n); n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    safe_int &operator%=(int r) {
        w = rsa_d(t); w = mod(n, r); n = w; t = rsa_c(w); w ^= w;
        return *this;
    }
    friend safe_int operator+(const safe_int &l, const safe_int &r) { return safe_int(l) += r; }
    friend safe_int operator+(const safe_int &l, int r) { return safe_int(l) += r; }
    friend safe_int operator+(int l, const safe_int &r) { return safe_int(l) += r; }
    friend safe_int operator-(const safe_int &l, const safe_int &r) { return safe_int(l) -= r; }
    friend safe_int operator-(const safe_int &l, int r) { return safe_int(l) -= r; }
    friend safe_int operator-(int l, const safe_int &r) { return safe_int(l) -= r; }
    friend safe_int operator*(const safe_int &l, const safe_int &r) { return safe_int(l) *= r; }
    friend safe_int operator*(const safe_int &l, int r) { return safe_int(l) *= r; }
    friend safe_int operator*(int l, const safe_int &r) { return safe_int(l) *= r; }
    friend safe_int operator/(const safe_int &l, const safe_int &r) { return safe_int(l) /= r; }
    friend safe_int operator/(const safe_int &l, int r) { return safe_int(l) /= r; }
    friend safe_int operator/(int l, const safe_int &r) { return safe_int(l) /= r; }
    friend safe_int operator^(const safe_int &l, const safe_int &r) { return safe_int(l) ^= r; }
    friend safe_int operator^(const safe_int &l, int r) { return safe_int(l) ^= r; }
    friend safe_int operator^(int l, const safe_int &r) { return safe_int(l) ^= r; }
    friend safe_int operator%(const safe_int &l, const safe_int &r) { return safe_int(l) %= r; }
    friend safe_int operator%(const safe_int &l, int r) { return safe_int(l) %= r; }
    friend safe_int operator%(int l, const safe_int &r) { return safe_int(l) %= r; }
    bool operator==(const safe_int &r) const { return n == r.n; }
    bool operator!=(const safe_int &r) const { return !(*this == r); }
    bool operator< (const safe_int &r) const { return n < r.n; }
    bool operator> (const safe_int &r) const { return r < *this; }
    bool operator<=(const safe_int &r) const { return !(r > *this); }
    bool operator>=(const safe_int &r) const { return !(r < *this); }
    friend bool operator==(const safe_int &l, int r) { return safe_int(r) == l; }
    friend bool operator==(int l, const safe_int &r) { return safe_int(l) == r; }
    friend bool operator!=(const safe_int &l, int r) { return safe_int(r) != l; }
    friend bool operator!=(int l, const safe_int &r) { return safe_int(l) != r; }
    friend bool operator< (const safe_int &l, int r) { return safe_int(r) > l; }
    friend bool operator< (int l, const safe_int &r) { return safe_int(l) < r; }
    friend bool operator> (const safe_int &l, int r) { return safe_int(r) < l; }
    friend bool operator> (int l, const safe_int &r) { return safe_int(l) > r; }
    friend bool operator<=(const safe_int &l, int r) { return !(safe_int(r) < l); }
    friend bool operator<=(int l, const safe_int &r) { return !(safe_int(l) > r); }
    friend bool operator>=(const safe_int &l, int r) { return !(safe_int(r) > l); }
    friend bool operator>=(int l, const safe_int &r) { return !(safe_int(l) < r); }
};

safe_int rand(int n);

//bool ISDEBUGGERPRESENT();
//void CheckNtGlobalFlag();
void HardwareDebugRegisters();
void sha256(const void *src, char *dst);
void err();

static inline void anti_debug() {
    //void(*pfunc1)() = CheckNtGlobalFlag;
    //if (FindWindowA(NULL, "x64dbg") != NULL) err();
    //if (FindWindowA(NULL, "OLLYDBG") != NULL) err();
    //BOOL bDebuggerPresent; pfunc1();
    void(*pfunc2)() = HardwareDebugRegisters;
    /*if (TRUE == CheckRemoteDebuggerPresent(GetCurrentProcess(),
    &bDebuggerPresent) && TRUE == bDebuggerPresent) err();*/
    if (IsDebuggerPresent()) err();
    //if (ISDEBUGGERPRESENT()) err();
    pfunc2();
}

}
#endif