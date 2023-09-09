#ifndef _UNCHEAT_H_
#define _UNCHEAT_H_

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

template<int... I>
struct Indexes { using type = Indexes<I..., sizeof...(I)>; };

template<int N>
struct Make_Indexes { using type = typename Make_Indexes<N-1>::type::type; };

template<>
struct Make_Indexes<0> { using type = Indexes<>; };

constexpr char time[] = __TIME__;
constexpr int DTI(char c) { return c - '0'; }
const int seed = (DTI(time[7]) +
                 DTI(time[6]) * 10 +
                 DTI(time[4]) * 60 +
                 DTI(time[3]) * 600 +
                 DTI(time[1]) * 3600 +
                 DTI(time[0]) * 36000) ^ 0x12345678;

template<int N>
struct MetaRandomGenerator
{
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
    : buffer_ {static_cast<char>(K), encrypt(str[I])...} { }

    inline const char* decrypt() {
        for(size_t i = 0; i < sizeof...(I); ++i) buffer_[i + 1] = decrypt(buffer_[i + 1]);
        buffer_[sizeof...(I) + 1] = 0;
        return buffer_ + 1;
    }

private:
    constexpr char key() const { return buffer_[0]; }
    constexpr char encrypt(char c) const { return c ^ key(); }
    constexpr char decrypt(char c) const { return encrypt(c); }

private:
    char buffer_[sizeof...(I) + 2];
};

template<int N>
struct MetaRandomChar {
	static const char value = static_cast<char>(1 + MetaRandom<N, 0x7F - 1>::value);
};

#define uc(str) (MetaString<Make_Indexes<sizeof(str) - 1>::type, MetaRandomChar<__COUNTER__>::value>(str).decrypt())

#define SHA256_SIZE (64 + 1)

#define ROTR(x,n)   ((x >> n | x << (32 -n)))
#define SHR(x,n)    ((x >> n))
#define Ch(x,y,z)   ((x & y) ^ (~x & z))
#define Maj(x,y,z)   ((x & y) ^ (x & z) ^ (y & z))
#define SIGMA0(x)   ((ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22)))
#define SIGMA1(x)   ((ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25)))
#define sigma0(x)   ((ROTR(x,  7) ^ ROTR(x, 18) ^  SHR(x,  3)))
#define sigma1(x)   ((ROTR(x, 17) ^ ROTR(x, 19) ^  SHR(x, 10)))

typedef struct sha256 {
    unsigned int state[8];
    unsigned char buffer[64];
    unsigned long long n_bits;
    unsigned char buffer_counter;
} sha256;

namespace ucl {

bool ISDEBUGGERPRESENT();
void sha256(const void *src, char *dst);

static inline void anti_debug() {
    BOOL bDebuggerPresent;
    if (TRUE == CheckRemoteDebuggerPresent(GetCurrentProcess(),
    &bDebuggerPresent) && TRUE == bDebuggerPresent) ExitProcess(-1);
    if (IsDebuggerPresent()) ExitProcess(-1);
    if (ISDEBUGGERPRESENT()) ExitProcess(-1);
}

}
#endif