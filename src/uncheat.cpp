#include "uncheat.h"

void update_w(unsigned int *w, int i, const unsigned char *buffer) {
    for (int j = 0; j < 16; j++) {
        if (i < 16) {
            w[j] =
                ((unsigned int)buffer[0] << 24) |
                ((unsigned int)buffer[1] << 16) |
                ((unsigned int)buffer[2] <<  8) |
                ((unsigned int)buffer[3]);
            buffer += 4;
        }
        else {
            unsigned int a = w[(j + 1) & 15];
            unsigned int b = w[(j + 14) & 15];
            unsigned int s0 = sigma0(a);
            unsigned int s1 = sigma1(b);
            w[j] += w[(j + 9) & 15] + s0 + s1;
        }
    }
}

void sha256_block(struct sha256 *sha) {
    unsigned int *state = sha->state;

    constexpr unsigned int k[8 * 8] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    unsigned int a = state[0];
    unsigned int b = state[1];
    unsigned int c = state[2];
    unsigned int d = state[3];
    unsigned int e = state[4];
    unsigned int f = state[5];
    unsigned int g = state[6];
    unsigned int h = state[7];

    unsigned int w[16], temp;

    int i, j;
    for (i = 0; i < 64; i += 16) {
        update_w(w, i, sha->buffer);

        for (j = 0; j < 16; j += 4) {
            temp = h + (SIGMA1(e) + Ch(e, f, g)) + k[i + j + 0] + w[j + 0];
            h = temp + d;
            d = temp + (SIGMA0(a) + Maj(a, b, c));
            temp = g + (SIGMA1(h) + Ch(h, e, f)) + k[i + j + 1] + w[j + 1];
            g = temp + c;
            c = temp + (SIGMA0(d) + Maj(d, a, b));
            temp = f + (SIGMA1(g) + Ch(g, h, e)) + k[i + j + 2] + w[j + 2];
            f = temp + b;
            b = temp + (SIGMA0(c) + Maj(c, d, a));
            temp = e + (SIGMA1(f) + Ch(f, g, h)) + k[i + j + 3] + w[j + 3];
            e = temp + a;
            a = temp + (SIGMA0(b) + Maj(b, c, d));
        }
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_init(struct sha256 *sha) {
    sha->state[0] = 0x6a09e667;
    sha->state[1] = 0xbb67ae85;
    sha->state[2] = 0x3c6ef372;
    sha->state[3] = 0xa54ff53a;
    sha->state[4] = 0x510e527f;
    sha->state[5] = 0x9b05688c;
    sha->state[6] = 0x1f83d9ab;
    sha->state[7] = 0x5be0cd19;
    sha->n_bits = 0;
    sha->buffer_counter = 0;
}

void sha256_append_byte(struct sha256 *sha, unsigned char byte) {
    sha->buffer[sha->buffer_counter++] = byte;
    sha->n_bits += 8;

    if (sha->buffer_counter == 64) {
        sha->buffer_counter = 0;
        sha256_block(sha);
    }
}

void sha256_append(struct sha256 *sha, const void *src, size_t n_bytes) {
    const unsigned char *bytes = (const unsigned char*)src;
    for (size_t i = 0; i < n_bytes; i++) sha256_append_byte(sha, bytes[i]);
}

void sha256_finalize(struct sha256 *sha) {
    unsigned long long n_bits = sha->n_bits;

    sha256_append_byte(sha, 0x80);

    while (sha->buffer_counter != 56) sha256_append_byte(sha, 0);

    for (int i = 7; i >= 0; i--) {
        unsigned char byte = (n_bits >> 8 * i) & 0xff;
        sha256_append_byte(sha, byte);
    }
}

void sha256_finalize_hex(struct sha256 *sha, char *dst_hex65) {
    int i, j;
    unsigned char nibble;
    sha256_finalize(sha);

    for (i = 0; i < 8; i++) {
        for (j = 7; j >= 0; j--) {
            nibble = (sha->state[i] >> j * 4) & 0xf;
            *dst_hex65++ = "0123456789abcdef"[nibble];
        }
    }

    *dst_hex65 = '\0';
}

void ucl::sha256(const void *src, char *dst) {
    struct sha256 sha;
    const unsigned char *str = (const unsigned char*)src;
    size_t len = 0;
    while (str[len] != '\0') len++;
    sha256_init(&sha);
    sha256_append(&sha, src, len);
    sha256_finalize_hex(&sha, dst);
}
/*
unsigned int SHA1::f(int t, unsigned int B, unsigned int C, unsigned int D) {
    if (t < 20) return (B & C) | ((~ B) & D);
    else if (t < 40) return B ^ C ^ D;
    else if (t < 60) return (B & C) | (B & D) | (C & D);
    else return B ^ C ^ D;
}

unsigned int SHA1::K(int t) {
    if (t < 20) return 0x5A827999;
    else if (t < 40) return 0x6ED9EBA1;
    else if (t < 60) return 0x8F1BBCDC;
    else return 0xCA62C1D6;
}

void SHA1::SHA1ProcessBlock(unsigned int *W, unsigned int *H) {
    unsigned int A, B, C, D, E, t, TEMP;

    for (t = 16; t < 80; t++) W[t] = CircularShift(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    A = H[0];
    B = H[1];
    C = H[2];
    D = H[3];
    E = H[4];
    for (t = 0; t < 80; t++) {
        TEMP = CircularShift(5, A) + f(t, B, C, D) + E + W[t] + K(t);
        E = D; D = C; C = CircularShift(30, B); B = A; A = TEMP;
    }
    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
    H[4] += E;
}

void SHA1::sha1(const char *src, char dst[]) {
    unsigned char aLastBlock[64] = {0};
    int cnBlock,nLastBlockSize, nIndex, i, j, t;
    unsigned int awBlock[80];
    unsigned int pwResult[5];
    unsigned int wLength = 0;
    while (src[wLength] != '\0') wLength++;

    pwResult[0] = 0x67452301;
    pwResult[1] = 0xEFCDAB89;
    pwResult[2] = 0x98BADCFE;
    pwResult[3] = 0x10325476;
    pwResult[4] = 0xC3D2E1F0;

    cnBlock = wLength / 64;
    nLastBlockSize = wLength - 64 * cnBlock;

    for (i = 0; i < cnBlock; i++) {
        for(t = 0; t < 16; t++) {
            awBlock[t] = src[i*64+t*4] << 24;
            awBlock[t] |= src[i*64+t*4+1] << 16;
            awBlock[t] |= src[i*64+t*4+2] << 8;
            awBlock[t] |= src[i*64+t*4+3];
        }
        SHA1ProcessBlock(awBlock,pwResult);
    }

    if (nLastBlockSize > 55) {
        memcpy((char*)aLastBlock, src+cnBlock*64, nLastBlockSize);
        aLastBlock[nLastBlockSize] = 0x80;

        for(t = 0; t < 16; t++) {
            awBlock[t] = aLastBlock[t*4] << 24;
            awBlock[t] |= aLastBlock[t*4+1] << 16;
            awBlock[t] |= aLastBlock[t*4+2] << 8;
            awBlock[t] |= aLastBlock[t*4+3];
        }
        SHA1ProcessBlock(awBlock,pwResult);
        nIndex = 0;
    }
    else {
        memcpy((char*)aLastBlock,src+cnBlock*64,nLastBlockSize);
        nIndex = nLastBlockSize;
        aLastBlock[nIndex++] = 0x80;
    }

    for (t = nIndex; t < 60; t++) aLastBlock[t] = 0;

    aLastBlock[60] = wLength * 8 >> 24;
    aLastBlock[61] = wLength * 8 >> 16;
    aLastBlock[62] = wLength * 8 >> 8;
    aLastBlock[63] = wLength * 8;

    for (t = 0; t < 16; t++) {
        awBlock[t] = aLastBlock[t*4] << 24;
        awBlock[t] |= aLastBlock[t*4+1] << 16;
        awBlock[t] |= aLastBlock[t*4+2] << 8;
        awBlock[t] |= aLastBlock[t*4+3];
    }
    SHA1ProcessBlock(awBlock, pwResult);

    sprintf(dst, "%5x%5x%5x%5x%5x", pwResult[0], pwResult[1], pwResult[2], pwResult[3], pwResult[4]);
}

int safe_int::sha1_cmp(int n, int m) {
    char out1[SHA1_SIZE] = {0}, out2[SHA1_SIZE] = {0}, str1[SHA1_SIZE] = {0}, str2[SHA1_SIZE] = {0};
    sprintf(str1, "%d", m);
    sprintf(str2, "%d", n);
    printf("%d, %d\n", n, m);
    sha1(str1, out1);
    sha1(str2, out2);
    printf("%s\n%s\n\n", out1, out2);
    if (!strcmp(out2, out1)) return 1;
    return 0;
}
*/

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

ucl::big_int ucl::RSA::modPow(ucl::big_int a, ucl::big_int k, ucl::big_int x) {
    a %= x;

    if (a == 0 || x == 0) return 0;
    if (k == 0) return 1 % x;

    ucl::big_int value = 1;
    for(ucl::big_int i = 0; i < k; i++) {
        value *= a;
        if(value >= x) {
            value %= x;
        }
    }
    return value;
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

ucl::big_int ucl::RSA::sqrt(double x) {
    double s, last;

    if (x > 1.0) s = x;
    else s = 1.0;

    do {
        last = s;
        s = (x / s + s) / 2.0;
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
        if (p > 100000 && q > 100000) break;
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
    if (d % 2 == 0) d += 1;
    else if (d < 0) d = -1 * d;
    while ((e * d % l) != 1) d += 2;
    crypto = modPow(num, e, u);
    return crypto;
}

int ucl::RSA::rsa_d(ucl::big_int num) {
    return static_cast<int>(crt(p, q, num, d));
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
    return static_cast<safe_int>(w);
}

PVOID GetPEB() {
#ifdef _WIN64
    return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
#else
    return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}

PVOID GetPEB64() {
    PVOID pPeb = 0;
#ifndef _WIN64
    if (IsWin8OrHigher()) {
        BOOL isWow64 = FALSE;
        typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
        pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
            GetProcAddress(GetModuleHandleA(uc("Kernel32.dll")), uc("IsWow64Process"));
        if (fnIsWow64Process(GetCurrentProcess(), &isWow64)) {
            if (isWow64) {
                pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
                pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
            }
        }
    }
#endif
    return pPeb;
}

void ucl::CheckNtGlobalFlag() {
    PVOID pPeb = GetPEB();
    PVOID pPeb64 = GetPEB64();
    DWORD offsetNtGlobalFlag = 0;
#ifdef _WIN64
    offsetNtGlobalFlag = 0xBC;
#else
    offsetNtGlobalFlag = 0x68;
#endif
    DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
    if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED) ExitProcess(-1);
    if (pPeb64) {
        DWORD NtGlobalFlagWow64 = *(PDWORD)((PBYTE)pPeb64 + 0xBC);
        if (NtGlobalFlagWow64 & NT_GLOBAL_FLAG_DEBUGGED) ExitProcess(-1);
    }
}

bool ucl::ISDEBUGGERPRESENT() {
    HMODULE hKernel32 = GetModuleHandleA(uc("kernel32.dll"));
    if (!hKernel32) return false;
    FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, uc("IsDebuggerPresent"));
    if (!pIsDebuggerPresent) return false;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return false;
    PROCESSENTRY32W ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnapshot, &ProcessEntry)) return false;
    bool bDebuggerPresent = false;
    HANDLE hProcess = NULL;
    DWORD dwFuncBytes = 0;
    const DWORD dwCurrentPID = GetCurrentProcessId();
    do {
        try {
            if (dwCurrentPID == ProcessEntry.th32ProcessID) continue;
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
            if (NULL == hProcess) continue;
            if (!ReadProcessMemory(hProcess, (LPCVOID)pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL)) continue;
            if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent) {
                bDebuggerPresent = true;
                break;
            }
        }
        catch (...) {
            if (hProcess) CloseHandle(hProcess);
        }
    } while (Process32NextW(hSnapshot, &ProcessEntry));
    if (hSnapshot) CloseHandle(hSnapshot);
    return bDebuggerPresent;
}