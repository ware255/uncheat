#include <cstdio>
#include "uncheat.h"

void update_w(unsigned int *w, int i, const unsigned char *buffer) {
    int j;
    for (j = 0; j < 16; j++){
        if (i < 16){
            w[j] =
                ((unsigned int)buffer[0] << 24) |
                ((unsigned int)buffer[1] << 16) |
                ((unsigned int)buffer[2] <<  8) |
                ((unsigned int)buffer[3]);
            buffer += 4;
        }
        else{
            unsigned int a = w[(j + 1) & 15];
            unsigned int b = w[(j + 14) & 15];
            unsigned int s0 = sigma0(a);//(rotr(a,  7) ^ rotr(a, 18) ^ (a >>  3));
            unsigned int s1 = sigma1(b);//(rotr(b, 17) ^ rotr(b, 19) ^ (b >> 10));
            w[j] += w[(j + 9) & 15] + s0 + s1;
        }
    }
}

void sha256_block(struct sha256 *sha) {
    unsigned int *state = sha->state;

    const unsigned int k[8 * 8] = {
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

    unsigned int w[16];

    int i, j;
    for (i = 0; i < 64; i += 16){
        update_w(w, i, sha->buffer);

        for (j = 0; j < 16; j += 4){
            unsigned int temp;
            temp = h + (SIGMA1(e) + Ch(e, f, g)) + k[i + j + 0] + w[j + 0];//step1(e, f, g) + k[i + j + 0] + w[j + 0];
            h = temp + d;
            d = temp + (SIGMA0(a) + Maj(a, b, c));//step2(a, b, c);
            temp = g + (SIGMA1(h) + Ch(h, e, f)) + k[i + j + 1] + w[j + 1];//step1(h, e, f) + k[i + j + 1] + w[j + 1];
            g = temp + c;
            c = temp + (SIGMA0(d) + Maj(d, a, b));//step2(d, a, b);
            temp = f + (SIGMA1(g) + Ch(g, h, e)) + k[i + j + 2] + w[j + 2];//step1(g, h, e) + k[i + j + 2] + w[j + 2];
            f = temp + b;
            b = temp + (SIGMA0(c) + Maj(c, d, a));//step2(c, d, a);
            temp = e + (SIGMA1(f) + Ch(f, g, h)) + k[i + j + 3] + w[j + 3];//step1(f, g, h) + k[i + j + 3] + w[j + 3];
            e = temp + a;
            a = temp + (SIGMA0(b) + Maj(b, c, d));//step2(b, c, d);
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

    if (sha->buffer_counter == 64){
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
    sha256_finalize(sha);

    for (i = 0; i < 8; i++) {
        for (j = 7; j >= 0; j--) {
            unsigned char nibble = (sha->state[i] >> j * 4) & 0xf;
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