#include "uncheat.h"


/*
 * hash: sha256
 */

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
 * hash: sha1
 */

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

    sprintf(dst, "%x%x%x%x%x", pwResult[0], pwResult[1], pwResult[2], pwResult[3], pwResult[4]);
}
