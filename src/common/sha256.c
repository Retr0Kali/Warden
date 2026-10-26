/*
 * Warden - src/common/sha256.c
 * Compact self-contained SHA-256 (FIPS 180-4). No external dependencies.
 * Public-domain style implementation, adapted for Warden.
 */
#include "util.h"

/* --- SHA-256 constants --------------------------------------------- */
static const unsigned int W_K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x,n) (((x) >> (n)) | ((x) << (32-(n))))

static void sha256_compress(unsigned int state[8], const unsigned char block[64])
{
    unsigned int w[64];
    unsigned int a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((unsigned int)block[i*4] << 24)
             | ((unsigned int)block[i*4+1] << 16)
             | ((unsigned int)block[i*4+2] << 8)
             | ((unsigned int)block[i*4+3]);
    }
    for (i = 16; i < 64; i++) {
        unsigned int s0 = ROR32(w[i-15], 7) ^ ROR32(w[i-15], 18) ^ (w[i-15] >> 3);
        unsigned int s1 = ROR32(w[i-2], 17) ^ ROR32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        unsigned int S1 = ROR32(e,6) ^ ROR32(e,11) ^ ROR32(e,25);
        unsigned int ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + W_K[i] + w[i];
        unsigned int S0 = ROR32(a,2) ^ ROR32(a,13) ^ ROR32(a,22);
        unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void wu_sha256(const unsigned char *data, size_t len, unsigned char digest[32])
{
    unsigned int state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    unsigned char block[64];
    size_t i, rem;
    unsigned long long bitlen = (unsigned long long)len * 8ull;

    /* full blocks */
    for (i = 0; i + 64 <= len; i += 64)
        sha256_compress(state, data + i);

    /* tail + padding */
    rem = len - i;
    memcpy(block, data + i, rem);
    block[rem] = 0x80;
    memset(block + rem + 1, 0, (rem < 56 ? 55 : 63) - rem);
    if (rem >= 56) {
        sha256_compress(state, block);
        memset(block, 0, 56);
    }
    for (i = 0; i < 8; i++)
        block[56 + i] = (unsigned char)(bitlen >> (56 - 8 * i));
    sha256_compress(state, block);

    for (i = 0; i < 8; i++) {
        digest[i*4]     = (unsigned char)(state[i] >> 24);
        digest[i*4 + 1] = (unsigned char)(state[i] >> 16);
        digest[i*4 + 2] = (unsigned char)(state[i] >> 8);
        digest[i*4 + 3] = (unsigned char)(state[i]);
    }
}
