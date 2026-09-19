#include "lpofi_bch.h"

#include <stdio.h>
#include <string.h>

/*
 * BCH-C fixed parameters:
 *
 * m = 9
 * t = 16
 * n = 511
 * primitive polynomial = 0x211
 *
 * Generator:
 *
 * g(x) =
 * 0x12b6bd0545db34c1e01d5296e58c8ed2701ad
 *
 * Degree = 144.
 *
 * generator_bits[0] = coefficient of x^144
 * generator_bits[144] = coefficient of x^0
 */

static const uint8_t generator_bytes[19] = {
    0x01,
    0x2b, 0x6b, 0xd0, 0x54, 0x5d, 0xb3,
    0x4c, 0x1e, 0x01, 0xd5, 0x29, 0x6e,
    0x58, 0xc8, 0xed, 0x27, 0x01, 0xad
};


static uint8_t generator_bit(unsigned i)
{
    if (i == 0U) {
        return 1U;
    }

    i -= 1U;

    return (generator_bytes[1U + i / 8U] >>
            (7U - (i % 8U))) & 1U;
}


static uint8_t data_bit(const uint8_t *data, unsigned i)
{
    return (data[i / 8U] >>
            (7U - (i % 8U))) & 1U;
}


bool lpofi_bch_encode(
    const uint8_t data[LPOFI_BCH_DATA_BYTES],
    uint8_t ecc[LPOFI_BCH_ECC_BYTES])
{
    if (data == NULL || ecc == NULL) {
        return false;
    }

    /*
     * Direct GF(2) polynomial long division.
     *
     * work[0..127]   = data bits, MSB first
     * work[128..271] = appended zeros
     *
     * This represents data(x) * x^144.
     */
    uint8_t work[
        LPOFI_BCH_DATA_BYTES * 8U +
        LPOFI_BCH_ECC_BITS
    ];

    memset(work, 0, sizeof(work));

    for (unsigned i = 0;
         i < LPOFI_BCH_DATA_BYTES * 8U;
         ++i) {
        work[i] = data_bit(data, i);
    }

    /*
     * For each possible leading data position:
     *
     * if current coefficient == 1,
     * XOR g(x) aligned at that position.
     *
     * This is the bit-array equivalent of:
     *
     *     work ^= GENERATOR << shift
     *
     * used by the independently verified Python encoder.
     */
    for (unsigned i = 0;
         i < LPOFI_BCH_DATA_BYTES * 8U;
         ++i) {

        if (work[i] == 0U) {
            continue;
        }

        for (unsigned j = 0;
             j <= LPOFI_BCH_ECC_BITS;
             ++j) {

            work[i + j] ^= generator_bit(j);
        }
    }

    /*
     * After division, the first 128 coefficients must be zero.
     */
    for (unsigned i = 0;
         i < LPOFI_BCH_DATA_BYTES * 8U;
         ++i) {

        if (work[i] != 0U) {
            memset(work, 0, sizeof(work));
            memset(ecc, 0, LPOFI_BCH_ECC_BYTES);
            return false;
        }
    }

    /*
     * Final 144 bits are the remainder/ECC, MSB first.
     */
    memset(ecc, 0, LPOFI_BCH_ECC_BYTES);

    for (unsigned i = 0;
         i < LPOFI_BCH_ECC_BITS;
         ++i) {

        if (work[
                LPOFI_BCH_DATA_BYTES * 8U + i
            ]) {

            ecc[i / 8U] |=
                (uint8_t)(
                    1U << (7U - (i % 8U))
                );
        }
    }

    memset(work, 0, sizeof(work));

    return true;
}



/* ============================================================
 * BCH-C decoder
 *
 * Independent fixed implementation corresponding to the
 * validated Python decoder.
 *
 * GF(2^9), primitive polynomial 0x211
 * 32 syndromes
 * Berlekamp-Massey
 * Chien search
 * correction in place
 * syndrome post-check
 * ============================================================ */

#define BCH_GF_N       511
#define BCH_SYNDROMES  (2 * LPOFI_BCH_T)
#define BCH_MAX_POLY   (2 * LPOFI_BCH_T + 1)

static uint16_t bch_alpha_to[BCH_GF_N];
static int16_t  bch_index_of[BCH_GF_N + 1];
static bool     bch_gf_ready = false;


static void bch_gf_init(void)
{
    if (bch_gf_ready) {
        return;
    }

    for (unsigned i = 0; i <= BCH_GF_N; ++i) {
        bch_index_of[i] = -1;
    }

    uint16_t x = 1U;

    for (unsigned i = 0; i < BCH_GF_N; ++i) {

        bch_alpha_to[i] = x;
        bch_index_of[x] = (int16_t)i;

        x <<= 1U;

        if (x & (1U << LPOFI_BCH_M)) {
            x ^= LPOFI_BCH_PRIM_POLY;
        }

        x &= BCH_GF_N;
    }

    /*
     * With primitive polynomial 0x211, alpha^511 = 1.
     */
    if (x == 1U) {
        bch_gf_ready = true;
    }
}


static uint16_t bch_gf_mul(uint16_t a, uint16_t b)
{
    if (a == 0U || b == 0U) {
        return 0U;
    }

    int ia = bch_index_of[a];
    int ib = bch_index_of[b];

    return bch_alpha_to[(ia + ib) % BCH_GF_N];
}


static uint16_t bch_gf_div(uint16_t a, uint16_t b)
{
    if (b == 0U) {
        return 0U;
    }

    if (a == 0U) {
        return 0U;
    }

    int e = bch_index_of[a] - bch_index_of[b];

    e %= BCH_GF_N;

    if (e < 0) {
        e += BCH_GF_N;
    }

    return bch_alpha_to[e];
}


static uint8_t bch_packet_bit(
    const uint8_t packet[LPOFI_BCH_PACKET_BYTES],
    unsigned bit)
{
    return (packet[bit / 8U] >>
            (7U - (bit % 8U))) & 1U;
}


static void bch_flip_packet_bit(
    uint8_t packet[LPOFI_BCH_PACKET_BYTES],
    unsigned bit)
{
    packet[bit / 8U] ^=
        (uint8_t)(1U << (7U - (bit % 8U)));
}


/*
 * S[1] ... S[32].
 * S[0] is intentionally unused.
 */
static void bch_compute_syndromes(
    const uint8_t packet[LPOFI_BCH_PACKET_BYTES],
    uint16_t S[BCH_SYNDROMES + 1])
{
    memset(S, 0,
           sizeof(uint16_t) * (BCH_SYNDROMES + 1));

    for (unsigned j = 1; j <= BCH_SYNDROMES; ++j) {

        uint16_t syndrome = 0U;

        for (unsigned pos = 0;
             pos < LPOFI_BCH_PACKET_BYTES * 8U;
             ++pos) {

            if (!bch_packet_bit(packet, pos)) {
                continue;
            }

            /*
             * packet bit 0 corresponds to polynomial
             * degree 271, matching the validated Python
             * shortened-code convention.
             */
            unsigned degree =
                LPOFI_BCH_PACKET_BYTES * 8U - 1U - pos;

            unsigned exponent =
                (j * degree) % BCH_GF_N;

            syndrome ^= bch_alpha_to[exponent];
        }

        S[j] = syndrome;
    }
}


static bool bch_syndromes_zero(
    const uint16_t S[BCH_SYNDROMES + 1])
{
    for (unsigned i = 1; i <= BCH_SYNDROMES; ++i) {
        if (S[i] != 0U) {
            return false;
        }
    }

    return true;
}


/*
 * Berlekamp-Massey.
 *
 * locator[0..L] receives:
 *
 * Lambda(x) =
 *   1 + lambda_1*x + ... + lambda_L*x^L
 */
static int bch_berlekamp_massey(
    const uint16_t S[BCH_SYNDROMES + 1],
    uint16_t locator[BCH_MAX_POLY])
{
    uint16_t B[BCH_MAX_POLY];
    uint16_t old_locator[BCH_MAX_POLY];

    memset(locator, 0,
           sizeof(uint16_t) * BCH_MAX_POLY);

    memset(B, 0, sizeof(B));

    locator[0] = 1U;
    B[0] = 1U;

    int L = 0;
    int m = 1;
    uint16_t b = 1U;

    for (int n = 0; n < BCH_SYNDROMES; ++n) {

        uint16_t d = S[n + 1];

        for (int i = 1; i <= L; ++i) {

            if (locator[i] != 0U &&
                S[n + 1 - i] != 0U) {

                d ^= bch_gf_mul(
                    locator[i],
                    S[n + 1 - i]);
            }
        }

        if (d == 0U) {
            ++m;
            continue;
        }

        memcpy(old_locator,
               locator,
               sizeof(old_locator));

        uint16_t coef = bch_gf_div(d, b);

        for (int i = 0;
             i < BCH_MAX_POLY - m;
             ++i) {

            if (B[i] != 0U) {
                locator[i + m] ^=
                    bch_gf_mul(coef, B[i]);
            }
        }

        if (2 * L <= n) {

            L = n + 1 - L;

            memcpy(B,
                   old_locator,
                   sizeof(B));

            b = d;
            m = 1;

        } else {

            ++m;
        }
    }

    memset(B, 0, sizeof(B));
    memset(old_locator, 0, sizeof(old_locator));

    return L;
}


/*
 * Chien search over transmitted shortened positions only.
 *
 * Error at polynomial degree d has locator root alpha^(-d).
 */
static int bch_chien_search(
    const uint16_t locator[BCH_MAX_POLY],
    int L,
    unsigned positions[LPOFI_BCH_T])
{
    int found = 0;

    for (unsigned packet_pos = 0;
         packet_pos < LPOFI_BCH_PACKET_BYTES * 8U;
         ++packet_pos) {

        unsigned degree =
            LPOFI_BCH_PACKET_BYTES * 8U -
            1U - packet_pos;

        unsigned exp =
            (BCH_GF_N -
             (degree % BCH_GF_N))
            % BCH_GF_N;

        uint16_t x = bch_alpha_to[exp];

        uint16_t value = locator[0];
        uint16_t power = 1U;

        for (int i = 1; i <= L; ++i) {

            power = bch_gf_mul(power, x);

            if (locator[i] != 0U) {
                value ^=
                    bch_gf_mul(locator[i], power);
            }
        }

        if (value == 0U) {

            if (found >= LPOFI_BCH_T) {
                return -1;
            }

            positions[found++] = packet_pos;
        }
    }

    return found;
}


int lpofi_bch_decode(
    uint8_t packet[LPOFI_BCH_PACKET_BYTES])
{
    if (packet == NULL) {
        return -1;
    }

    bch_gf_init();

    if (!bch_gf_ready) {
        return -1;
    }

    uint16_t S[BCH_SYNDROMES + 1];

    bch_compute_syndromes(packet, S);

    if (bch_syndromes_zero(S)) {
        memset(S, 0, sizeof(S));
        return 0;
    }

    uint16_t locator[BCH_MAX_POLY];

    int L = bch_berlekamp_massey(S, locator);

    if (L <= 0 || L > LPOFI_BCH_T) {
        memset(S, 0, sizeof(S));
        memset(locator, 0, sizeof(locator));
        return -1;
    }

    unsigned positions[LPOFI_BCH_T];

    int found =
        bch_chien_search(locator, L, positions);

    if (found != L) {
        memset(S, 0, sizeof(S));
        memset(locator, 0, sizeof(locator));
        memset(positions, 0, sizeof(positions));
        return -1;
    }

    for (int i = 0; i < found; ++i) {
        bch_flip_packet_bit(packet, positions[i]);
    }

    /*
     * Authoritative algebraic post-check.
     */
    bch_compute_syndromes(packet, S);

    if (!bch_syndromes_zero(S)) {

        /*
         * Do not return a silently corrupted codeword.
         * Caller must treat this as decoding failure.
         */
        memset(S, 0, sizeof(S));
        memset(locator, 0, sizeof(locator));
        memset(positions, 0, sizeof(positions));

        return -1;
    }

    memset(S, 0, sizeof(S));
    memset(locator, 0, sizeof(locator));
    memset(positions, 0, sizeof(positions));

    return found;
}



/* ---------- reference vectors ---------- */

typedef struct {
    const char *name;

    uint8_t data[LPOFI_BCH_DATA_BYTES];

    uint8_t expected[LPOFI_BCH_ECC_BYTES];
} bch_vector_t;


static const bch_vector_t vectors[] = {

    {
        "zero",
        {0},
        {0}
    },

    {
        "ff",
        {
            0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff
        },
        {
            0x42,0xcc,0xf4,0x45,0x0f,0x0f,
            0xf4,0x32,0xe2,0xcc,0x16,0x50,
            0x10,0xb1,0xe4,0x52,0xa2,0x34
        }
    },

    {
        "incrementing",
        {
            0x00,0x01,0x02,0x03,
            0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,
            0x0c,0x0d,0x0e,0x0f
        },
        {
            0xc4,0xc6,0x7b,0x82,0x86,0xcd,
            0x86,0x01,0xc7,0xdf,0x5b,0xc1,
            0xb1,0xfa,0x01,0xff,0xd4,0xfd
        }
    },

    {
        "golden",
        {
            0x00,0x11,0x22,0x33,
            0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,
            0xcc,0xdd,0xee,0xff
        },
        {
            0x55,0x3b,0xd0,0x0d,0x2c,0xf1,
            0xfa,0x8b,0xb2,0x02,0x20,0x7f,
            0x53,0xf6,0x2e,0x81,0x91,0x5c
        }
    },

    {
        "walking_msb",
        {
            0x80,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00
        },
        {
            0xe3,0xaa,0x8e,0x67,0x88,0x88,
            0x0e,0x2b,0x93,0xaa,0x1d,0x78,
            0x18,0xe9,0x16,0x7b,0xf3,0x2e
        }
    },

    {
        "walking_lsb",
        {
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x01
        },
        {
            0x2b,0x6b,0xd0,0x54,0x5d,0xb3,
            0x4c,0x1e,0x01,0xd5,0x29,0x6e,
            0x58,0xc8,0xed,0x27,0x01,0xad
        }
    }
};


bool lpofi_bch_selftest(void)
{
    uint8_t ecc[LPOFI_BCH_ECC_BYTES];

    const unsigned count =
        sizeof(vectors) / sizeof(vectors[0]);

    for (unsigned i = 0; i < count; ++i) {

        memset(ecc, 0, sizeof(ecc));

        if (!lpofi_bch_encode(
                vectors[i].data,
                ecc)) {

            printf(
                "BCH_VECTOR,%s,ENCODE_FAIL\n",
                vectors[i].name
            );

            return false;
        }

        if (memcmp(
                ecc,
                vectors[i].expected,
                LPOFI_BCH_ECC_BYTES) != 0) {

            printf(
                "BCH_VECTOR,%s,MISMATCH\n",
                vectors[i].name
            );

            printf("BCH_EXPECTED,");

            for (unsigned j = 0;
                 j < LPOFI_BCH_ECC_BYTES;
                 ++j) {
                printf("%02X",
                       vectors[i].expected[j]);
            }

            printf("\nBCH_ACTUAL,");

            for (unsigned j = 0;
                 j < LPOFI_BCH_ECC_BYTES;
                 ++j) {
                printf("%02X", ecc[j]);
            }

            printf("\n");

            memset(ecc, 0, sizeof(ecc));

            return false;
        }

        printf(
            "BCH_VECTOR,%s,PASS\n",
            vectors[i].name
        );
    }

    memset(ecc, 0, sizeof(ecc));

    printf("BCH_VECTOR_SUMMARY,%u/%u,PASS\n",
           count, count);

    return true;
}


/* ============================================================
 * BCH-C deterministic decoder conformance self-test
 * ============================================================ */

typedef struct {
    const char *name;
    unsigned flips[17];
    unsigned flip_count;
    int expected_return;
} bch_decode_vector_t;


static const uint8_t bch_golden_packet[
    LPOFI_BCH_PACKET_BYTES
] = {
    0x00,0x11,0x22,0x33,
    0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,
    0xcc,0xdd,0xee,0xff,

    0x55,0x3b,0xd0,0x0d,
    0x2c,0xf1,0xfa,0x8b,
    0xb2,0x02,0x20,0x7f,
    0x53,0xf6,0x2e,0x81,
    0x91,0x5c
};


static const bch_decode_vector_t
bch_decode_vectors[] = {

    {
        "clean",
        {0},
        0,
        0
    },

    {
        "one_data_bit",
        {0},
        1,
        1
    },

    {
        "one_ecc_bit",
        {128},
        1,
        1
    },

    {
        "eight_spread",
        {
            0,17,34,51,
            68,85,130,200
        },
        8,
        8
    },

    {
        "sixteen_spread",
        {
            0,17,34,51,
            68,85,102,119,
            136,153,170,187,
            204,221,238,255
        },
        16,
        16
    },

    {
        "seventeen_spread",
        {
            0,16,32,48,
            64,80,96,112,
            128,144,160,176,
            192,208,224,240,
            256
        },
        17,
        -1
    }
};


bool lpofi_bch_decoder_selftest(void)
{
    uint8_t packet[LPOFI_BCH_PACKET_BYTES];

    const unsigned count =
        sizeof(bch_decode_vectors) /
        sizeof(bch_decode_vectors[0]);

    unsigned passed = 0;

    for (unsigned v = 0; v < count; ++v) {

        memcpy(packet,
               bch_golden_packet,
               sizeof(packet));

        for (unsigned i = 0;
             i < bch_decode_vectors[v].flip_count;
             ++i) {

            bch_flip_packet_bit(
                packet,
                bch_decode_vectors[v].flips[i]);
        }

        int result = lpofi_bch_decode(packet);

        bool ok;

        if (bch_decode_vectors[v].expected_return >= 0) {

            /*
             * Strong criterion:
             * decoder count must match AND the complete
             * corrected 34-byte packet must equal the
             * original codeword.
             */
            ok =
                result ==
                bch_decode_vectors[v].expected_return
                &&
                memcmp(
                    packet,
                    bch_golden_packet,
                    sizeof(packet)) == 0;

        } else {

            /*
             * For the frozen deterministic 17-error
             * vector, require explicit decoding failure.
             */
            ok = (result == -1);
        }

        printf(
            "BCH_DECODE,%s,%d,%s\n",
            bch_decode_vectors[v].name,
            result,
            ok ? "PASS" : "FAIL");

        if (ok) {
            ++passed;
        }
    }

    printf(
        "BCH_DECODE_SUMMARY,%u/%u,%s\n",
        passed,
        count,
        (passed == count) ? "PASS" : "FAIL");

    memset(packet, 0, sizeof(packet));

    return passed == count;
}
