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
