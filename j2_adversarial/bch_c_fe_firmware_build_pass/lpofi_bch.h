#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LPOFI_BCH_M           9
#define LPOFI_BCH_T           16
#define LPOFI_BCH_N           511
#define LPOFI_BCH_PRIM_POLY   0x211

#define LPOFI_BCH_DATA_BYTES  16
#define LPOFI_BCH_ECC_BITS    144
#define LPOFI_BCH_ECC_BYTES   18
#define LPOFI_BCH_PACKET_BYTES \
    (LPOFI_BCH_DATA_BYTES + LPOFI_BCH_ECC_BYTES)

/*
 * Fixed BCH-C encoder.
 *
 * Parameters:
 *   m          = 9
 *   t          = 16
 *   n          = 511
 *   prim_poly  = 0x211
 *   ecc_bits   = 144
 *
 * Generator:
 *   g(x) =
 *   0x12b6bd0545db34c1e01d5296e58c8ed2701ad
 *
 * The implementation is checked against byte-level reference
 * vectors generated with bchlib 2.1.3.
 */

bool lpofi_bch_encode(const uint8_t data[LPOFI_BCH_DATA_BYTES],
                      uint8_t ecc[LPOFI_BCH_ECC_BYTES]);

/*
 * Decode/correct one shortened BCH-C codeword in place.
 *
 * Return:
 *   0      clean codeword
 *   1..16  number of corrected bit errors
 *  -1      decoding failure / uncorrectable
 */
int lpofi_bch_decode(
    uint8_t packet[LPOFI_BCH_PACKET_BYTES]);

bool lpofi_bch_selftest(void);
bool lpofi_bch_decoder_selftest(void);

