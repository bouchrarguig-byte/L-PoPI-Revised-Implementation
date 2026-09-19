/*
 * Generated BCH-C enrollment data.
 *
 * Enrollment captures: 001-020
 * Region: 1
 *
 * BCH-C: m=9, t=16, n=511
 * Shortened packet: 34 bytes / 272 bits
 *
 * Selection:
 * first 272 indexes from the frozen enrollment-only
 * 1664-bit stable-cell pool.
 *
 * IMPORTANT:
 * The secret used for this integration artifact is the
 * deterministic J2 benchmark secret (seed 20260913).
 * This is for reproducible experimental validation and
 * is NOT a production secret-generation procedure.
 */

#pragma once

#include <stdint.h>

#define LPOFI_BCH_PUF_REGION 1
#define LPOFI_BCH_PUF_REGION_BYTES 256

#define LPOFI_BCH_PUF_SELECTED_BITS 272
#define LPOFI_BCH_PUF_SECRET_BYTES 16
#define LPOFI_BCH_PUF_PACKET_BYTES 34
#define LPOFI_BCH_PUF_KEY_BYTES 32

static const uint16_t lpofi_bch_puf_bit_indexes[272] = {
    0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    14, 15, 16, 18, 19, 20, 21, 22, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    41, 42, 43, 44, 45, 46, 49, 50, 52, 54, 56, 57,
    58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
    70, 71, 72, 73, 74, 75, 76, 77, 78, 80, 81, 82,
    83, 85, 86, 87, 90, 91, 92, 94, 95, 96, 97, 98,
    100, 101, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
    114, 115, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126,
    127, 128, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
    141, 142, 144, 146, 148, 149, 150, 151, 152, 153, 154, 156,
    157, 158, 160, 161, 162, 163, 164, 165, 166, 168, 170, 171,
    172, 173, 174, 175, 176, 178, 180, 181, 182, 183, 184, 185,
    186, 188, 189, 190, 191, 192, 193, 194, 195, 197, 198, 199,
    200, 201, 202, 204, 205, 207, 208, 209, 210, 211, 212, 213,
    215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 227,
    228, 230, 231, 232, 233, 234, 235, 237, 238, 239, 240, 241,
    242, 243, 245, 246, 249, 252, 253, 254, 255, 259, 260, 261,
    262, 263, 264, 265, 266, 267, 269, 270, 271, 272, 273, 274,
    276, 277, 278, 279, 280, 281, 283, 284, 288, 289, 290, 291,
    292, 293, 294, 296, 297, 298, 299, 300, 301, 302, 303, 305,
    307, 309, 310, 311, 313, 315, 316, 317, 318, 319, 320, 321,
    323, 324, 326, 327, 329, 330, 331, 332,
};

static const uint8_t lpofi_bch_puf_helper_bytes[34] = {
    0xfd, 0xd2, 0xa6, 0x7a, 0xb1, 0x32, 0x8e, 0x9a, 0x30, 0x3b, 0x9f, 0xcd,
    0xf3, 0x8a, 0xf3, 0xc6, 0xff, 0x53, 0x1d, 0xdc, 0x0a, 0x87, 0xc8, 0x6f,
    0x62, 0x37, 0x76, 0x15, 0x7b, 0x16, 0x7e, 0xd7, 0x3d, 0x61,
};

static const uint8_t lpofi_bch_puf_hkdf_salt[32] = {
    0x74, 0x6e, 0x52, 0x86, 0xfa, 0x8e, 0xc1, 0x68, 0xbf, 0x44, 0xb6, 0x3b,
    0x32, 0x26, 0xbe, 0xd6, 0xeb, 0x0e, 0x0a, 0x82, 0x2b, 0x0d, 0xb5, 0x03,
    0xda, 0x7b, 0x15, 0x38, 0xc7, 0xd3, 0xfb, 0xc3,
};

static const uint8_t lpofi_bch_puf_key_commitment[32] = {
    0xa3, 0x27, 0x67, 0x1d, 0x3c, 0x30, 0x08, 0x87, 0x78, 0x8a, 0x83, 0xd1,
    0xc6, 0xed, 0x6c, 0xd4, 0xb0, 0xc0, 0xb4, 0x60, 0xdc, 0x73, 0x59, 0xd9,
    0x51, 0x09, 0xb9, 0x24, 0xc8, 0xe9, 0xe8, 0x4e,
};
