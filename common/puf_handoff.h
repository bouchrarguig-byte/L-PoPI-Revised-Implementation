#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * The ESP32's RTC slow memory begins at this address.  The application owns
 * the first RTC_NOINIT object, and validates this placement at run time.
 * Do not enable ULP RTC-memory reservation without changing this address.
 */
#define LPOFI_RTC_HANDOFF_ADDR 0x50000000UL
#define LPOFI_PUF_HANDOFF_MAGIC 0x4C505046UL /* "LPPF" */
#define LPOFI_PUF_HANDOFF_VERSION 1U
#define LPOFI_PUF_HANDOFF_REGION_BYTES 256U

typedef struct {
    uint32_t magic;       /* Written last by the bootloader. */
    uint16_t version;
    uint16_t region_id;
    uint16_t region_bytes;
    uint16_t reserved;
    uint8_t raw_region[LPOFI_PUF_HANDOFF_REGION_BYTES];
    uint32_t crc32;
} lpofi_puf_handoff_t;

static inline uint32_t lpofi_crc32_update(uint32_t crc, uint8_t byte)
{
    crc ^= byte;
    for (unsigned bit = 0; bit < 8; ++bit) {
        crc = (crc >> 1) ^ (0xEDB88320UL & (0U - (crc & 1U)));
    }
    return crc;
}

static inline uint32_t lpofi_puf_handoff_crc(const volatile lpofi_puf_handoff_t *handoff)
{
    const volatile uint8_t *data = (const volatile uint8_t *)&handoff->version;
    const size_t length = offsetof(lpofi_puf_handoff_t, crc32) -
                          offsetof(lpofi_puf_handoff_t, version);
    uint32_t crc = 0xFFFFFFFFUL;
    for (size_t i = 0; i < length; ++i) {
        crc = lpofi_crc32_update(crc, data[i]);
    }
    return ~crc;
}

static inline void lpofi_puf_handoff_clear(volatile lpofi_puf_handoff_t *handoff)
{
    volatile uint8_t *data = (volatile uint8_t *)handoff;
    for (size_t i = 0; i < sizeof(*handoff); ++i) {
        data[i] = 0;
    }
}
