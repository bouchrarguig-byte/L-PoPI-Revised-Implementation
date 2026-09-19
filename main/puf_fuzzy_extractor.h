#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/*
 * Derive the 32-byte L-PoPI attestation key from one early-boot PUF region.
 * raw_region must be copied by the bootloader hook before that region is used
 * by any startup code.  This function never persists the reconstructed secret.
 */
esp_err_t lpofi_puf_reproduce_key(const uint8_t *raw_region, size_t raw_region_len,
                                  uint8_t key_out[32]);
