#ifndef LPOFI_ZK_BINDING_H
#define LPOFI_ZK_BINDING_H

#include <stdint.h>
#include "esp_err.h"

/*
 * Derive the BN254 Fr witness scalar from the 32-byte
 * fuzzy-extractor key using the frozen convention:
 *
 *   lpofi-fe-key-to-bn254-fr-v1
 *
 * The scalar is returned as exactly 32 bytes, big-endian.
 */
esp_err_t lpofi_zk_derive_scalar(
    const uint8_t fe_key[32],
    uint8_t scalar_out[32],
    uint32_t *accepted_counter
);

/*
 * Non-secret conformance tag:
 *
 * SHA256(
 *   "L-POPI/ZK/scalar-check/v1" || scalar32_be
 * )
 */
esp_err_t lpofi_zk_scalar_tag(
    const uint8_t scalar[32],
    uint8_t tag_out[32]
);

#endif
