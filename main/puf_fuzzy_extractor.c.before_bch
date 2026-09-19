#include "puf_fuzzy_extractor.h"

#include <stdbool.h>
#include <string.h>
#include "psa/crypto.h"
#include "puf_enrollment_generated.h"

static const uint8_t HKDF_INFO[] = "L-POPI/ESP32/SRAM-PUF/v1";
static const uint8_t COMMIT_INFO[] = "L-POPI/ESP32/SRAM-PUF/key-commit/v1";

static uint8_t bit_at(const uint8_t *data, uint16_t index)
{
    return (data[index / 8] >> (7 - (index % 8))) & 1U;
}

esp_err_t lpofi_puf_reproduce_key(const uint8_t *raw_region, size_t raw_region_len,
                                  uint8_t key_out[32])
{
    if (!raw_region || !key_out || raw_region_len != LPOFI_PUF_REGION_BYTES ||
        LPOFI_PUF_SELECTED_BITS != LPOFI_PUF_SECRET_BYTES * 8 * LPOFI_PUF_GROUP_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t secret[LPOFI_PUF_SECRET_BYTES] = {0};
    for (size_t secret_bit = 0; secret_bit < LPOFI_PUF_SECRET_BYTES * 8; ++secret_bit) {
        unsigned ones = 0;
        for (size_t offset = 0; offset < LPOFI_PUF_GROUP_SIZE; ++offset) {
            size_t i = secret_bit * LPOFI_PUF_GROUP_SIZE + offset;
            ones += bit_at(raw_region, lpofi_puf_bit_indexes[i]) ^ lpofi_puf_helper_bits[i];
        }
        if (ones > LPOFI_PUF_GROUP_SIZE / 2) {
            secret[secret_bit / 8] |= (uint8_t)(1U << (7 - (secret_bit % 8)));
        }
    }

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        memset(secret, 0, sizeof(secret));
        return ESP_FAIL;
    }
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SALT,
                                                lpofi_puf_hkdf_salt, sizeof(lpofi_puf_hkdf_salt));
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SECRET,
                                                secret, sizeof(secret));
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_INFO,
                                                HKDF_INFO, sizeof(HKDF_INFO) - 1);
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_output_bytes(&operation, key_out, 32);
    }
    psa_key_derivation_abort(&operation);
    memset(secret, 0, sizeof(secret));
    if (status != PSA_SUCCESS) {
        memset(key_out, 0, 32);
        return ESP_FAIL;
    }

    uint8_t digest[32];
    uint8_t commitment_input[sizeof(COMMIT_INFO) - 1 + 32];
    memcpy(commitment_input, COMMIT_INFO, sizeof(COMMIT_INFO) - 1);
    memcpy(commitment_input + sizeof(COMMIT_INFO) - 1, key_out, 32);
    size_t digest_length = 0;
    status = psa_hash_compute(PSA_ALG_SHA_256, commitment_input, sizeof(commitment_input),
                              digest, sizeof(digest), &digest_length);
    memset(commitment_input, 0, sizeof(commitment_input));
    bool valid = (status == PSA_SUCCESS) && (digest_length == sizeof(digest)) &&
                 (memcmp(digest, lpofi_puf_key_commitment, sizeof(digest)) == 0);
    memset(digest, 0, sizeof(digest));
    if (!valid) {
        memset(key_out, 0, 32);
        return ESP_ERR_INVALID_CRC;
    }
    return ESP_OK;
}
