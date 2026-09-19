#include "lpofi_zk_binding.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "psa/crypto.h"

static const uint8_t DERIVE_DOMAIN[] =
    "L-POPI/ZK/BN254-SCALAR/v1";

static const uint8_t SALT_SUFFIX[] =
    "/salt";

static const uint8_t CANDIDATE_SUFFIX[] =
    "/candidate/";

static const uint8_t TAG_DOMAIN[] =
    "L-POPI/ZK/scalar-check/v1";

/*
 * BN254 scalar-field modulus:
 *
 * 21888242871839275222246405745257275088548364400416034343698204186575808495617
 *
 * 32-byte unsigned big-endian representation.
 */
static const uint8_t BN254_FR[32] = {
    0x30, 0x64, 0x4e, 0x72,
    0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6,
    0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91,
    0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16,
    0xd8, 0x7c, 0xfd, 0x47
};


static void secure_zero_local(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    while (len--) {
        *p++ = 0;
    }
}


static bool is_zero32(const uint8_t x[32])
{
    uint8_t acc = 0;

    for (size_t i = 0; i < 32; ++i) {
        acc |= x[i];
    }

    return acc == 0;
}


/*
 * Both operands are exactly 32-byte unsigned big-endian
 * integers, so lexicographic byte comparison is numeric
 * comparison.
 */
static bool less_than_fr(const uint8_t x[32])
{
    for (size_t i = 0; i < 32; ++i) {

        if (x[i] < BN254_FR[i]) {
            return true;
        }

        if (x[i] > BN254_FR[i]) {
            return false;
        }
    }

    /* Equality is not accepted. */
    return false;
}


static esp_err_t sha256_bytes(
    const uint8_t *input,
    size_t input_len,
    uint8_t output[32])
{
    size_t output_len = 0;

    psa_status_t status = psa_hash_compute(
        PSA_ALG_SHA_256,
        input,
        input_len,
        output,
        32,
        &output_len
    );

    if (status != PSA_SUCCESS || output_len != 32) {
        memset(output, 0, 32);
        return ESP_FAIL;
    }

    return ESP_OK;
}


/*
 * HMAC-SHA256 implemented through a transient PSA key.
 */
static esp_err_t hmac_sha256(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t output[32])
{
    psa_key_attributes_t attributes =
        PSA_KEY_ATTRIBUTES_INIT;

    psa_key_id_t key_id = 0;

    psa_set_key_usage_flags(
        &attributes,
        PSA_KEY_USAGE_SIGN_MESSAGE
    );

    psa_set_key_algorithm(
        &attributes,
        PSA_ALG_HMAC(PSA_ALG_SHA_256)
    );

    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_HMAC
    );

    psa_set_key_bits(
        &attributes,
        key_len * 8
    );

    psa_status_t status = psa_import_key(
        &attributes,
        key,
        key_len,
        &key_id
    );

    psa_reset_key_attributes(&attributes);

    if (status != PSA_SUCCESS) {
        memset(output, 0, 32);
        return ESP_FAIL;
    }

    size_t output_len = 0;

    status = psa_mac_compute(
        key_id,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        data,
        data_len,
        output,
        32,
        &output_len
    );

    psa_status_t destroy_status =
        psa_destroy_key(key_id);

    if (status != PSA_SUCCESS ||
        destroy_status != PSA_SUCCESS ||
        output_len != 32) {

        memset(output, 0, 32);
        return ESP_FAIL;
    }

    return ESP_OK;
}


esp_err_t lpofi_zk_derive_scalar(
    const uint8_t fe_key[32],
    uint8_t scalar_out[32],
    uint32_t *accepted_counter)
{
    if (!fe_key || !scalar_out || !accepted_counter) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_status_t status = psa_crypto_init();

    if (status != PSA_SUCCESS) {
        return ESP_FAIL;
    }

    /*
     * salt =
     * SHA256(DERIVE_DOMAIN || "/salt")
     */
    uint8_t salt_input[
        sizeof(DERIVE_DOMAIN) - 1 +
        sizeof(SALT_SUFFIX) - 1
    ];

    memcpy(
        salt_input,
        DERIVE_DOMAIN,
        sizeof(DERIVE_DOMAIN) - 1
    );

    memcpy(
        salt_input + sizeof(DERIVE_DOMAIN) - 1,
        SALT_SUFFIX,
        sizeof(SALT_SUFFIX) - 1
    );

    uint8_t salt[32];

    esp_err_t err = sha256_bytes(
        salt_input,
        sizeof(salt_input),
        salt
    );

    secure_zero_local(
        salt_input,
        sizeof(salt_input)
    );

    if (err != ESP_OK) {
        return err;
    }

    /*
     * HKDF-Extract:
     *
     * PRK = HMAC-SHA256(salt, FE_KEY)
     */
    uint8_t prk[32];

    err = hmac_sha256(
        salt,
        sizeof(salt),
        fe_key,
        32,
        prk
    );

    secure_zero_local(salt, sizeof(salt));

    if (err != ESP_OK) {
        secure_zero_local(prk, sizeof(prk));
        return err;
    }

    /*
     * Frozen v1 rejection sampling.
     *
     * info =
     *   DOMAIN || "/candidate/" || uint32_be(counter)
     *
     * Since output length is exactly 32 bytes,
     * RFC5869 HKDF-Expand consists of one block:
     *
     * T(1) = HMAC(PRK, info || 0x01)
     */
    uint8_t expand_input[
        sizeof(DERIVE_DOMAIN) - 1 +
        sizeof(CANDIDATE_SUFFIX) - 1 +
        4 +
        1
    ];

    const size_t prefix_len =
        sizeof(DERIVE_DOMAIN) - 1 +
        sizeof(CANDIDATE_SUFFIX) - 1;

    memcpy(
        expand_input,
        DERIVE_DOMAIN,
        sizeof(DERIVE_DOMAIN) - 1
    );

    memcpy(
        expand_input + sizeof(DERIVE_DOMAIN) - 1,
        CANDIDATE_SUFFIX,
        sizeof(CANDIDATE_SUFFIX) - 1
    );

    /*
     * The loop is bounded defensively. For the frozen
     * experimental vector the accepted counter is 16.
     */
    for (uint32_t counter = 0;
         counter < 1024;
         ++counter) {

        expand_input[prefix_len + 0] =
            (uint8_t)(counter >> 24);

        expand_input[prefix_len + 1] =
            (uint8_t)(counter >> 16);

        expand_input[prefix_len + 2] =
            (uint8_t)(counter >> 8);

        expand_input[prefix_len + 3] =
            (uint8_t)counter;

        /* RFC5869 block index T(1). */
        expand_input[prefix_len + 4] = 0x01;

        err = hmac_sha256(
            prk,
            sizeof(prk),
            expand_input,
            sizeof(expand_input),
            scalar_out
        );

        if (err != ESP_OK) {
            secure_zero_local(
                prk,
                sizeof(prk)
            );

            secure_zero_local(
                expand_input,
                sizeof(expand_input)
            );

            memset(scalar_out, 0, 32);
            return err;
        }

        if (!is_zero32(scalar_out) &&
            less_than_fr(scalar_out)) {

            *accepted_counter = counter;

            secure_zero_local(
                prk,
                sizeof(prk)
            );

            secure_zero_local(
                expand_input,
                sizeof(expand_input)
            );

            return ESP_OK;
        }

        secure_zero_local(
            scalar_out,
            32
        );
    }

    secure_zero_local(prk, sizeof(prk));

    secure_zero_local(
        expand_input,
        sizeof(expand_input)
    );

    memset(scalar_out, 0, 32);

    return ESP_ERR_NOT_FOUND;
}


esp_err_t lpofi_zk_scalar_tag(
    const uint8_t scalar[32],
    uint8_t tag_out[32])
{
    if (!scalar || !tag_out) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t tag_input[
        sizeof(TAG_DOMAIN) - 1 + 32
    ];

    memcpy(
        tag_input,
        TAG_DOMAIN,
        sizeof(TAG_DOMAIN) - 1
    );

    memcpy(
        tag_input + sizeof(TAG_DOMAIN) - 1,
        scalar,
        32
    );

    esp_err_t err = sha256_bytes(
        tag_input,
        sizeof(tag_input),
        tag_out
    );

    secure_zero_local(
        tag_input,
        sizeof(tag_input)
    );

    return err;
}
