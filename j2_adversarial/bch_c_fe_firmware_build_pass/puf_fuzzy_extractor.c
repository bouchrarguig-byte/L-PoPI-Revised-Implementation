#include "puf_fuzzy_extractor.h"

#include <stdbool.h>
#include <string.h>

#include "esp_log.h"
#include "psa/crypto.h"

#include "lpofi_bch.h"
#include "puf_enrollment_bch_c_region1.h"

static const char *TAG = "PUF_FE";

static const uint8_t HKDF_INFO[] =
    "L-POPI/ESP32/SRAM-PUF/v1";

static const uint8_t COMMIT_INFO[] =
    "L-POPI/ESP32/SRAM-PUF/key-commit/v1";


static uint8_t bit_at(
    const uint8_t *data,
    uint16_t index)
{
    return
        (data[index / 8] >>
         (7 - (index % 8))) & 1U;
}


/*
 * Reconstruct the shortened BCH-C packet:
 *
 *     recovered_codeword =
 *         selected_SRAM_bits XOR helper
 *
 * Bit ordering is MSB-first within every byte, matching
 * the frozen Python enrollment and BCH implementation.
 */
static void reconstruct_bch_packet(
    const uint8_t *raw_region,
    uint8_t packet[LPOFI_BCH_PACKET_BYTES])
{
    memset(
        packet,
        0,
        LPOFI_BCH_PACKET_BYTES
    );

    for (size_t i = 0;
         i < LPOFI_BCH_PUF_SELECTED_BITS;
         ++i) {

        uint8_t puf_bit = bit_at(
            raw_region,
            lpofi_bch_puf_bit_indexes[i]
        );

        uint8_t helper_bit =
            (lpofi_bch_puf_helper_bytes[i / 8] >>
             (7 - (i % 8))) & 1U;

        uint8_t recovered_bit =
            puf_bit ^ helper_bit;

        if (recovered_bit) {
            packet[i / 8] |=
                (uint8_t)(
                    1U << (7 - (i % 8))
                );
        }
    }
}


esp_err_t lpofi_puf_reproduce_key(
    const uint8_t *raw_region,
    size_t raw_region_len,
    uint8_t key_out[32])
{
    if (!raw_region ||
        !key_out ||
        raw_region_len != LPOFI_BCH_PUF_REGION_BYTES ||
        LPOFI_BCH_PUF_SELECTED_BITS !=
            LPOFI_BCH_PACKET_BYTES * 8 ||
        LPOFI_BCH_PUF_SECRET_BYTES !=
            LPOFI_BCH_DATA_BYTES ||
        LPOFI_BCH_PUF_PACKET_BYTES !=
            LPOFI_BCH_PACKET_BYTES) {

        return ESP_ERR_INVALID_ARG;
    }

    /*
     * Recover helper XOR SRAM response.
     * lpofi_bch_decode() corrects this packet in place.
     */
    uint8_t packet[LPOFI_BCH_PACKET_BYTES];

    reconstruct_bch_packet(
        raw_region,
        packet
    );

    int corrected_errors =
        lpofi_bch_decode(packet);

    if (corrected_errors < 0) {

        ESP_LOGE(
            TAG,
            "BCH_C_FE,decoder=FAIL"
        );

        memset(
            packet,
            0,
            sizeof(packet)
        );

        memset(key_out, 0, 32);

        return ESP_ERR_INVALID_CRC;
    }

    ESP_LOGI(
        TAG,
        "BCH_C_FE,decoder_errors=%d",
        corrected_errors
    );

    /*
     * After successful BCH decoding, packet[0..15]
     * is the corrected 128-bit enrollment secret.
     */
    psa_status_t status =
        psa_crypto_init();

    if (status != PSA_SUCCESS) {

        memset(
            packet,
            0,
            sizeof(packet)
        );

        memset(key_out, 0, 32);

        return ESP_FAIL;
    }

    psa_key_derivation_operation_t operation =
        PSA_KEY_DERIVATION_OPERATION_INIT;

    status = psa_key_derivation_setup(
        &operation,
        PSA_ALG_HKDF(PSA_ALG_SHA_256)
    );

    if (status == PSA_SUCCESS) {
        status =
            psa_key_derivation_input_bytes(
                &operation,
                PSA_KEY_DERIVATION_INPUT_SALT,
                lpofi_bch_puf_hkdf_salt,
                sizeof(lpofi_bch_puf_hkdf_salt)
            );
    }

    if (status == PSA_SUCCESS) {
        status =
            psa_key_derivation_input_bytes(
                &operation,
                PSA_KEY_DERIVATION_INPUT_SECRET,
                packet,
                LPOFI_BCH_DATA_BYTES
            );
    }

    if (status == PSA_SUCCESS) {
        status =
            psa_key_derivation_input_bytes(
                &operation,
                PSA_KEY_DERIVATION_INPUT_INFO,
                HKDF_INFO,
                sizeof(HKDF_INFO) - 1
            );
    }

    if (status == PSA_SUCCESS) {
        status =
            psa_key_derivation_output_bytes(
                &operation,
                key_out,
                32
            );
    }

    psa_key_derivation_abort(
        &operation
    );

    /*
     * Secret and corrected codeword are no longer
     * required after HKDF.
     */
    memset(
        packet,
        0,
        sizeof(packet)
    );

    if (status != PSA_SUCCESS) {

        memset(key_out, 0, 32);

        return ESP_FAIL;
    }

    /*
     * Final enrollment-key validation:
     *
     * SHA256(
     *   "L-POPI/ESP32/SRAM-PUF/key-commit/v1"
     *   || derived_key
     * )
     */
    uint8_t digest[32];

    uint8_t commitment_input[
        sizeof(COMMIT_INFO) - 1 + 32
    ];

    memcpy(
        commitment_input,
        COMMIT_INFO,
        sizeof(COMMIT_INFO) - 1
    );

    memcpy(
        commitment_input +
            sizeof(COMMIT_INFO) - 1,
        key_out,
        32
    );

    size_t digest_length = 0;

    status = psa_hash_compute(
        PSA_ALG_SHA_256,
        commitment_input,
        sizeof(commitment_input),
        digest,
        sizeof(digest),
        &digest_length
    );

    memset(
        commitment_input,
        0,
        sizeof(commitment_input)
    );

    bool valid =
        (status == PSA_SUCCESS) &&
        (digest_length == sizeof(digest)) &&
        (memcmp(
            digest,
            lpofi_bch_puf_key_commitment,
            sizeof(digest)
        ) == 0);

    memset(
        digest,
        0,
        sizeof(digest)
    );

    if (!valid) {

        ESP_LOGE(
            TAG,
            "BCH_C_FE,commitment=FAIL"
        );

        memset(key_out, 0, 32);

        return ESP_ERR_INVALID_CRC;
    }

    ESP_LOGI(
        TAG,
        "BCH_C_FE,commitment=PASS"
    );

    return ESP_OK;
}
