#include <stdint.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "puf_fuzzy_extractor.h"
#include "puf_enrollment_generated.h"
#include "puf_handoff.h"
#include "puf_build_config.h"

static const char *TAG = "SRAM_PUF";

/* Must remain the first RTC_NOINIT object in this application. */
static RTC_NOINIT_ATTR volatile lpofi_puf_handoff_t s_puf_handoff;

#if LPOFI_PUF_DEBUG_CAPTURE
static void print_puf_capture(void)
{
    printf("PUF_CAPTURE_START\n");
    printf("PUF_REGIONS,1\n");
    printf("PUF_REGION_SIZE,%u\n",
           (unsigned)LPOFI_PUF_REGION_BYTES);

    printf("PUF_REGION_START,%u,0x3FFF5000,%u\n",
           (unsigned)s_puf_handoff.region_id,
           (unsigned)s_puf_handoff.region_bytes);

    printf("PUF_DATA,%u,",
           (unsigned)s_puf_handoff.region_id);

    for (size_t i = 0; i < s_puf_handoff.region_bytes; ++i) {
        printf("%02X",
               (unsigned)s_puf_handoff.raw_region[i]);
    }

    printf("\nPUF_REGION_END,%u\n",
           (unsigned)s_puf_handoff.region_id);

    printf("PUF_CAPTURE_END\n");
    fflush(stdout);
}
#endif


static bool handoff_is_valid(void)
{
    if ((uintptr_t)&s_puf_handoff != LPOFI_RTC_HANDOFF_ADDR) {
        ESP_LOGE(TAG, "RTC handoff address changed; check ULP/RTC linker configuration");
        return false;
    }
    if (s_puf_handoff.magic != LPOFI_PUF_HANDOFF_MAGIC) {
        ESP_LOGE(TAG, "PUF handoff rejected: magic");
        return false;
    }
    if (s_puf_handoff.version != LPOFI_PUF_HANDOFF_VERSION) {
        ESP_LOGE(TAG, "PUF handoff rejected: version");
        return false;
    }
    if (s_puf_handoff.region_id != LPOFI_PUF_REGION_ID) {
        ESP_LOGE(TAG, "PUF handoff rejected: region");
        return false;
    }
    if (s_puf_handoff.region_bytes != LPOFI_PUF_REGION_BYTES) {
        ESP_LOGE(TAG, "PUF handoff rejected: size");
        return false;
    }
    if (s_puf_handoff.crc32 != lpofi_puf_handoff_crc(&s_puf_handoff)) {
        ESP_LOGE(TAG, "PUF handoff rejected: CRC");
        return false;
    }
    return true;
}

void app_main(void)
{
    ESP_LOGI(TAG, "L-PoPI SRAM-PUF reproduction test");

    uint8_t key[32] = {0};
    if (!handoff_is_valid()) {
        ESP_LOGE(TAG, "PUF_HANDOFF_INVALID");
    } else {

#if LPOFI_PUF_DEBUG_CAPTURE
        /*
         * The SRAM response was already captured by the early boot hook.
         * Delay only the UART export so that the host can reconnect after
         * a complete USB power cycle.
         */
        vTaskDelay(pdMS_TO_TICKS(3000));
        print_puf_capture();
#endif

        esp_err_t result = lpofi_puf_reproduce_key((const uint8_t *)s_puf_handoff.raw_region,
                                                   LPOFI_PUF_REGION_BYTES, key);
        if (result == ESP_OK) {
            ESP_LOGI(TAG, "PUF_REPRODUCTION,PASS");
        } else {
            ESP_LOGE(TAG, "PUF_REPRODUCTION,FAIL,0x%x", (unsigned)result);
        }
    }
    /* Never retain an early-boot response or reconstructed key after use. */
    lpofi_puf_handoff_clear(&s_puf_handoff);
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = 0;
    }

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
