#include <stdint.h>
#include "esp_rom_sys.h"
#include "puf_build_config.h"
#include "puf_handoff.h"

/*
 * ============================================================
 * L-PoPI Early-Boot SRAM PUF Experiment
 * Target: ESP32 classic / Xtensa
 *
 * IMPORTANT:
 * This is an experimental early-boot SRAM response capture.
 * It must NOT yet be considered a cryptographic PUF until
 * repeated power-cycle measurements have been analyzed.
 * ============================================================
 */

/*
 * Candidate SRAM regions.
 *
 * Bootloader DRAM:
 *   0x3FFF0000 - 0x3FFF5FFF
 *
 * We deliberately avoid the beginning of the region where
 * the bootloader's linked .bss/.data sections are located.
 *
 * These addresses are candidates and must be experimentally
 * validated.
 */
#define REGION_COUNT       5
#define REGION_SIZE        256

#define REGION0_ADDR       0x3FFF1000
#define REGION1_ADDR       0x3FFF2000
#define REGION2_ADDR       0x3FFF3000
#define REGION3_ADDR       0x3FFF4000
#define REGION4_ADDR       0x3FFF5000

static const uintptr_t region_addresses[REGION_COUNT] = {
    REGION0_ADDR,
    REGION1_ADDR,
    REGION2_ADDR,
    REGION3_ADDR,
    REGION4_ADDR
};

static volatile lpofi_puf_handoff_t *const puf_handoff =
    (volatile lpofi_puf_handoff_t *)LPOFI_RTC_HANDOFF_ADDR;


/*
 * Print one SRAM region in a machine-readable format.
 *
 * Example:
 *
 * PUF_REGION_START,1,0x3FFF2000,256
 * PUF_DATA,1,C6D8FA1C...
 * PUF_REGION_END,1
 */
static void capture_region(int region_id, uintptr_t address)
{
    volatile const uint8_t *p =
        (volatile const uint8_t *)address;

#if LPOFI_PUF_DEBUG_CAPTURE
    esp_rom_printf("PUF_REGION_START,%d,0x%08X,%d\r\n", region_id,
                   (unsigned int)address, REGION_SIZE);
    esp_rom_printf("PUF_DATA,%d,", region_id);
#endif

    for (int i = 0; i < REGION_SIZE; i++) {

        uint8_t value = p[i];

        /* Region 1 is the enrolled source. Copy it before application boot. */
        if (region_id == LPOFI_PUF_SOURCE_REGION) {
            puf_handoff->raw_region[i] = value;
        }

#if LPOFI_PUF_DEBUG_CAPTURE
        esp_rom_printf(
            "%02X",
            (unsigned int)value
        );
#endif
    }

#if LPOFI_PUF_DEBUG_CAPTURE
    esp_rom_printf("\r\n");
    esp_rom_printf("PUF_REGION_END,%d\r\n", region_id);
#endif
}


void bootloader_hooks_include(void)
{
}


/*
 * ============================================================
 * EARLY BOOT HOOK
 * ============================================================
 *
 * This executes before bootloader_init().
 *
 * Keep this function extremely simple.
 *
 * DO NOT:
 *   - use malloc()
 *   - use FreeRTOS
 *   - use normal ESP-IDF logging
 *   - access SPI flash
 *   - initialize peripherals
 *   - use complex library functions
 *
 * ROM printf is used because it is available at this stage.
 */
void bootloader_before_init(void)
{
    /* Invalidate first. The application accepts a record only after CRC+magic. */
    puf_handoff->magic = 0;
    puf_handoff->version = LPOFI_PUF_HANDOFF_VERSION;
    puf_handoff->region_id = LPOFI_PUF_SOURCE_REGION; 
    puf_handoff->region_bytes = LPOFI_PUF_HANDOFF_REGION_BYTES;
    puf_handoff->reserved = 0;
#if LPOFI_PUF_DEBUG_CAPTURE
    esp_rom_printf("\r\nL-POPI EARLY SRAM CAPTURE\r\nPUF_CAPTURE_START\r\n");
    esp_rom_printf("PUF_REGIONS,1\r\nPUF_REGION_SIZE,%d\r\n", REGION_SIZE);
#endif

    /*
     * Capture all candidate regions.
     */
    if (LPOFI_PUF_SOURCE_REGION < REGION_COUNT) {
        capture_region(LPOFI_PUF_SOURCE_REGION,
                       region_addresses[LPOFI_PUF_SOURCE_REGION]);
    }

    if (LPOFI_PUF_SOURCE_REGION < REGION_COUNT) {
        puf_handoff->crc32 = lpofi_puf_handoff_crc(puf_handoff);
        puf_handoff->magic = LPOFI_PUF_HANDOFF_MAGIC;
    }

#if LPOFI_PUF_DEBUG_CAPTURE
    esp_rom_printf(
        "PUF_CAPTURE_END\r\n"
    );
#endif
}


void bootloader_after_init(void)
{
}
