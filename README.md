# L-PoPI ESP32 SRAM-PUF

This project captures candidate ESP32 SRAM startup regions from a bootloader
hook, characterises reset stability, and now includes a reproducible Phase-1
fuzzy-extractor enrollment workflow.

## What the current data establishes

The existing 30 reset captures establish *intra-device reset stability*. They
do not establish PUF uniqueness, min-entropy, cold-boot behaviour, or security
against physical access. Do not use the resulting key for production assets.

## Enroll the current device

From this directory and the Python virtual environment:

```bash
python3 enroll_puf.py
```

The command consumes `puf_results/reset_capture_*.txt`, uses region 1, retains
bits with at least 95% observed reliability, and writes:

- `enrollment/puf_helper.json`: public helper data, HKDF salt, and a key
  commitment; it contains neither the random secret nor the derived key.
- `main/puf_enrollment_generated.h`: the public helper data embedded in the
  ESP-IDF application.

The default uses 128 secret bits and a 13-bit repetition code (1,664 selected
SRAM bits). It is intentionally a measurable baseline; replace it with a
reviewed BCH secure sketch before a production deployment.

## Firmware API

`lpofi_puf_reproduce_key(raw_region, 256, key)` decodes the selected SRAM bits,
derives a 32-byte key with HKDF-SHA-256, and checks it against the enrollment
commitment. A mismatch returns `ESP_ERR_INVALID_CRC` and zeroes the output key.

`raw_region` is now copied by the early bootloader hook into a versioned RTC
`NOINIT` handoff record. The application verifies the magic value, metadata and
CRC, runs the extractor, then zeroes both the handoff and temporary key. The
firmware logs only `PUF_REPRODUCTION,PASS` or a failure code; it never prints a
raw response or key.

This build assumes RTC slow memory starts at `0x50000000` with no ULP-reserved
prefix. The application rejects the handoff if the linker places its RTC record
elsewhere, rather than reading an ambiguous memory location.

## Secure re-enrollment procedure

The previously logged regions `0`–`3` are demonstration data only. Do not use
them to protect a production identity. Region `4` (`0x3FFF5000`) is a new
candidate that is outside the currently linked bootloader data range; it still
must be characterised before use.

1. Temporarily configure region `4` and debug capture with:
   `python3 configure_puf.py --region 4 --debug-capture on`.
2. Build/flash and privately collect 30 reset captures with:
   `python3 collect_private_region.py --port /dev/ttyUSB1 --region 4`.
   Never upload or paste those raw records.
3. Enroll the new region with:
   `python3 enroll_puf.py --capture-dir puf_private_results --region 4`.
4. Disable raw capture while retaining source region `4` with:
   `python3 configure_puf.py --region 4 --debug-capture off`.
   Build/flash, then validate `PUF_REPRODUCTION,PASS`.

## Required validation before attestation

1. Repeat captures after complete power removal (not only EN/reset).
2. Repeat under temperature and supply-voltage variation.
3. Measure inter-device Hamming distance on at least three ESP32 devices.
4. Re-enroll every device separately; helper data is device-specific.
