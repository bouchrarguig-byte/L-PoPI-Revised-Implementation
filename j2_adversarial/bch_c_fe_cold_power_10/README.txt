L-PoPI BCH-C fuzzy-extractor physical cold-power validation

Firmware binary SHA256:
dea116278ae42d51384c06deb3897b26dfd2208fb3d2ea8e421414d7da068edb

ESP-IDF:
v6.1-dev-7562-g85c826ecb1d

Target:
ESP32 rev v3.0
CPU 160 MHz

BCH-C:
m=9
t=16
n=511
ecc_bits=144
secret=128 bits
shortened packet=272 bits

Protocol:
- 10 physical power-off / power-on trials
- approximately 10 s unpowered between trials
- no reflashing between trials
- same frozen enrollment/helper
- record decoder_errors, commitment result, and PUF_REPRODUCTION
