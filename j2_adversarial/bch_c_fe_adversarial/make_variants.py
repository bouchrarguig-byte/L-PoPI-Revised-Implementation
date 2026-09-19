#!/usr/bin/env python3
from pathlib import Path
import re
import hashlib

SRC = Path("main/puf_enrollment_bch_c_region1.h")
OUT = Path("j2_adversarial/bch_c_fe_adversarial")
text = SRC.read_text()

def sha256(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def parse_array(src, name):
    pat = rf'(static const uint8_t {re.escape(name)}\[\d+\] = \{{)(.*?)(\}};)'
    m = re.search(pat, src, re.S)
    if not m:
        raise RuntimeError(f"array not found: {name}")
    vals = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(2))]
    return m, vals

def replace_array(src, name, vals):
    m, _ = parse_array(src, name)
    body = "\n"
    for i in range(0, len(vals), 12):
        body += "    " + ", ".join(f"0x{x:02x}" for x in vals[i:i+12]) + ",\n"
    return src[:m.start()] + m.group(1) + body + m.group(3) + src[m.end():]

def flip_helper_bits(src, positions):
    _, vals = parse_array(src, "lpofi_bch_puf_helper_bytes")
    for pos in positions:
        if not 0 <= pos < 272:
            raise ValueError(pos)
        vals[pos // 8] ^= 1 << (7 - (pos % 8))
    return replace_array(src, "lpofi_bch_puf_helper_bytes", vals)

variants = {}

# Baseline: byte-for-byte enrollment.
variants["baseline"] = text

# Eight deterministic helper-bit flips.
# Well inside BCH t=16 relative to the enrolled codeword.
variants["helper_8"] = flip_helper_bits(
    text, [0, 17, 34, 51, 68, 85, 130, 200]
)

# Frozen deterministic 17-bit pattern.
# >t. Outcome is empirical; do NOT assume decoder failure.
variants["helper_17"] = flip_helper_bits(
    text, list(range(0, 257, 16))
)

# Salt tamper: flip MSB of first salt byte.
_, salt = parse_array(text, "lpofi_bch_puf_hkdf_salt")
salt[0] ^= 0x80
variants["salt_1bit"] = replace_array(
    text, "lpofi_bch_puf_hkdf_salt", salt
)

# Commitment tamper: flip MSB of first commitment byte.
_, commitment = parse_array(text, "lpofi_bch_puf_key_commitment")
commitment[0] ^= 0x80
variants["commitment_1bit"] = replace_array(
    text, "lpofi_bch_puf_key_commitment", commitment
)

for name, data in variants.items():
    p = OUT / f"puf_enrollment_{name}.h"
    p.write_text(data)
    print(f"{name:16s} {sha256(p)}  {p}")

print("BCH_C_ADVERSARIAL_VARIANTS_OK")
