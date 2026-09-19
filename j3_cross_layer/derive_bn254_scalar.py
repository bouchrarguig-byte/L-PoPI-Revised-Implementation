#!/usr/bin/env python3

import hashlib
import hmac
import json
from pathlib import Path

# BN254 scalar field used by Circom/snarkjs.
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Frozen experimentally reproduced FE key.
FE_KEY = bytes.fromhex(
    "4dbf7ac35ec536844b7324ada3a37e6d"
    "701e5f9d6da53e33c100322d70a01f60"
)

DOMAIN = b"L-POPI/ZK/BN254-SCALAR/v1"

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1

    while len(out) < length:
        t = hmac.new(
            prk,
            t + info + bytes([counter]),
            hashlib.sha256
        ).digest()
        out += t
        counter += 1

    return out[:length]

def derive_scalar(fe_key: bytes):
    # Fixed public salt: domain separation, not secrecy.
    salt = hashlib.sha256(DOMAIN + b"/salt").digest()
    prk = hkdf_extract(salt, fe_key)

    counter = 0

    while True:
        info = DOMAIN + b"/candidate/" + counter.to_bytes(4, "big")
        candidate_bytes = hkdf_expand(prk, info, 32)
        candidate = int.from_bytes(candidate_bytes, "big")

        # Rejection sampling:
        # accept only non-zero values inside the BN254 scalar field.
        if 0 < candidate < R:
            return {
                "counter": counter,
                "candidate_hex": candidate_bytes.hex(),
                "scalar_decimal": str(candidate),
                "scalar_hex": hex(candidate),
            }

        counter += 1

        if counter > 1000000:
            raise RuntimeError("rejection sampling failed unexpectedly")

result = derive_scalar(FE_KEY)

artifact = {
    "scheme": "lpofi-fe-key-to-bn254-fr-v1",
    "domain_ascii": DOMAIN.decode(),
    "bn254_scalar_field_r": str(R),
    "fe_key_sha256": hashlib.sha256(FE_KEY).hexdigest(),
    "fe_key_bytes": len(FE_KEY),
    **result,
}

out = Path("j3_cross_layer/fe_to_bn254_vector.json")
out.write_text(json.dumps(artifact, indent=2) + "\n")

print("scheme:", artifact["scheme"])
print("FE key SHA256:", artifact["fe_key_sha256"])
print("counter:", artifact["counter"])
print("candidate:", artifact["candidate_hex"])
print("scalar decimal:", artifact["scalar_decimal"])
print("scalar < r:", int(artifact["scalar_decimal"]) < R)
print("scalar != 0:", int(artifact["scalar_decimal"]) != 0)
print("output:", out)
print("J3_FE_TO_BN254_VECTOR_OK")
