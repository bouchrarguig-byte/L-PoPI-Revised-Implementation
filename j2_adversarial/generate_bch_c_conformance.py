import bchlib
import hashlib
import json

BCH = bchlib.BCH(16, m=9)

vectors = [
    ("zero", bytes(16)),
    ("ff", bytes([0xff] * 16)),
    ("incrementing", bytes(range(16))),
    ("golden", bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )),
    ("walking_msb", bytes.fromhex(
        "80000000000000000000000000000000"
    )),
    ("walking_lsb", bytes.fromhex(
        "00000000000000000000000000000001"
    )),
]

out = {
    "implementation": "bchlib==2.1.3",
    "m": BCH.m,
    "t": BCH.t,
    "n": BCH.n,
    "prim_poly": BCH.prim_poly,
    "ecc_bits": BCH.ecc_bits,
    "ecc_bytes": BCH.ecc_bytes,
    "vectors": [],
}

for name, data in vectors:
    ecc = bytes(BCH.encode(bytearray(data)))
    packet = data + ecc

    entry = {
        "name": name,
        "data": data.hex(),
        "ecc": ecc.hex(),
        "packet": packet.hex(),
        "packet_sha256": hashlib.sha256(packet).hexdigest(),
    }

    out["vectors"].append(entry)

    print(name)
    print("  data =", data.hex())
    print("  ecc  =", ecc.hex())
    print("  sha  =", entry["packet_sha256"])

path = "j2_adversarial/bch_c_conformance_vectors.json"

with open(path, "w") as f:
    json.dump(out, f, indent=2)
    f.write("\n")

print("\nwritten:", path)
