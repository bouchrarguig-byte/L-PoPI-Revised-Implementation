import json

GENERATOR = int(
    "12b6bd0545db34c1e01d5296e58c8ed2701ad", 16
)

ECC_BITS = 144
ECC_BYTES = 18


def encode_independent(data: bytes) -> bytes:
    """
    Systematic shortened BCH encoder.

    Interpret data MSB-first as one polynomial bit string.
    Compute remainder of:

        data(x) * x^144 / g(x)

    where deg(g)=144.
    """
    msg = int.from_bytes(data, "big")
    work = msg << ECC_BITS

    while work.bit_length() - 1 >= ECC_BITS:
        shift = (work.bit_length() - 1) - ECC_BITS
        work ^= GENERATOR << shift

    return work.to_bytes(ECC_BYTES, "big")


path = "j2_adversarial/bch_c_conformance_vectors.json"

with open(path) as f:
    reference = json.load(f)

assert reference["m"] == 9
assert reference["t"] == 16
assert reference["n"] == 511
assert reference["prim_poly"] == 0x211
assert reference["ecc_bits"] == 144
assert reference["ecc_bytes"] == 18

passed = 0

for v in reference["vectors"]:
    data = bytes.fromhex(v["data"])
    expected = bytes.fromhex(v["ecc"])
    actual = encode_independent(data)

    ok = actual == expected

    print(f"{v['name']:14s} {'PASS' if ok else 'FAIL'}")
    print("  expected =", expected.hex())
    print("  actual   =", actual.hex())

    if ok:
        passed += 1

print()
print(f"RESULT {passed}/{len(reference['vectors'])}")

if passed != len(reference["vectors"]):
    raise SystemExit(1)

print("BCH_C_INDEPENDENT_ENCODER_OK")
