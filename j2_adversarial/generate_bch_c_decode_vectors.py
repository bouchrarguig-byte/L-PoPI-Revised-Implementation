import bchlib
import json

BCH = bchlib.BCH(16, m=9)

DATA = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
)

ECC = bytes(BCH.encode(bytearray(DATA)))
PACKET = DATA + ECC

# MSB-first packet bit numbering, identical to J2 offline.
patterns = {
    "clean": [],
    "one_data_bit": [0],
    "one_ecc_bit": [128],
    "eight_spread": [
        0, 17, 34, 51, 68, 85, 130, 200
    ],
    "sixteen_spread": [
        0, 17, 34, 51, 68, 85, 102, 119,
        136, 153, 170, 187, 204, 221, 238, 255
    ],
    "seventeen_spread": [
        0, 16, 32, 48, 64, 80, 96, 112, 128,
        144, 160, 176, 192, 208, 224, 240, 256
    ],
}

results = []

for name, flips in patterns.items():
    corrupted = bytearray(PACKET)

    for bit in flips:
        corrupted[bit // 8] ^= 1 << (7 - (bit % 8))

    data = bytearray(corrupted[:16])
    ecc = bytearray(corrupted[16:])

    nerr = BCH.decode(data, ecc)

    if nerr >= 0:
        BCH.correct(data, ecc)

    result = {
        "name": name,
        "flips_msb_first": flips,
        "corrupted_packet": corrupted.hex(),
        "decoder_return": nerr,
        "corrected_data": data.hex(),
        "secret_match": bytes(data) == DATA,
    }

    results.append(result)

    print(
        f"{name:18s} "
        f"flips={len(flips):2d} "
        f"decoder={nerr:3d} "
        f"match={bytes(data) == DATA}"
    )

with open(
    "j2_adversarial/bch_c_decode_vectors.json", "w"
) as f:
    json.dump(results, f, indent=2)
    f.write("\n")
