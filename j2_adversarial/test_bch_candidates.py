import os
import bchlib

SECRET_BYTES = 16

CANDIDATES = [
    ("BCH-A", 8, 8),
    ("BCH-B", 8, 12),
    ("BCH-C", 9, 16),
]

secret = bytearray(os.urandom(SECRET_BYTES))

print("=" * 72)
print("L-PoPI BCH candidate sanity check")
print("=" * 72)

for name, m, t in CANDIDATES:
    bch = bchlib.BCH(t, m=m)

    data = bytearray(secret)
    ecc = bytearray(bch.encode(data))

    packet = data + ecc

    print()
    print(name)
    print(f"  m              : {m}")
    print(f"  t              : {t}")
    print(f"  n              : {bch.n}")
    print(f"  ecc_bits       : {bch.ecc_bits}")
    print(f"  ecc_bytes      : {bch.ecc_bytes}")
    print(f"  secret bytes   : {len(data)}")
    print(f"  packet bytes   : {len(packet)}")
    print(f"  packet bits    : {len(packet) * 8}")

    # No-error decode
    data_test = bytearray(data)
    ecc_test = bytearray(ecc)

    nerr = bch.decode(data_test, ecc_test)

    if nerr >= 0:
        bch.correct(data_test, ecc_test)

    ok = (data_test == secret)

    print(f"  clean decode   : {'PASS' if ok else 'FAIL'}")
    print(f"  decode result  : {nerr}")
