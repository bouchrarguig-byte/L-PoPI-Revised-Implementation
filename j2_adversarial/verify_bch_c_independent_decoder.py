import json

M = 9
N = 511
T = 16
PRIM = 0x211

DATA_BYTES = 16
ECC_BYTES = 18
PACKET_BYTES = 34
PACKET_BITS = 272

# ------------------------------------------------------------
# GF(2^9), primitive polynomial x^9 + x^4 + 1 = 0x211
# ------------------------------------------------------------

alpha_to = [0] * N
index_of = [-1] * (N + 1)

x = 1
for i in range(N):
    alpha_to[i] = x
    index_of[x] = i

    x <<= 1
    if x & (1 << M):
        x ^= PRIM
    x &= N

assert x == 1


def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return alpha_to[(index_of[a] + index_of[b]) % N]


def gf_div(a, b):
    if b == 0:
        raise ZeroDivisionError
    if a == 0:
        return 0
    return alpha_to[(index_of[a] - index_of[b]) % N]


# ------------------------------------------------------------
# Shortened systematic code
#
# Full BCH length = 511.
# Our shortened packet contains 272 transmitted bits.
#
# bchlib convention established by the encoder:
# packet bit 0 is the MSB of byte 0.
#
# For syndrome evaluation, transmitted packet bit i corresponds
# to polynomial degree:
#
#     271 - i
#
# The omitted high-order shortened positions are zero.
# ------------------------------------------------------------

def packet_bits(packet):
    assert len(packet) == PACKET_BYTES

    for i in range(PACKET_BITS):
        yield (
            packet[i // 8] >>
            (7 - (i % 8))
        ) & 1


def syndromes(packet):
    bits = list(packet_bits(packet))

    S = [0] * (2 * T + 1)

    for j in range(1, 2 * T + 1):
        s = 0

        for i, bit in enumerate(bits):
            if bit:
                degree = PACKET_BITS - 1 - i
                s ^= alpha_to[(j * degree) % N]

        S[j] = s

    return S


# ------------------------------------------------------------
# Berlekamp-Massey
#
# Lambda(x) = 1 + lambda_1 x + ... + lambda_L x^L
# ------------------------------------------------------------

def berlekamp_massey(S):
    C = [0] * (2 * T + 1)
    B = [0] * (2 * T + 1)

    C[0] = 1
    B[0] = 1

    L = 0
    m = 1
    b = 1

    for n in range(0, 2 * T):
        d = S[n + 1]

        for i in range(1, L + 1):
            if C[i] and S[n + 1 - i]:
                d ^= gf_mul(
                    C[i],
                    S[n + 1 - i]
                )

        if d == 0:
            m += 1
            continue

        Tcopy = C[:]

        coef = gf_div(d, b)

        for i in range(0, 2 * T + 1 - m):
            if B[i]:
                C[i + m] ^= gf_mul(coef, B[i])

        if 2 * L <= n:
            L = n + 1 - L
            B = Tcopy
            b = d
            m = 1
        else:
            m += 1

    return C, L


# ------------------------------------------------------------
# Chien search over the 272 transmitted positions only.
#
# Error at polynomial degree d gives locator root alpha^(-d).
# ------------------------------------------------------------

def chien_search(locator, L):
    positions = []

    for packet_pos in range(PACKET_BITS):
        degree = PACKET_BITS - 1 - packet_pos

        x = alpha_to[(-degree) % N]

        value = locator[0]
        power = 1

        for i in range(1, L + 1):
            power = gf_mul(power, x)

            if locator[i]:
                value ^= gf_mul(locator[i], power)

        if value == 0:
            positions.append(packet_pos)

    return positions


def flip_packet_bit(packet, pos):
    packet[pos // 8] ^= 1 << (7 - (pos % 8))


def decode(packet):
    packet = bytearray(packet)

    S = syndromes(packet)

    if all(v == 0 for v in S[1:]):
        return 0, packet

    locator, L = berlekamp_massey(S)

    if L == 0 or L > T:
        return -1, packet

    positions = chien_search(locator, L)

    if len(positions) != L:
        return -1, packet

    for pos in positions:
        flip_packet_bit(packet, pos)

    # Authoritative algebraic post-check.
    S2 = syndromes(packet)

    if not all(v == 0 for v in S2[1:]):
        return -1, packet

    return len(positions), packet


# ------------------------------------------------------------
# Load frozen deterministic decode vectors
# ------------------------------------------------------------

GOLDEN_PACKET = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "553bd00d2cf1fa8bb202207f53f62e81915c"
)

with open(
    "j2_adversarial/bch_c_decode_vectors.json"
) as f:
    ref = json.load(f)

assert isinstance(ref, list)
assert len(ref) == 6

print("BCH-C independent decoder")
print(f"m={M} t={T} n={N} prim=0x{PRIM:x}")
print()

passed = 0

for v in ref:
    name = v["name"]

    corrupted = bytes.fromhex(v["corrupted_packet"])

    expected_nerr = v["decoder_return"]
    expected_secret_match = v["secret_match"]

    actual_nerr, corrected = decode(corrupted)

    secret_match = (
        corrected[:DATA_BYTES] ==
        GOLDEN_PACKET[:DATA_BYTES]
    )

    packet_match = corrected == GOLDEN_PACKET

    if expected_nerr >= 0:
        # Strong criterion for all correctable vectors:
        # exact decoder count + exact complete codeword recovery.
        ok = (
            actual_nerr == expected_nerr
            and expected_secret_match is True
            and secret_match
            and packet_match
        )
    else:
        # Frozen 17-error vector:
        # require this independent decoder to declare failure
        # and not recover the golden secret.
        ok = (
            actual_nerr == -1
            and expected_secret_match is False
            and not secret_match
        )

    print(
        f"{name:18s} "
        f"expected={expected_nerr:3d} "
        f"actual={actual_nerr:3d} "
        f"secret_match={str(secret_match):5s} "
        f"packet_match={str(packet_match):5s} "
        f"{'PASS' if ok else 'FAIL'}"
    )

    if not ok:
        print("  flips     =", v["flips_msb_first"])
        print("  corrupted =", corrupted.hex())
        print("  corrected =", corrected.hex())

    if ok:
        passed += 1

print()
print(f"RESULT {passed}/{len(ref)}")

if passed != len(ref):
    raise SystemExit(1)

print("BCH_C_INDEPENDENT_DECODER_OK")

