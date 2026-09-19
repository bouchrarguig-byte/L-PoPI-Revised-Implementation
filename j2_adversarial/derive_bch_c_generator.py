M = 9
N = (1 << M) - 1
PRIM = 0x211
T = 16

# GF(2^m) log/antilog tables.
alpha_to = [0] * (N + 1)
index_of = [-1] * (N + 1)

x = 1
for i in range(N):
    alpha_to[i] = x
    index_of[x] = i

    x <<= 1
    if x & (1 << M):
        x ^= PRIM

    x &= N

alpha_to[N] = 1
index_of[0] = -1


def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return alpha_to[(index_of[a] + index_of[b]) % N]


def cyclotomic_coset(i):
    out = []
    x = i % N

    while x not in out:
        out.append(x)
        x = (x * 2) % N

    return out


# Narrow-sense primitive BCH: roots alpha^1 ... alpha^(2t).
cosets = []
seen = set()

for i in range(1, 2 * T + 1):
    if i in seen:
        continue

    c = cyclotomic_coset(i)
    cosets.append(c)
    seen.update(c)

print("cosets:")
for c in cosets:
    print(c)

# Construct product over GF(2^m):
#     g(x) = product (x + alpha^i)
#
# Result must collapse to GF(2), i.e. coefficients 0 or 1.
poly = [1]

for coset in cosets:
    for root_exp in coset:
        root = alpha_to[root_exp]

        new = [0] * (len(poly) + 1)

        for j, coeff in enumerate(poly):
            # coeff * root
            new[j] ^= gf_mul(coeff, root)

            # coeff * x
            new[j + 1] ^= coeff

        poly = new

bad = [(i, c) for i, c in enumerate(poly) if c not in (0, 1)]

if bad:
    raise RuntimeError(
        "generator did not collapse to GF(2): "
        + repr(bad[:10])
    )

degree = len(poly) - 1

print()
print("generator degree:", degree)
print("expected degree:", 144)

# poly[i] is coefficient of x^i.
g = 0
for i, coeff in enumerate(poly):
    if coeff:
        g |= 1 << i

print("generator hex:", hex(g))
print("generator bits:", bin(g))
print("generator bit length:", g.bit_length())

assert degree == 144
assert g.bit_length() == 145

with open(
    "j2_adversarial/bch_c_generator.txt", "w"
) as f:
    f.write(f"m={M}\n")
    f.write(f"t={T}\n")
    f.write(f"n={N}\n")
    f.write(f"prim_poly=0x{PRIM:x}\n")
    f.write(f"degree={degree}\n")
    f.write(f"generator=0x{g:x}\n")
