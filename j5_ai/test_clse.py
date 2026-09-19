from pathlib import Path
import csv
import hashlib

OUT = Path("results/clse")
OUT.mkdir(parents=True, exist_ok=True)

# Functional policy thresholds.
# These are illustrative policy thresholds for CLSE logic testing,
# NOT classifier thresholds or measured operating points.
TAU1 = 0.30
TAU2 = 0.70


def clse(zk_valid, freshness_valid, risk):
    """
    Cryptographic/freshness evidence has hard precedence.
    Behavioral risk only refines the decision after those checks pass.
    """

    if not freshness_valid:
        return "REJECT_FRESHNESS"

    if not zk_valid:
        return "REJECT_CRYPTO"

    if risk < TAU1:
        return "ACCEPT"

    if risk < TAU2:
        return "MONITOR"

    return "RESTRICT"


tests = [
    {
        "id": "S1",
        "description": "valid ZK + fresh + benign behavior",
        "zk_valid": True,
        "freshness_valid": True,
        "risk": 0.10,
        "expected": "ACCEPT",
    },
    {
        "id": "S2",
        "description": "invalid ZK + fresh + benign behavior",
        "zk_valid": False,
        "freshness_valid": True,
        "risk": 0.10,
        "expected": "REJECT_CRYPTO",
    },
    {
        "id": "S3",
        "description": "valid ZK + fresh + intermediate risk",
        "zk_valid": True,
        "freshness_valid": True,
        "risk": 0.50,
        "expected": "MONITOR",
    },
    {
        "id": "S4",
        "description": "valid ZK + fresh + suspicious behavior",
        "zk_valid": True,
        "freshness_valid": True,
        "risk": 0.90,
        "expected": "RESTRICT",
    },
    {
        "id": "S5",
        "description": "invalid ZK + suspicious behavior",
        "zk_valid": False,
        "freshness_valid": True,
        "risk": 0.90,
        "expected": "REJECT_CRYPTO",
    },
    {
        "id": "S6",
        "description": "replayed/stale proof + benign behavior",
        "zk_valid": True,
        "freshness_valid": False,
        "risk": 0.10,
        "expected": "REJECT_FRESHNESS",
    },
    {
        "id": "S7",
        "description": "replayed/stale proof + suspicious behavior",
        "zk_valid": True,
        "freshness_valid": False,
        "risk": 0.90,
        "expected": "REJECT_FRESHNESS",
    },
]


rows = []

print("=== CLSE FUNCTIONAL POLICY TEST ===")
print("TAU1 =", TAU1)
print("TAU2 =", TAU2)
print()

for t in tests:
    observed = clse(
        t["zk_valid"],
        t["freshness_valid"],
        t["risk"],
    )

    passed = observed == t["expected"]

    row = {
        **t,
        "observed": observed,
        "pass": passed,
    }

    rows.append(row)

    print(
        f"{t['id']}: "
        f"ZK={int(t['zk_valid'])} "
        f"fresh={int(t['freshness_valid'])} "
        f"risk={t['risk']:.2f} "
        f"-> {observed} "
        f"[{'PASS' if passed else 'FAIL'}]"
    )


csv_path = OUT / "clse_functional_tests.csv"

with csv_path.open("w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=rows[0].keys()
    )
    writer.writeheader()
    writer.writerows(rows)


assert all(r["pass"] for r in rows)

sha = hashlib.sha256(
    csv_path.read_bytes()
).hexdigest()

print()
print(
    f"RESULT: {sum(r['pass'] for r in rows)}/"
    f"{len(rows)} PASS"
)
print("SHA256:", sha)
print("J5_CLSE_FUNCTIONAL_OK")
