#!/usr/bin/env python3
"""Reproduce the L-PoPI D0-D5 SRAM-PUF multi-device analysis.

Inputs:
  raw/D0 ... raw/D5, each containing puf_results/capture_001.txt ... capture_030.txt

Protocol:
  - enrollment: captures 001-020
  - held-out:   captures 021-030
  - 2048-bit Region 1 at 0x3FFF2000 (256 bytes)
  - enrollment template: per-bit majority vote; exact 10/10 ties use capture 001
  - per-device BCH mask: 272 highest enrollment-stability positions; ties by bit index
  - common-mask stress test: first 272 positions perfect (20/20) in all six devices
  - BCH-C: m=9, t=16, n=511, shortened 272-bit packet = 128 data + 144 ECC

Only Python standard-library modules are required.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import itertools
import json
import math
import statistics
from pathlib import Path

DEVICES = ["D0", "D1", "D2", "D3", "D4", "D5"]
REVISIONS = {"D0": "v3.0", "D1": "v3.1", "D2": "v3.1", "D3": "v3.1", "D4": "v3.1", "D5": "v3.1"}
ENROLL = range(1, 21)
HELDOUT = range(21, 31)
REGION_BITS = 2048
SELECTED_BITS = 272

# BCH-C parameters frozen in firmware.
BCH_M = 9
BCH_T = 16
BCH_N = 511
BCH_PRIM_POLY = 0x211
BCH_DATA_BYTES = 16
BCH_ECC_BITS = 144
BCH_ECC_BYTES = 18
BCH_PACKET_BYTES = 34
BCH_SYNDROMES = 2 * BCH_T
BCH_MAX_POLY = 2 * BCH_T + 1
GENERATOR_HEX = "12b6bd0545db34c1e01d5296e58c8ed2701ad"
GENERATOR_INT = int(GENERATOR_HEX, 16)
BENCHMARK_SECRET = bytes.fromhex("00112233445566778899aabbccddeeff")
HKDF_INFO = b"L-POPI/ESP32/SRAM-PUF/v1"
COMMIT_INFO = b"L-POPI/ESP32/SRAM-PUF/key-commit/v1"


def bits_from_bytes(raw: bytes) -> list[int]:
    return [(byte >> bit) & 1 for byte in raw for bit in range(7, -1, -1)]


def bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("bit length must be byte aligned")
    out = bytearray(len(bits) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (7 - (i % 8))
    return bytes(out)


def read_capture(path: Path) -> list[int]:
    lines = [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    if len(lines) < 4 or not lines[2].startswith("REGION,1,0x3FFF2000,256"):
        raise ValueError(f"Unexpected capture format: {path}")
    raw = bytes.fromhex(lines[3])
    if len(raw) != 256:
        raise ValueError(f"Expected 256 bytes in {path}, got {len(raw)}")
    return bits_from_bytes(raw)


def hamming(a: list[int], b: list[int]) -> int:
    return sum(x != y for x, y in zip(a, b))


def template_from_enrollment(samples: list[list[int]]) -> tuple[list[int], list[float], int]:
    n = len(samples)
    ones = [sum(s[i] for s in samples) for i in range(REGION_BITS)]
    ties = 0
    template = []
    stability = []
    for i, c in enumerate(ones):
        stability.append(max(c, n - c) / n)
        if 2 * c > n:
            template.append(1)
        elif 2 * c < n:
            template.append(0)
        else:
            ties += 1
            template.append(samples[0][i])
    return template, stability, ties


def stable_indexes(stability: list[float], count: int = SELECTED_BITS) -> list[int]:
    return sorted(sorted(range(REGION_BITS), key=lambda i: (-stability[i], i))[:count])


def sample_sd(values: list[float]) -> float:
    return statistics.stdev(values) if len(values) >= 2 else 0.0


# -------- BCH-C encoder / decoder: Python reproduction of firmware logic --------

def generator_bit(i: int) -> int:
    # generator bit 0 is coefficient of x^144; bit 144 is coefficient of x^0.
    return (GENERATOR_INT >> (BCH_ECC_BITS - i)) & 1


def bch_encode(data: bytes) -> bytes:
    if len(data) != BCH_DATA_BYTES:
        raise ValueError("BCH data must be 16 bytes")
    work = bits_from_bytes(data) + [0] * BCH_ECC_BITS
    for i in range(BCH_DATA_BYTES * 8):
        if work[i] == 0:
            continue
        for j in range(BCH_ECC_BITS + 1):
            work[i + j] ^= generator_bit(j)
    if any(work[: BCH_DATA_BYTES * 8]):
        raise RuntimeError("BCH division invariant failed")
    return bits_to_bytes(work[BCH_DATA_BYTES * 8 :])


ALPHA_TO = [0] * BCH_N
INDEX_OF = [-1] * (BCH_N + 1)

def gf_init() -> None:
    x = 1
    for i in range(BCH_N):
        ALPHA_TO[i] = x
        INDEX_OF[x] = i
        x <<= 1
        if x & (1 << BCH_M):
            x ^= BCH_PRIM_POLY
        x &= BCH_N
    if x != 1:
        raise RuntimeError("GF initialization failed")

gf_init()


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return ALPHA_TO[(INDEX_OF[a] + INDEX_OF[b]) % BCH_N]


def gf_div(a: int, b: int) -> int:
    if b == 0:
        return 0
    if a == 0:
        return 0
    e = (INDEX_OF[a] - INDEX_OF[b]) % BCH_N
    return ALPHA_TO[e]


def packet_bit(packet: bytearray | bytes, bit: int) -> int:
    return (packet[bit // 8] >> (7 - (bit % 8))) & 1


def flip_packet_bit(packet: bytearray, bit: int) -> None:
    packet[bit // 8] ^= 1 << (7 - (bit % 8))


def compute_syndromes(packet: bytes | bytearray) -> list[int]:
    S = [0] * (BCH_SYNDROMES + 1)
    for j in range(1, BCH_SYNDROMES + 1):
        syndrome = 0
        for pos in range(BCH_PACKET_BYTES * 8):
            if not packet_bit(packet, pos):
                continue
            degree = BCH_PACKET_BYTES * 8 - 1 - pos
            exponent = (j * degree) % BCH_N
            syndrome ^= ALPHA_TO[exponent]
        S[j] = syndrome
    return S


def syndromes_zero(S: list[int]) -> bool:
    return all(x == 0 for x in S[1:])


def berlekamp_massey(S: list[int]) -> tuple[list[int], int]:
    locator = [0] * BCH_MAX_POLY
    B = [0] * BCH_MAX_POLY
    locator[0] = 1
    B[0] = 1
    L = 0
    m = 1
    b = 1
    for n in range(BCH_SYNDROMES):
        d = S[n + 1]
        for i in range(1, L + 1):
            if locator[i] and S[n + 1 - i]:
                d ^= gf_mul(locator[i], S[n + 1 - i])
        if d == 0:
            m += 1
            continue
        old_locator = locator[:]
        coef = gf_div(d, b)
        for i in range(BCH_MAX_POLY - m):
            if B[i]:
                locator[i + m] ^= gf_mul(coef, B[i])
        if 2 * L <= n:
            L = n + 1 - L
            B = old_locator
            b = d
            m = 1
        else:
            m += 1
    return locator, L


def chien_search(locator: list[int], L: int) -> list[int] | None:
    positions: list[int] = []
    for packet_pos in range(BCH_PACKET_BYTES * 8):
        degree = BCH_PACKET_BYTES * 8 - 1 - packet_pos
        exp = (BCH_N - (degree % BCH_N)) % BCH_N
        x = ALPHA_TO[exp]
        value = locator[0]
        power = 1
        for i in range(1, L + 1):
            power = gf_mul(power, x)
            if locator[i]:
                value ^= gf_mul(locator[i], power)
        if value == 0:
            if len(positions) >= BCH_T:
                return None
            positions.append(packet_pos)
    return positions


def bch_decode(packet_in: bytes) -> tuple[int, bytes]:
    packet = bytearray(packet_in)
    S = compute_syndromes(packet)
    if syndromes_zero(S):
        return 0, bytes(packet)
    locator, L = berlekamp_massey(S)
    if L <= 0 or L > BCH_T:
        return -1, bytes(packet)
    positions = chien_search(locator, L)
    if positions is None or len(positions) != L:
        return -1, bytes(packet)
    for p in positions:
        flip_packet_bit(packet, p)
    if not syndromes_zero(compute_syndromes(packet)):
        return -1, bytes(packet)
    return len(positions), bytes(packet)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = bytearray()
    prev = b""
    counter = 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        out.extend(prev)
        counter += 1
    return bytes(out[:length])


def bch_selftest() -> None:
    expected = {
        bytes(16): bytes(18),
        bytes.fromhex("ff" * 16): bytes.fromhex("42ccf4450f0ff432e2cc165010b1e452a234"),
        bytes(range(16)): bytes.fromhex("c4c67b8286cd8601c7df5bc1b1fa01ffd4fd"),
        bytes.fromhex("00112233445566778899aabbccddeeff"): bytes.fromhex("553bd00d2cf1fa8bb202207f53f62e81915c"),
        bytes.fromhex("80" + "00" * 15): bytes.fromhex("e3aa8e6788880e2b93aa1d7818e9167bf32e"),
        bytes.fromhex("00" * 15 + "01"): bytes.fromhex("2b6bd0545db34c1e01d5296e58c8ed2701ad"),
    }
    for data, ecc in expected.items():
        assert bch_encode(data) == ecc
    golden = BENCHMARK_SECRET + bch_encode(BENCHMARK_SECRET)
    tests = [([], 0), ([0], 1), ([128], 1), ([0,17,34,51,68,85,130,200], 8),
             ([0,17,34,51,68,85,102,119,136,153,170,187,204,221,238,255], 16)]
    for flips, expected_n in tests:
        p = bytearray(golden)
        for f in flips:
            flip_packet_bit(p, f)
        n, decoded = bch_decode(bytes(p))
        assert n == expected_n and decoded == golden
    p = bytearray(golden)
    for f in [0,16,32,48,64,80,96,112,128,144,160,176,192,208,224,240,256]:
        flip_packet_bit(p, f)
    n, _ = bch_decode(bytes(p))
    assert n == -1


def fe_replay(sample: list[int], reference: list[int], indexes: list[int], device_label: str) -> tuple[bool, int, bool]:
    codeword = BENCHMARK_SECRET + bch_encode(BENCHMARK_SECRET)
    code_bits = bits_from_bytes(codeword)
    ref_bits = [reference[i] for i in indexes]
    helper = [r ^ c for r, c in zip(ref_bits, code_bits)]
    noisy_bits = [sample[i] ^ h for i, h in zip(indexes, helper)]
    nerr, corrected = bch_decode(bits_to_bytes(noisy_bits))
    if nerr < 0:
        return False, -1, False
    code_ok = corrected == codeword
    # Reproduce the firmware's HKDF + key commitment stage using a deterministic public replay salt.
    salt = hashlib.sha256(("L-POPI/multidevice-replay/" + device_label).encode()).digest()
    enrolled_key = hkdf_sha256(BENCHMARK_SECRET, salt, HKDF_INFO, 32)
    commitment = hashlib.sha256(COMMIT_INFO + enrolled_key).digest()
    recovered_secret = corrected[:BCH_DATA_BYTES]
    recovered_key = hkdf_sha256(recovered_secret, salt, HKDF_INFO, 32)
    commitment_ok = hashlib.sha256(COMMIT_INFO + recovered_key).digest() == commitment
    return code_ok and commitment_ok, nerr, commitment_ok


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    here = Path(__file__).resolve().parent
    root = here.parent
    raw_root = root / "raw"
    out = root / "results" / "reproduced"
    out.mkdir(parents=True, exist_ok=True)

    bch_selftest()

    captures: dict[str, dict[int, list[int]]] = {}
    templates: dict[str, list[int]] = {}
    stabilities: dict[str, list[float]] = {}
    selected: dict[str, list[int]] = {}
    device_rows: list[dict] = []
    heldout_rows: list[dict] = []
    fe_rows: list[dict] = []

    for dev in DEVICES:
        files = sorted((raw_root / dev / "puf_results").glob("capture_*.txt"))
        if len(files) != 30:
            raise RuntimeError(f"{dev}: expected 30 captures, found {len(files)}")
        cap = {i: read_capture(raw_root / dev / "puf_results" / f"capture_{i:03d}.txt") for i in range(1,31)}
        captures[dev] = cap
        all_samples = [cap[i] for i in range(1,31)]
        enroll_samples = [cap[i] for i in ENROLL]
        template, stability, ties = template_from_enrollment(enroll_samples)
        templates[dev] = template
        stabilities[dev] = stability
        indexes = stable_indexes(stability)
        selected[dev] = indexes

        all_ones = [sum(s[j] for s in all_samples) for j in range(REGION_BITS)]
        all_reliability = statistics.mean(max(c/30, 1-c/30) for c in all_ones) * 100
        uniformity = sum(template)/REGION_BITS*100
        perfect = sum(x == 1.0 for x in stability)
        heldout_bers = []
        fe_errors = []
        fe_success = 0
        for i in HELDOUT:
            hd = hamming(cap[i], template)
            ber = hd/REGION_BITS*100
            heldout_bers.append(ber)
            heldout_rows.append({"device":dev,"capture":i,"hd_bits":hd,"ber_percent":f"{ber:.6f}"})
            ok, nerr, commitment_ok = fe_replay(cap[i], template, indexes, dev)
            fe_errors.append(nerr)
            fe_success += int(ok)
            fe_rows.append({"device":dev,"capture":i,"selected_bits":SELECTED_BITS,"corrected_errors":nerr,
                            "decoder_capacity_t":BCH_T,"commitment_pass":str(commitment_ok).lower(),"fe_pass":str(ok).lower()})
        # Acquisition retry count is explicit in the collector log and is not a PUF error event.
        log_text = (raw_root/dev/"collection.log").read_text(encoding="utf-8", errors="replace")
        retries = log_text.count("FAILED ATTEMPT NOT COUNTED")
        device_rows.append({
            "device":dev,"revision":REVISIONS[dev],"captures":30,"acquisition_retries_not_counted":retries,
            "all_capture_reliability_percent":f"{all_reliability:.4f}","template_uniformity_percent":f"{uniformity:.4f}",
            "heldout_raw_ber_mean_percent":f"{statistics.mean(heldout_bers):.4f}",
            "heldout_raw_ber_min_percent":f"{min(heldout_bers):.4f}","heldout_raw_ber_max_percent":f"{max(heldout_bers):.4f}",
            "perfect_stable_cells_20_of_20":perfect,"enrollment_template_ties":ties,
            "bch_error_mean":f"{statistics.mean(fe_errors):.4f}","bch_error_max":max(fe_errors),"fe_heldout_pass":f"{fe_success}/10"
        })

    # Inter-device uniqueness.
    pair_rows=[]
    for a,b in itertools.combinations(DEVICES,2):
        hd=hamming(templates[a],templates[b]); pct=hd/REGION_BITS*100
        pair_rows.append({"device_a":a,"device_b":b,"hd_bits":hd,"normalized_hd_percent":f"{pct:.6f}"})
    primary_vals=[float(r["normalized_hd_percent"]) for r in pair_rows if r["device_a"]!="D0" and r["device_b"]!="D0"]
    extended_vals=[float(r["normalized_hd_percent"]) for r in pair_rows]

    # Bit aliasing across six enrollment templates.
    alias_counts=[sum(templates[d][i] for d in DEVICES) for i in range(REGION_BITS)]
    alias_pct=[x/len(DEVICES)*100 for x in alias_counts]
    alias_summary={
        "devices":6,
        "mean_bit_aliasing_percent":statistics.mean(alias_pct),
        "exactly_50_percent_positions":sum(x==3 for x in alias_counts),
        "exactly_50_percent_fraction":sum(x==3 for x in alias_counts)/REGION_BITS,
        "positions_33_33_to_66_67_inclusive":sum(2<=x<=4 for x in alias_counts),
        "positions_33_33_to_66_67_fraction":sum(2<=x<=4 for x in alias_counts)/REGION_BITS,
        "all_zero_positions":sum(x==0 for x in alias_counts),
        "all_one_positions":sum(x==6 for x in alias_counts),
        "count_histogram":{str(k):alias_counts.count(k) for k in range(7)}
    }

    # Common-mask stress test: positions perfect in every device enrollment set.
    common=[i for i in range(REGION_BITS) if all(stabilities[d][i]==1.0 for d in DEVICES)]
    common_mask=common[:SELECTED_BITS]
    common_rows=[]
    common_success=0
    common_max=-1
    for dev in DEVICES:
        for i in HELDOUT:
            ok,nerr,commitment_ok=fe_replay(captures[dev][i],templates[dev],common_mask,dev+"/common")
            common_success += int(ok); common_max=max(common_max,nerr)
            common_rows.append({"device":dev,"capture":i,"corrected_errors":nerr,"fe_pass":str(ok).lower()})

    # Aggregate summary.
    dev_rel=[float(r["all_capture_reliability_percent"]) for r in device_rows]
    dev_uni=[float(r["template_uniformity_percent"]) for r in device_rows]
    dev_ber=[float(r["heldout_raw_ber_mean_percent"]) for r in device_rows]
    all_heldout=[float(r["ber_percent"]) for r in heldout_rows]
    summary={
        "protocol":{"devices":6,"valid_captures":180,"enrollment":"001-020","heldout":"021-030","region_bits":2048,
                    "selected_bch_bits":272,"firmware_commit":"8670f38"},
        "six_device_means":{
            "reliability_percent_mean":statistics.mean(dev_rel),"reliability_percent_sample_sd":sample_sd(dev_rel),
            "uniformity_percent_mean":statistics.mean(dev_uni),"uniformity_percent_sample_sd":sample_sd(dev_uni),
            "heldout_raw_ber_device_mean_percent":statistics.mean(dev_ber),"heldout_raw_ber_device_mean_sample_sd":sample_sd(dev_ber)
        },
        "uniqueness":{
            "primary_D1_D5":{"N":5,"pairs":10,"mean_percent":statistics.mean(primary_vals),"sample_sd_percent":sample_sd(primary_vals),
                              "min_percent":min(primary_vals),"max_percent":max(primary_vals)},
            "extended_D0_D5":{"N":6,"pairs":15,"mean_percent":statistics.mean(extended_vals),"sample_sd_percent":sample_sd(extended_vals),
                              "min_percent":min(extended_vals),"max_percent":max(extended_vals)}
        },
        "genuine_heldout":{"N":60,"mean_ber_percent":statistics.mean(all_heldout),"sample_sd_percent":sample_sd(all_heldout),
                           "min_percent":min(all_heldout),"max_percent":max(all_heldout)},
        "fuzzy_extractor":{"heldout_passes":sum(r["fe_pass"]=="true" for r in fe_rows),"heldout_total":len(fe_rows),
                           "corrected_error_min":min(int(r["corrected_errors"]) for r in fe_rows),
                           "corrected_error_max":max(int(r["corrected_errors"]) for r in fe_rows),"decoder_t":BCH_T},
        "common_mask":{"perfect_positions_across_all_six":len(common),"mask_size":len(common_mask),"heldout_passes":common_success,
                       "heldout_total":60,"corrected_error_max":common_max},
        "bit_aliasing":alias_summary
    }

    write_csv(out/"device_summary.csv",device_rows,list(device_rows[0].keys()))
    write_csv(out/"inter_device_HD.csv",pair_rows,list(pair_rows[0].keys()))
    write_csv(out/"heldout_BER.csv",heldout_rows,list(heldout_rows[0].keys()))
    write_csv(out/"bch_fe_results.csv",fe_rows,list(fe_rows[0].keys()))
    write_csv(out/"common_mask_bch_results.csv",common_rows,list(common_rows[0].keys()))
    (out/"analysis_summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    (out/"selected_indexes.json").write_text(json.dumps({"per_device":selected,"common_mask":common_mask},indent=2)+"\n",encoding="utf-8")

    # Sanity assertions matching the reported manuscript values.
    assert round(summary["uniqueness"]["primary_D1_D5"]["mean_percent"],4) == 49.2188
    assert round(summary["uniqueness"]["extended_D0_D5"]["mean_percent"],4) == 49.0885
    assert summary["fuzzy_extractor"]["heldout_passes"] == 60
    assert summary["fuzzy_extractor"]["corrected_error_max"] == 4
    assert summary["common_mask"]["perfect_positions_across_all_six"] == 547
    assert summary["common_mask"]["heldout_passes"] == 60

    print("PASS: 180 captures analyzed")
    print(f"Primary D1-D5 uniqueness: {summary['uniqueness']['primary_D1_D5']['mean_percent']:.4f}% (10 pairs)")
    print(f"Extended D0-D5 uniqueness: {summary['uniqueness']['extended_D0_D5']['mean_percent']:.4f}% (15 pairs)")
    print(f"FE held-out: {summary['fuzzy_extractor']['heldout_passes']}/60; max corrected errors={summary['fuzzy_extractor']['corrected_error_max']}/16")
    print(f"Common-mask stress test: {summary['common_mask']['heldout_passes']}/60; perfect common cells={len(common)}")
    print(f"Outputs: {out}")

if __name__ == "__main__":
    main()
