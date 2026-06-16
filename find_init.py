#!/usr/bin/env python3
"""
Correct GF(2) Gaussian elimination to find CRC32 init value.
Also: exhaustive scan of checksum computation functions.
"""
import struct, zlib, capstone

ORIG  = r"C:\EDC17\EDC17CP42_418085070BC018597408001011180100_FLASH_20260429102606_original.bin"
TARGET    = 0x6F3A9EAB
TARGET_CH = 0xDD8395D7
MCU   = 0x80000000

with open(ORIG, "rb") as f:
    raw = bytearray(f.read())

crc_tbl = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ 0xEDB88320 if (c & 1) else (c >> 1)
    crc_tbl.append(c)

def crc32(buf, init=0xFFFFFFFF, xorout=0xFFFFFFFF):
    crc = init
    for b in buf:
        crc = crc_tbl[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (crc ^ xorout) & 0xFFFFFFFF

# ===================================================================
# 1. Correct GF(2) system solver
#    Solve: sum_j(x_j * col_j) = target  (XOR, GF(2))
#    where col_j = basis[j], x = bits of init value I
# ===================================================================
def gf2_solve(cols, target):
    """Solve M*x=target over GF(2). cols[j] = j-th column (32-bit int)."""
    n = 32
    # Augmented matrix: rows[i] = row i of [M | target]
    # bits 0..31 of rows[i] = M[i][0..31], bit 32 = target[i]
    rows = []
    for i in range(n):
        row = 0
        for j in range(n):
            row |= (((cols[j] >> i) & 1) << j)
        row |= (((target >> i) & 1) << n)
        rows.append(row)

    # Forward elimination
    pivot_col_for_row = [-1] * n
    col_cursor = 0
    for r in range(n):
        # Find a row r' >= r with bit col_cursor set
        found = -1
        while col_cursor < n and found == -1:
            for r2 in range(r, n):
                if (rows[r2] >> col_cursor) & 1:
                    found = r2
                    break
            if found == -1:
                col_cursor += 1
        if found == -1:
            break
        # Swap
        rows[r], rows[found] = rows[found], rows[r]
        pivot_col_for_row[r] = col_cursor
        # Eliminate
        for r2 in range(n):
            if r2 != r and (rows[r2] >> col_cursor) & 1:
                rows[r2] ^= rows[r]
        col_cursor += 1

    # Back-substitution: extract solution
    x = 0
    for r in range(n):
        pc = pivot_col_for_row[r]
        if pc < 0:
            continue
        x_bit = (rows[r] >> n) & 1
        x |= (x_bit << pc)

    return x

# Test datasets
datasets = [
    # (label, buf, target)
]

# Main cal range [0x300000, 0x3FEFFC) with CS zeroed
buf_z = bytearray(raw[0x300000:0x3FEFFC])
buf_z[0x30:0x34] = b'\x00\x00\x00\x00'
buf_z = bytes(buf_z)

# Code hash range [0x1BFE74, 0x3FEF70)
buf_code = bytes(raw[0x1BFE74:0x3FEF70])

print("=== GF(2) SOLVER: Find CRC32 init value ===")

for (label, buf, tgt) in [
    ("cal_CS_zeroed [0x300000,0x3FEFFC)", buf_z, TARGET),
    ("code_hash [0x1BFE74,0x3FEF70)", buf_code, TARGET_CH),
]:
    n = len(buf)
    print(f"\n  Dataset: {label}, n={n:#x} bytes, target={tgt:#010x}")

    # Compute basis[k] = F^n(2^k)
    F_n_applied = lambda K: (lambda s: [s := crc_tbl[s & 0xFF] ^ (s >> 8) or s
                                        for _ in range(n)] and s)
    # Actually compute properly:
    basis = []
    print(f"  Computing basis (n={n:#x})...")
    for k in range(32):
        Kk = 1 << k
        for _ in range(n):
            Kk = crc_tbl[Kk & 0xFF] ^ (Kk >> 8)
        basis.append(Kk)

    # A(D) = CRC(D, 0, 0)
    A_D = crc32(buf, 0, 0)
    print(f"  CRC(D, 0, 0) = {A_D:#010x}")

    # Need: F^n(I) = tgt ^ 0xFFFFFFFF ^ A_D
    # (since CRC(D,I,0xFFFFFFFF) = F^n(I) ^ A(D) ^ 0xFFFFFFFF = tgt)
    need = (tgt ^ 0xFFFFFFFF) ^ A_D
    print(f"  Need F^n(I)  = {need:#010x}")

    # Solve: sum_k(I_k * basis[k]) = need
    I_val = gf2_solve(basis, need)
    print(f"  GF(2) solution I = {I_val:#010x}")

    # Verify
    c_verify = crc32(buf, I_val, 0xFFFFFFFF)
    print(f"  Verify CRC(D, {I_val:#010x}, 0xFFFFFFFF) = {c_verify:#010x}  {'*** CORRECT ***' if c_verify == tgt else 'WRONG'}")

    if c_verify != tgt:
        # Also try with xorout=0
        for xo in [0, 0xFFFFFFFF]:
            c2 = crc32(buf, I_val, xo)
            if c2 == tgt:
                print(f"  *** FOUND with xorout={xo:#010x}: CRC(D,{I_val:#010x},{xo:#010x}) = {c2:#010x}")

# ===================================================================
# 2. Try OTHER ranges with the same GF(2) solver
# ===================================================================
print("\n=== GF(2) solver for other ranges ===")

other_ranges = [
    ("cal no zero  [0x300000,0x3FEFFC)", bytes(raw[0x300000:0x3FEFFC]), TARGET),
    ("cal CS+CH_z  [0x300000,0x3FEFFC)", None, TARGET),  # special
    ("from 0x300034 [0x300034,0x3FEFFC)", bytes(raw[0x300034:0x3FEFFC]), TARGET),
    ("from 0x300038 [0x300038,0x3FEFFC)", bytes(raw[0x300038:0x3FEFFC]), TARGET),
    ("from 0x300060 [0x300060,0x3FEFFC)", bytes(raw[0x300060:0x3FEFFC]), TARGET),
    ("from 0x300080 [0x300080,0x3FEFFC)", bytes(raw[0x300080:0x3FEFFC]), TARGET),
    ("cal no RSA   [0x300000,0x3FEFC0)", bytes(raw[0x300000:0x3FEFC0]), TARGET),
    # Multi-range: cat code[0x204000,0x214000) + cal[0x300000,0x3FEFFC) CS-zeroed
    ("multi code+cal csz", None, TARGET),   # built below
]

def quick_solve(buf, tgt):
    n = len(buf)
    basis = []
    for k in range(32):
        Kk = 1 << k
        for _ in range(n):
            Kk = crc_tbl[Kk & 0xFF] ^ (Kk >> 8)
        basis.append(Kk)
    A_D = crc32(buf, 0, 0)
    need = (tgt ^ 0xFFFFFFFF) ^ A_D
    I_val = gf2_solve(basis, need)
    c_verify = crc32(buf, I_val, 0xFFFFFFFF)
    return I_val, c_verify

# Build special buffers
buf_z2 = bytearray(raw[0x300000:0x3FEFFC])
buf_z2[0x30:0x34] = b'\x00\x00\x00\x00'  # CS
buf_z2[0x74:0x78] = b'\x00\x00\x00\x00'  # CH
buf_z2 = bytes(buf_z2)

# Multi-range: code[0x204000,0x214000) concatenated with cal (CS zeroed)
cal_csz = bytearray(raw[0x300000:0x3FEFFC])
cal_csz[0x30:0x34] = b'\x00\x00\x00\x00'
buf_multi = bytes(raw[0x204000:0x214000]) + bytes(cal_csz)
buf_multi2 = bytes(cal_csz) + bytes(raw[0x204000:0x214000])  # reversed order

other_ranges.append(("multi cal+code csz", buf_multi2, TARGET))

for (label, buf, tgt) in other_ranges:
    if buf is None:
        if "multi" in label:
            buf = buf_multi
        else:
            buf = buf_z2
            label = "cal CS+CH_z  [0x300000,0x3FEFFC)"
    I_val, c_verify = quick_solve(buf, tgt)
    ok = "*** MATCH ***" if c_verify == tgt else ""
    if ok or I_val == 0xFFFFFFFF:
        print(f"  {label}: I={I_val:#010x} verify={c_verify:#010x} {ok}")
    else:
        print(f"  {label}: I={I_val:#010x}  (verify={c_verify:#010x})")

# ===================================================================
# 3. Also try: what if there is NO INIT at all and the algorithm uses
#    something else? Search for CALLI instructions in the TPROT area
# ===================================================================
print("\n=== Search CALLI (indirect calls) in TPROT area 0x016000-0x018000 ===")
md = capstone.Cs(capstone.CS_ARCH_TRICORE, capstone.CS_MODE_TRICORE_162)
md.detail = True

code_chunk = bytes(raw[0x016000:0x018000])
for ins in md.disasm(code_chunk, MCU + 0x016000):
    if ins.mnemonic in ('calli', 'ji', 'jli'):
        foff = ins.address - MCU
        print(f"  {ins.address:#010x} ({foff:#x}): {ins.mnemonic} {ins.op_str}")

# ===================================================================
# 4. Look for where checksum is compared or written in the TPROT area
#    Search for LD.W / ST.W instructions that could load/store the CS
# ===================================================================
print("\n=== Disassemble broader TPROT function 0x015E00-0x017000 ===")
for off in range(0x015E00, 0x017000, 0x200):
    code = bytes(raw[off:off+0x200])
    n_ins = 0
    for ins in md.disasm(code, MCU + off):
        n_ins += 1
        # Print only memory-related or call instructions
        if any(x in ins.mnemonic for x in ('ld.w', 'st.w', 'call', 'ret', 'movh.a', 'lea', 'eq', 'ne', 'jne', 'jeq')):
            print(f"  {ins.address:#010x}: {ins.mnemonic:<8} {ins.op_str}")
    if n_ins > 0:
        print(f"  --- ({n_ins} insns total in block {off:#x})")

print("\nDone.")
