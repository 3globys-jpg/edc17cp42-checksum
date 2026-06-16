#!/usr/bin/env python3
"""Test various zero patterns for CRC/sum computation."""
import struct, zlib, capstone

ORIG  = r"C:\EDC17\EDC17CP42_418085070BC018597408001011180100_FLASH_20260429102606_original.bin"
TARGET    = 0x6F3A9EAB
TARGET_CH = 0xDD8395D7
MCU   = 0x80000000

with open(ORIG, "rb") as f:
    raw = bytearray(f.read())

print(f"Cal checksum target: {TARGET:#010x}")
print(f"Code hash target:    {TARGET_CH:#010x}")

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

def s32(buf):
    return sum(struct.unpack_from("<I", buf, i)[0] for i in range(0, len(buf)-3, 4)) & 0xFFFFFFFF

# ===================================================================
# 1. Various ZEROING PATTERNS on full range [0x300000, 0x3FEFFC)
# ===================================================================
print("\n=== ZEROING PATTERN SWEEP [0x300000, 0x3FEFFC) ===")

range_buf = bytearray(raw[0x300000:0x3FEFFC])

zero_patterns = [
    # (description, list of (start_offset_from_range_start, len_bytes))
    ("zero CS only",             [(0x30, 4)]),
    ("zero CH only",             [(0x74, 4)]),
    ("zero CS+CH",               [(0x30, 4), (0x74, 4)]),
    ("zero CS+TPROT",            [(0x30, 4), (0x70, 4)]),
    ("zero CS+TPROT+CH",         [(0x30, 4), (0x70, 4), (0x74, 4)]),
    ("zero header 0-0x7F",       [(0, 0x80)]),
    ("zero header 0-0x3F",       [(0, 0x40)]),
    ("zero header 0x30-0x3F",    [(0x30, 0x10)]),
    ("zero header 0x10-0x2F",    [(0x10, 0x20)]),
    ("CS=0xFF (fill)",           [(0x30, 4)]),  # actually set to 0xFF
    ("zero nothing",             []),
    ("zero byte at 0x30",        [(0x30, 1)]),
    ("CS + entire block0x40-0x80", [(0x30, 4), (0x40, 0x40)]),
]

for desc, zeros in zero_patterns:
    buf = bytearray(range_buf)
    if "0xFF" in desc:
        buf[0x30:0x34] = b'\xFF\xFF\xFF\xFF'
    else:
        for (off, length) in zeros:
            buf[off:off+length] = b'\x00' * length
    buf = bytes(buf)
    c = crc32(buf)
    s = s32(buf)
    ns = (-s) & 0xFFFFFFFF
    xs = 0
    for i in range(0, len(buf)-3, 4): xs ^= struct.unpack_from("<I", buf, i)[0]

    for name, v in [("crc32", c), ("sum32", s), ("neg32", ns), ("xor32", xs)]:
        if v == TARGET:
            print(f"  *** MATCH [{desc}]: {name} = {v:#010x}")

print("  (no matches printed = no match)")

# ===================================================================
# 2. Same sweep but for CODE HASH
# ===================================================================
print("\n=== ZEROING PATTERN SWEEP for CODE HASH [0x1BFE74, 0x3FEF70) ===")
code_buf = bytearray(raw[0x1BFE74:0x3FEF70])
# CS is at 0x300030, offset from 0x1BFE74 = 0x300030 - 0x1BFE74 = 0xE01BC
cs_off_code = 0x300030 - 0x1BFE74
ch_off_code = 0x300074 - 0x1BFE74  # code hash offset
tp_off_code = 0x300070 - 0x1BFE74  # TPROT flag offset

zero_patterns_code = [
    ("zero nothing",     []),
    ("zero CS",          [(cs_off_code, 4)]),
    ("zero CH",          [(ch_off_code, 4)]),
    ("zero CS+CH",       [(cs_off_code, 4), (ch_off_code, 4)]),
    ("zero TPROT",       [(tp_off_code, 4)]),
    ("zero CS+CH+TP",    [(cs_off_code, 4), (ch_off_code, 4), (tp_off_code, 4)]),
    ("zero header0x80",  [(0x300000 - 0x1BFE74, 0x80)]),
]

for desc, zeros in zero_patterns_code:
    buf = bytearray(code_buf)
    for (off, length) in zeros:
        if 0 <= off < len(buf): buf[off:off+length] = b'\x00' * length
    buf = bytes(buf)
    c = crc32(buf)
    s = s32(buf)
    ns = (-s) & 0xFFFFFFFF
    for name, v in [("crc32", c), ("sum32", s), ("neg32", ns)]:
        if v == TARGET_CH:
            print(f"  *** CODE HASH MATCH [{desc}]: {name} = {v:#010x}")

print("  (no matches printed = no match)")

# ===================================================================
# 3. Disassemble checksum-related functions from descriptor tables
# ===================================================================
print("\n=== Disassemble function at 0x02F028 ===")
md = capstone.Cs(capstone.CS_ARCH_TRICORE, capstone.CS_MODE_TRICORE_162)
md.detail = True

def disasm(file_off, nbytes=256, label=""):
    print(f"\n--- {label} @ {file_off:#010x} (MCU {file_off+MCU:#010x}) ---")
    code = bytes(raw[file_off:file_off+nbytes])
    n = 0
    for ins in md.disasm(code, file_off + MCU):
        print(f"  {ins.address:#010x}: {' '.join(f'{b:02X}' for b in ins.bytes):<16} {ins.mnemonic} {ins.op_str}")
        n += 1
    print(f"  ({n} instructions decoded)")

# Try different offsets around 0x02F028
for off in [0x02F000, 0x02F010, 0x02F020, 0x02F028, 0x02F030]:
    disasm(off, 128, f"near 0x02F028 @ {off:#x}")

print("\n=== Disassemble 0x8012B68C ===")
disasm(0x12B68C, 256, "func 0x8012B68C")

print("\n=== Disassemble 0x8012B6D2 ===")
disasm(0x12B6D2, 128, "func 0x8012B6D2")

# ===================================================================
# 4. Deeper: find any function that references the CHECKSUM VALUE
#    0x6F3A9EAB as a literal in code
# ===================================================================
print("\n=== Search for 0x6F3A9EAB literal in code ===")
target_bytes = struct.pack("<I", TARGET)
pos = 0
while True:
    idx = raw.find(target_bytes, pos, 0x300000)
    if idx == -1: break
    print(f"  Found {TARGET:#010x} at code offset {idx:#010x}")
    disasm(max(0, idx-32), 64, f"  context")
    pos = idx + 1

# ===================================================================
# 5. Search for 0xDD8395D7 literal in code
# ===================================================================
print("\n=== Search for 0xDD8395D7 literal in code ===")
ch_bytes = struct.pack("<I", TARGET_CH)
pos = 0
while True:
    idx = raw.find(ch_bytes, pos, 0x300000)
    if idx == -1: break
    print(f"  Found {TARGET_CH:#010x} at code offset {idx:#010x}")
    disasm(max(0, idx-32), 64, f"  context")
    pos = idx + 1

# ===================================================================
# 6. NEW IDEA: Maybe CRC is NOT over the FLASH DATA but over some
#    TRANSFORMED data. Check if there's a non-trivial init that works.
# ===================================================================
print("\n=== CRC32 init sweep (brute force 2^20 values) ===")
# We know: CRC(D, I, 0xFFFFFFFF) = TARGET
# = CRC(D, I, 0) ^ 0xFFFFFFFF
# So CRC(D, I, 0) = TARGET ^ 0xFFFFFFFF = 0x90C56154
NEED_FINAL = TARGET ^ 0xFFFFFFFF  # = 0x90C56154

# For CRC32 with init=I:
# The "residual" from processing n=len bytes:
# state_n(I) = state_n(0) XOR f_n(I)
# where f_n is the propagation of init through n bytes of DATA (not zeros!)
# More precisely: state_n(I) = state_n(0) XOR (I processed through n bits of the POLYNOMIAL feedback)

# The CRC32 update: state = table[(state^b) & 0xFF] ^ (state >> 8)
# = (table[(state^b) & 0xFF] ^ (state >> 8))
# = ... this is NOT linear in state unless b=0

# For b=0: state = table[state & 0xFF] ^ (state >> 8) = LINEAR
# For non-zero b: the XOR with b makes it affine

# ACTUAL property of CRC32:
# CRC(D, I, 0) = CRC(D, J, 0) XOR CRC(empty, I XOR J, 0) propagated through len(D) bytes
# But CRC(empty, K, 0) = K (state doesn't change with empty data)
# And propagation of K through n bytes:
# state = K
# for each byte b in D: state = table[(state^b) & 0xFF] ^ (state >> 8)
# = This doesn't simplify nicely because D is non-zero data.

# SIMPLER OBSERVATION: There's a well-known property:
# CRC(D, I1, X) ^ CRC(D, I2, X) = C(I1 ^ I2, n)
# where C(K, n) = CRC([0]*n, K, 0) = K processed through n bytes of ZEROS

# So: CRC(D, I, 0) = CRC(D, 0, 0) ^ C(I, n)
# We want: CRC(D, I, 0) = NEED_FINAL = 0x90C56154
# CRC(D, 0, 0) = 0x0793BC3B (from deep_trace: crc_i0=0x6707ac16 was for code range...)

# Wait, for the full cal range [0x300000, 0x3FEFFC) zeroed:
buf_z = bytearray(raw[0x300000:0x3FEFFC])
buf_z[0x30:0x34] = b'\x00\x00\x00\x00'
buf_z = bytes(buf_z)

crc_i0 = crc32(buf_z, 0, 0)  # CRC with init=0, xorout=0
print(f"  CRC(D, init=0, xorout=0) = {crc_i0:#010x}")
print(f"  Need CRC(D, I, xorout=0) = {NEED_FINAL:#010x}")

# C(I, n) = NEED_FINAL ^ CRC(D, 0, 0)
C_needed = NEED_FINAL ^ crc_i0
print(f"  Need C(I, n) = {C_needed:#010x}")

# C(K, n) for n = len(buf_z) = 0xFEFFC bytes:
# Process K through 0xFEFFC bytes of zeros
# This is equivalent to: multiply K by the zero-propagation matrix M^n

# We can find I by computing the INVERSE: which I gives C(I, n) = C_needed?
# Since CRC propagation is linear: C(I, n) = I * M^n where M is the feedback matrix
# We need I such that I * M^n = C_needed
# This requires computing M^n and then M^(-n) to invert

# A simpler approach: compute C(1, n), C(2, n), ..., and build the transformation
# OR: just try known "special" values

# C(I, 0) = I (zero-length data)
# C(I, 1) = table[I & 0xFF] ^ (I >> 8)
n = len(buf_z)
print(f"  n = {n:#x} bytes")

# Compute C(1, n): propagate I=1 through n zero bytes
K = 1
for _ in range(n):
    K = crc_tbl[K & 0xFF] ^ (K >> 8)
print(f"  C(1, n) = {K:#010x}  (x^n mod poly in GF2)")

# Since C is linear: I * C(1, n) = C(I, n) [this is GF(2) multiplication]
# We need I such that C(I, n) = C_needed

# In GF(2): C(I, n) = sum over each bit i of I: I[i] * C(2^i, n)
# Since CRC is linear: C(I1 XOR I2, n) = C(I1, n) XOR C(I2, n)

# Let's compute C(2^k, n) for k=0..31 and build the "basis"
# Then solve for I

basis = []
for k in range(32):
    Kk = 1 << k
    for _ in range(n):
        Kk = crc_tbl[Kk & 0xFF] ^ (Kk >> 8)
    basis.append(Kk)

# Gaussian elimination to solve: I such that sum(I[k] * basis[k] for k in 0..31) = C_needed
# (in GF(2)^32)
# We have 32 equations (one per bit of C_needed) and 32 unknowns (bits of I)

print(f"\n  Solving for I using Gaussian elimination:")
print(f"  (basis[k] values computed)")

# Build augmented matrix [basis[31] | basis[30] | ... | basis[0] | C_needed]
# Each column is a bit vector (32 bits = 32 rows)
matrix = []
for col in range(32):
    matrix.append(basis[31-col])
# augment with target
target_col = C_needed

# GF(2) Gaussian elimination
pivot_cols = []
for row in range(32):
    # Find pivot in current row
    found = -1
    for col in range(row, 32):
        if (matrix[col] >> (31-row)) & 1:
            found = col
            break
    if found == -1:
        print(f"  WARNING: singular at row {row}")
        continue
    # Swap
    matrix[row], matrix[found] = matrix[found], matrix[row]
    # Eliminate target
    if (target_col >> (31-row)) & 1:
        target_col ^= matrix[row]
    # Eliminate other rows
    for col2 in range(32):
        if col2 != row and (matrix[col2] >> (31-row)) & 1:
            matrix[col2] ^= matrix[row]
            # Also eliminate target? No, we already did it for target above
    pivot_cols.append(row)

print(f"  Result I = {target_col:#010x}")

# Verify
I_found = target_col
c_verify = crc32(buf_z, I_found, 0xFFFFFFFF)
print(f"  Verify: CRC(D, {I_found:#010x}, 0xFFFFFFFF) = {c_verify:#010x} (need {TARGET:#010x})")
if c_verify == TARGET:
    print(f"  *** FOUND INIT VALUE: I = {I_found:#010x}")

print("\nDone.")
