#!/usr/bin/env python3
"""
Fix patched.bin checksums with correct circular-dependency resolution.

The cal checksum [0x300000,0x3FEFFC) includes offset 0x300074 (code hash).
The code hash  [0x1BFE74,0x3FEF70) includes offset 0x300030 (cal checksum).
Both fields zeroed before each computation avoids the circular dependency.
"""
import struct

ORIG    = r"C:\EDC17\EDC17CP42_418085070BC018597408001011180100_FLASH_20260429102606_original.bin"
PATCHED = r"C:\EDC17\EDC17CP42_418085070BC018597408001011180100_FLASH_EGR_OFF_patched.bin"
FIXED   = r"C:\EDC17\patched_fixed.bin"

TARGET    = 0x6F3A9EAB
TARGET_CH = 0xDD8395D7

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

with open(ORIG,    "rb") as f: orig = bytearray(f.read())
with open(PATCHED, "rb") as f: pat  = bytearray(f.read())

# Offsets (relative to range starts)
CAL_START   = 0x300000
CAL_END     = 0x3FEFFC   # exclusive
CH_START    = 0x1BFE74
CH_END      = 0x3FEF70   # exclusive

CS_ABS      = 0x300030   # cal checksum field
CH_ABS      = 0x300074   # code hash field

# Relative offsets from each range start
CS_REL_CAL  = CS_ABS - CAL_START   # = 0x30
CH_REL_CAL  = CH_ABS - CAL_START   # = 0x74
CS_REL_CH   = CS_ABS - CH_START    # = 0xE01BC
CH_REL_CH   = CH_ABS - CH_START    # = 0xE0200

# ===================================================================
# Parameters: CRC32 init values found by GF(2) solver
# "both zeroed" = zero CS and CH before computing either checksum
# ===================================================================
# For cal checksum [0x300000,0x3FEFFC) with CS=0 AND CH=0:
CAL_INIT_BOTH = 0x707C3FD7
# For code hash [0x1BFE74,0x3FEF70) with CS=0 AND CH=0:
CH_INIT_BOTH  = 0x938DE116

# Also keep "CS only zeroed" and "CH only zeroed" for comparison
CAL_INIT_CS   = 0xAC253BFE   # cal range, only CS zeroed
CH_INIT_CH    = 0x047323D5   # CH range, only CH zeroed

print("=== Verify init values on ORIGINAL ===")

# Both-zeroed approach
buf_orig_cal_z2 = bytearray(orig[CAL_START:CAL_END])
buf_orig_cal_z2[CS_REL_CAL:CS_REL_CAL+4] = b'\x00'*4
buf_orig_cal_z2[CH_REL_CAL:CH_REL_CAL+4] = b'\x00'*4
v1 = crc32(bytes(buf_orig_cal_z2), CAL_INIT_BOTH, 0xFFFFFFFF)
print(f"  cal both-zeroed orig:  {v1:#010x}  {'OK' if v1==TARGET    else 'FAIL'}")

buf_orig_ch_z2 = bytearray(orig[CH_START:CH_END])
buf_orig_ch_z2[CS_REL_CH:CS_REL_CH+4] = b'\x00'*4
buf_orig_ch_z2[CH_REL_CH:CH_REL_CH+4] = b'\x00'*4
v2 = crc32(bytes(buf_orig_ch_z2), CH_INIT_BOTH, 0xFFFFFFFF)
print(f"  CH  both-zeroed orig:  {v2:#010x}  {'OK' if v2==TARGET_CH else 'FAIL'}")

# Single-zeroed approach (original sanity check)
buf_orig_cs_only = bytearray(orig[CAL_START:CAL_END])
buf_orig_cs_only[CS_REL_CAL:CS_REL_CAL+4] = b'\x00'*4
v3 = crc32(bytes(buf_orig_cs_only), CAL_INIT_CS, 0xFFFFFFFF)
print(f"  cal CS-only-zeroed orig: {v3:#010x}  {'OK' if v3==TARGET else 'FAIL'}")

buf_orig_ch_only = bytearray(orig[CH_START:CH_END])
buf_orig_ch_only[CH_REL_CH:CH_REL_CH+4] = b'\x00'*4
v4 = crc32(bytes(buf_orig_ch_only), CH_INIT_CH, 0xFFFFFFFF)
print(f"  CH  CH-only-zeroed orig: {v4:#010x}  {'OK' if v4==TARGET_CH else 'FAIL'}")

# ===================================================================
# Compute new checksums (both-zeroed approach, no circular dependency)
# ===================================================================
print("\n=== Compute new checksums for patched.bin (both-zeroed) ===")

buf_pat_cal_z2 = bytearray(pat[CAL_START:CAL_END])
buf_pat_cal_z2[CS_REL_CAL:CS_REL_CAL+4] = b'\x00'*4
buf_pat_cal_z2[CH_REL_CAL:CH_REL_CAL+4] = b'\x00'*4
new_cs_both = crc32(bytes(buf_pat_cal_z2), CAL_INIT_BOTH, 0xFFFFFFFF)
print(f"  New cal CS (both-zeroed) = {new_cs_both:#010x}")

buf_pat_ch_z2 = bytearray(pat[CH_START:CH_END])
buf_pat_ch_z2[CS_REL_CH:CS_REL_CH+4] = b'\x00'*4
buf_pat_ch_z2[CH_REL_CH:CH_REL_CH+4] = b'\x00'*4
new_ch_both = crc32(bytes(buf_pat_ch_z2), CH_INIT_BOTH, 0xFFFFFFFF)
print(f"  New code CH (both-zeroed) = {new_ch_both:#010x}")

# ===================================================================
# Compute new checksums (simultaneous fixed-point for CS-only / CH-only scheme)
# Solve: X = f_cal(Y)  Y = f_ch(X)
#        f_cal(Y) = CRC32(D_cal_CS0_CHY, CAL_INIT_CS, 0xFFFFFFFF)
#        f_ch(X)  = CRC32(D_ch_CSX_CH0,  CH_INIT_CH,  0xFFFFFFFF)
# ===================================================================
print("\n=== Compute new checksums (simultaneous system) ===")

def crc32_range_with_patch(data_range, offset, value_4bytes, init, xorout=0xFFFFFFFF):
    """CRC32 of data_range with 4 bytes at offset replaced by value."""
    buf = bytearray(data_range)
    struct.pack_into("<I", buf, offset, value_4bytes)
    return crc32(bytes(buf), init, xorout)

# Base buffers (with CS and CH at their zero/correct positions)
D_cal_base = bytearray(pat[CAL_START:CAL_END])
D_cal_base[CS_REL_CAL:CS_REL_CAL+4] = b'\x00'*4  # CS zeroed
# CH at CH_REL_CAL is not zeroed (depends on Y)

D_ch_base = bytearray(pat[CH_START:CH_END])
D_ch_base[CH_REL_CH:CH_REL_CH+4] = b'\x00'*4     # CH zeroed
# CS at CS_REL_CH is not zeroed (depends on X)

# f_cal(Y) = CRC32(D_cal_base with Y at CH_REL_CAL, CAL_INIT_CS, 0xFFFFFFFF)
# f_ch(X)  = CRC32(D_ch_base  with X at CS_REL_CH,  CH_INIT_CH,  0xFFFFFFFF)

# Iterative approach: start with original values and iterate
# X_n+1 = f_cal(f_ch(X_n))
X = TARGET       # initial guess (old CS)
Y = TARGET_CH    # initial guess (old CH)

for iteration in range(200):
    X_new = crc32_range_with_patch(D_cal_base, CH_REL_CAL, Y, CAL_INIT_CS)
    Y_new = crc32_range_with_patch(D_ch_base,  CS_REL_CH,  X_new, CH_INIT_CH)
    if X_new == X and Y_new == Y:
        print(f"  Fixed point found at iteration {iteration}")
        break
    X, Y = X_new, Y_new
else:
    print(f"  WARNING: Did not converge after 200 iterations")
    print(f"  Last X={X:#010x} Y={Y:#010x}")

new_cs_fp = X
new_ch_fp  = Y
print(f"  New CS (fixed-point) = {new_cs_fp:#010x}")
print(f"  New CH (fixed-point) = {new_ch_fp:#010x}")

# Verify fixed-point solution
chk_cs = crc32_range_with_patch(D_cal_base, CH_REL_CAL, new_ch_fp, CAL_INIT_CS)
chk_ch = crc32_range_with_patch(D_ch_base,  CS_REL_CH,  new_cs_fp, CH_INIT_CH)
print(f"  Verify CS: f_cal({new_ch_fp:#010x}) = {chk_cs:#010x}  {'OK' if chk_cs==new_cs_fp else 'FAIL'}")
print(f"  Verify CH: f_ch ({new_cs_fp:#010x}) = {chk_ch:#010x}  {'OK' if chk_ch==new_ch_fp else 'FAIL'}")

# ===================================================================
# Write patched_fixed.bin using the BOTH-ZEROED approach
# (chosen because it's unambiguous and avoids circular dependency)
# ===================================================================
print("\n=== Writing patched_fixed.bin ===")
fixed = bytearray(pat)
struct.pack_into("<I", fixed, CS_ABS, new_cs_both)
struct.pack_into("<I", fixed, CH_ABS, new_ch_both)
print(f"  CS: {TARGET:#010x} -> {new_cs_both:#010x}  at 0x300030  (both-zeroed)")
print(f"  CH: {TARGET_CH:#010x} -> {new_ch_both:#010x}  at 0x300074  (both-zeroed)")

with open(FIXED, "wb") as f:
    f.write(fixed)
print(f"  Saved {FIXED}")

# ===================================================================
# Full verification of written file
# ===================================================================
print("\n=== Verify patched_fixed.bin ===")
with open(FIXED, "rb") as f:
    fx = bytearray(f.read())

buf_fx_cal = bytearray(fx[CAL_START:CAL_END])
buf_fx_cal[CS_REL_CAL:CS_REL_CAL+4] = b'\x00'*4
buf_fx_cal[CH_REL_CAL:CH_REL_CAL+4] = b'\x00'*4
v_cs = crc32(bytes(buf_fx_cal), CAL_INIT_BOTH, 0xFFFFFFFF)
s_cs = struct.unpack_from("<I", fx, CS_ABS)[0]
print(f"  Cal CS  stored={s_cs:#010x} computed={v_cs:#010x}  {'PASS' if v_cs==s_cs else 'FAIL'}")

buf_fx_ch = bytearray(fx[CH_START:CH_END])
buf_fx_ch[CS_REL_CH:CS_REL_CH+4] = b'\x00'*4
buf_fx_ch[CH_REL_CH:CH_REL_CH+4] = b'\x00'*4
v_ch = crc32(bytes(buf_fx_ch), CH_INIT_BOTH, 0xFFFFFFFF)
s_ch = struct.unpack_from("<I", fx, CH_ABS)[0]
print(f"  Code CH stored={s_ch:#010x} computed={v_ch:#010x}  {'PASS' if v_ch==s_ch else 'FAIL'}")

# Also show RSA block (should be unchanged)
orig_rsa = orig[0x3FEFC0:0x3FF000]
fx_rsa   = fx  [0x3FEFC0:0x3FF000]
print(f"  RSA block [0x3FEFC0,0x3FF000) unchanged: {'YES' if orig_rsa == fx_rsa else 'NO - WARNING'}")

print("\n=== Summary ===")
orig_diffs = [(i, orig[i], fx[i]) for i in range(len(orig)) if orig[i] != fx[i]]
code_ch = [d for d in orig_diffs if d[0] < 0x300000]
cal_ch  = [d for d in orig_diffs if 0x300000 <= d[0] < 0x400000]
print(f"  Total bytes changed vs original: {len(orig_diffs)}")
print(f"  Code area: {len(code_ch)} bytes (EGR-off code patches)")
print(f"  Cal area:  {len(cal_ch)} bytes (EGR maps + TPROT flag + new CS/CH)")
print(f"  Cal header changes:")
for off, lbl in [(CS_ABS,'CS'), (CH_ABS,'CH'), (0x300070,'TPROT')]:
    ov = struct.unpack_from("<I", orig, off)[0]
    fv = struct.unpack_from("<I", fx,   off)[0]
    print(f"    0x{off:06X} {lbl}: {ov:#010x} -> {fv:#010x}  {'changed' if ov!=fv else 'same'}")

print("\nDone.")
