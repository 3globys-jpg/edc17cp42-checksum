#!/usr/bin/env python3
"""
Bosch EDC17CP42 calibration checksum fixer.

Usage:
    python fix_checksum.py input.bin output.bin

Fixes two fields in the calibration block header:
  0x300030 - calibration checksum (CS)
  0x300074 - code hash (CH)

Algorithm: CRC32 (poly=0xEDB88320, reflected, xorout=0xFFFFFFFF)
Both CS and CH are zeroed before each computation to avoid circular dependency
(the CS range includes 0x300074, the CH range includes 0x300030).

Verified against EDC17CP42_418085070BC018597408001011180100 firmware family.
"""
import sys
import struct

# ---------------------------------------------------------------------------
# CRC32 table (poly = 0xEDB88320, reflected)
# ---------------------------------------------------------------------------
_CRC_TBL = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if (_c & 1) else (_c >> 1)
    _CRC_TBL.append(_c)

def crc32(buf, init=0xFFFFFFFF, xorout=0xFFFFFFFF):
    crc = init
    for b in buf:
        crc = _CRC_TBL[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (crc ^ xorout) & 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Flash layout constants (EDC17CP42, 4 MB flash)
# ---------------------------------------------------------------------------
FLASH_SIZE  = 0x400000

CAL_START   = 0x300000   # calibration block start
CAL_END     = 0x3FEFFC   # calibration block end (exclusive)
CH_START    = 0x1BFE74   # code-hash range start
CH_END      = 0x3FEF70   # code-hash range end (exclusive)

CS_ADDR     = 0x300030   # cal checksum field (4 bytes, little-endian)
CH_ADDR     = 0x300074   # code hash field    (4 bytes, little-endian)
TPROT_ADDR  = 0x300070   # TPROT flag (informational only)

MAGIC1_ADDR = 0x300040   # FADECAFE marker
MAGIC2_ADDR = 0x300060   # second FADECAFE marker
FADECAFE    = 0xFADECAFE

# Relative offsets within each range
CS_REL_CAL  = CS_ADDR - CAL_START    # 0x30
CH_REL_CAL  = CH_ADDR - CAL_START    # 0x74
CS_REL_CH   = CS_ADDR - CH_START     # 0xE01BC
CH_REL_CH   = CH_ADDR - CH_START     # 0xE0200

# Non-standard CRC32 init values derived by GF(2) linear algebra from a
# known-good EDC17CP42 flash image (both CS and CH zeroed before each run).
CAL_INIT    = 0x707C3FD7
CH_INIT     = 0x938DE116

# ---------------------------------------------------------------------------

def compute_cs(data):
    """Compute calibration checksum over [0x300000, 0x3FEFFC) with CS and CH zeroed."""
    buf = bytearray(data[CAL_START:CAL_END])
    buf[CS_REL_CAL:CS_REL_CAL + 4] = b'\x00' * 4
    buf[CH_REL_CAL:CH_REL_CAL + 4] = b'\x00' * 4
    return crc32(bytes(buf), CAL_INIT)

def compute_ch(data):
    """Compute code hash over [0x1BFE74, 0x3FEF70) with CS and CH zeroed."""
    buf = bytearray(data[CH_START:CH_END])
    buf[CS_REL_CH:CS_REL_CH + 4] = b'\x00' * 4
    buf[CH_REL_CH:CH_REL_CH + 4] = b'\x00' * 4
    return crc32(bytes(buf), CH_INIT)

def read_u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]

def write_u32(data, offset, value):
    struct.pack_into("<I", data, offset, value)

# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} input.bin output.bin")
        sys.exit(1)

    in_path, out_path = sys.argv[1], sys.argv[2]

    print(f"Input:  {in_path}")
    print(f"Output: {out_path}")

    with open(in_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) != FLASH_SIZE:
        print(f"ERROR: expected {FLASH_SIZE:#x} bytes, got {len(data):#x}")
        sys.exit(1)

    # Sanity check: Bosch magic markers
    m1 = read_u32(data, MAGIC1_ADDR)
    m2 = read_u32(data, MAGIC2_ADDR)
    if m1 != FADECAFE or m2 != FADECAFE:
        print(f"WARNING: FADECAFE markers not found (got {m1:#010x}, {m2:#010x})")
        print("         Proceeding anyway — double-check this is an EDC17CP42 image.")

    old_cs = read_u32(data, CS_ADDR)
    old_ch = read_u32(data, CH_ADDR)
    tprot  = read_u32(data, TPROT_ADDR)

    print(f"\nCurrent values:")
    print(f"  0x{CS_ADDR:06X}  Cal CS   = {old_cs:#010x}")
    print(f"  0x{CH_ADDR:06X}  Code CH  = {old_ch:#010x}")
    print(f"  0x{TPROT_ADDR:06X}  TPROT    = {tprot:#010x}")

    new_cs = compute_cs(data)
    new_ch = compute_ch(data)

    print(f"\nComputed values:")
    print(f"  0x{CS_ADDR:06X}  Cal CS   = {new_cs:#010x}  {'(unchanged)' if new_cs == old_cs else '(CHANGED)'}")
    print(f"  0x{CH_ADDR:06X}  Code CH  = {new_ch:#010x}  {'(unchanged)' if new_ch == old_ch else '(CHANGED)'}")

    if new_cs == old_cs and new_ch == old_ch:
        print("\nNo changes needed — checksums are already correct.")
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"Written (unchanged) to {out_path}")
        return

    write_u32(data, CS_ADDR, new_cs)
    write_u32(data, CH_ADDR, new_ch)

    # Self-verify before writing
    v_cs = compute_cs(data)
    v_ch = compute_ch(data)
    if v_cs != new_cs or v_ch != new_ch:
        print(f"\nERROR: self-verification failed!")
        print(f"  CS: stored={new_cs:#010x} recomputed={v_cs:#010x}")
        print(f"  CH: stored={new_ch:#010x} recomputed={v_ch:#010x}")
        sys.exit(1)

    with open(out_path, "wb") as f:
        f.write(data)

    print(f"\nVerification: PASS")
    print(f"Written to {out_path}")

if __name__ == "__main__":
    main()
