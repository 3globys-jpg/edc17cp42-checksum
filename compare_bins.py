#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, struct
sys.stdout.reconfigure(encoding='utf-8')

ORIG  = r"C:\EDC17\EDC17CP42_418085070BC018597408001011180100_FLASH_20260429102606_original.bin"
FIXED = r"C:\EDC17\patched_fixed.bin"

with open(ORIG,  "rb") as f: orig  = f.read()
with open(FIXED, "rb") as f: fixed = f.read()

# Known expected change regions
EXPECTED = [
    (0x035DAE, 0x035DB0, "P2264 enable flag"),
    (0x03089A, 0x03089C, "P2269 index"),
    (0x000308FA, 0x000308FC, "code patch"),
    (0x00017210, 0x00017214, "code patch (TPROT area)"),
    (0x300030, 0x300034, "Cal checksum CS"),
    (0x300070, 0x300074, "TPROT flag"),
    (0x300074, 0x300078, "Code hash CH"),
    (0x30288C, 0x302970, "EGR DTC monitor pre"),
    (0x302970, 0x302B70, "EGR Map 1"),
    (0x302B70, 0x302BB0, "EGR Map 1 tail"),
    (0x302BB0, 0x302DB0, "EGR Map 2"),
    (0x302DC4, 0x302E40, "EGR DTC monitor"),
    (0x3032B8, 0x30332C, "P2495 thresholds"),
]

def classify(addr):
    for (s, e, name) in EXPECTED:
        if s <= addr < e:
            return name
    return None

# Collect all diffs
diffs = [(i, orig[i], fixed[i]) for i in range(min(len(orig), len(fixed))) if orig[i] != fixed[i]]

print(f"{'='*70}")
print(f"Порівняння: original.bin vs patched_fixed.bin")
print(f"Всього відмінностей: {len(diffs)} байт")
print(f"{'='*70}\n")

# Group into contiguous runs
runs = []
if diffs:
    start = diffs[0][0]
    prev  = diffs[0][0]
    run   = [diffs[0]]
    for addr, o, p in diffs[1:]:
        if addr == prev + 1:
            run.append((addr, o, p))
        else:
            runs.append((start, run))
            start = addr
            run   = [(addr, o, p)]
        prev = addr
    runs.append((start, run))

unexpected = []

for run_start, run in runs:
    run_end = run[-1][0] + 1
    length  = len(run)
    cat     = classify(run_start)

    # Check if ALL bytes in run are within expected region
    all_known = all(classify(addr) is not None for addr, _, _ in run)

    if not all_known:
        unexpected.append((run_start, run_end, run))

    # Header
    print(f"── 0x{run_start:06X}–0x{run_end:06X}  ({length} байт)  [{cat or '*** НЕВІДОМО ***'}]")

    # Show bytes (limit to 32 for long runs)
    show = run if length <= 16 else run[:8] + [None] + run[-4:]
    for item in show:
        if item is None:
            print(f"   ... ({length - 12} байт пропущено) ...")
            continue
        addr, o, p = item
        print(f"   0x{addr:06X}:  {o:02X} → {p:02X}")

    # Assessment
    if cat == "Cal checksum CS":
        o_val = struct.unpack_from("<I", bytes(b for _, b, _ in run))[0] if length == 4 else 0
        p_val = struct.unpack_from("<I", bytes(b for _, _, b in run))[0] if length == 4 else 0
        print(f"   Значення: {orig[run_start:run_start+4].hex()} → {fixed[run_start:run_start+4].hex()}")
        print(f"   ✅ Очікувана зміна. Новий CRC32 контрольної суми калібрування.")
    elif cat == "Code hash CH":
        print(f"   Значення: {orig[run_start:run_start+4].hex()} → {fixed[run_start:run_start+4].hex()}")
        print(f"   ✅ Очікувана зміна. Новий хеш коду.")
    elif cat == "TPROT flag":
        print(f"   ✅ Очікувана зміна. TPROT flag: 0x00001001 → 0x00001000 (відключення захисту запису).")
    elif cat and "EGR" in cat:
        zeros = all(p == 0x00 for _, _, p in run)
        print(f"   {'✅' if zeros else '⚠️'} EGR карта → {'нулі (відключення EGR)' if zeros else 'не нулі — перевірити!'}.")
    elif cat and "P2495" in cat:
        ffff = all(p == 0xFF for _, _, p in run)
        print(f"   {'✅' if ffff else '⚠️'} P2495 пороги → {'0xFFFF (відключення DTC)' if ffff else 'несподіване значення'}.")
    elif cat and ("P2264" in cat or "P2269" in cat or "code patch" in cat):
        zeros = all(p == 0x00 for _, _, p in run)
        print(f"   {'✅' if zeros else '⚠️'} Патч коду → {'нулі (NOP/відключення)' if zeros else 'несподіване значення'}.")
    elif not all_known:
        print(f"   ❌ НЕВІДОМА ЗМІНА — потребує перевірки!")
    else:
        print(f"   ✅ В межах очікуваного діапазону.")
    print()

# Summary
print(f"{'='*70}")
print(f"ПІДСУМОК")
print(f"{'='*70}")
print(f"Всього змінено байт:    {len(diffs)}")
print(f"Груп змін (блоків):     {len(runs)}")
print(f"Несподіваних блоків:    {len(unexpected)}")
print()

code_changes = [(s, r) for s, r in runs if s < 0x300000]
cal_changes  = [(s, r) for s, r in runs if s >= 0x300000]
print(f"Зміни в коді    (< 0x300000): {sum(len(r) for _,r in code_changes)} байт у {len(code_changes)} блоках")
print(f"Зміни в калібр. (≥ 0x300000): {sum(len(r) for _,r in cal_changes)} байт у {len(cal_changes)} блоках")
print()

if not unexpected:
    print("✅ ВИСНОВОК: Всі зміни відповідають очікуваним.")
    print("   Безпечно заливати в ЕБУ.")
else:
    print("❌ ВИСНОВОК: Знайдено несподівані зміни:")
    for s, e, r in unexpected:
        cats = set(classify(a) or "НЕВІДОМО" for a, _, _ in r)
        print(f"   0x{s:06X}–0x{e:06X}: {cats}")
    print("   Перевірте ці адреси перед заливкою!")
