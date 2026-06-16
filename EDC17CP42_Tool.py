#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EDC17CP42 Tool — повноцінний GUI для патчування прошивки
Вкладки: Файли | EGR | DTC | Захист | Контрольна сума | Аудит
"""

import os
import struct
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ─── CRC32 (poly=0xEDB88320, reflected) ────────────────────────────────────
_CRC_TBL = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if (_c & 1) else (_c >> 1)
    _CRC_TBL.append(_c)

def _crc32(buf, init=0xFFFFFFFF):
    crc = init
    for b in buf:
        crc = _CRC_TBL[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF

# ─── Flash layout (EDC17CP42, 4 MB) ────────────────────────────────────────
FLASH_SIZE  = 0x400000
CAL_START   = 0x300000;  CAL_END = 0x3FEFFC
CH_START    = 0x1BFE74;  CH_END  = 0x3FEF70
CS_ADDR     = 0x300030
CH_ADDR     = 0x300074
TPROT_ADDR  = 0x300070
MAGIC1_ADDR = 0x300040
FADECAFE    = 0xFADECAFE
CAL_INIT    = 0x707C3FD7
CH_INIT     = 0x938DE116
CS_REL_CAL  = CS_ADDR - CAL_START
CH_REL_CAL  = CH_ADDR - CAL_START
CS_REL_CH   = CS_ADDR - CH_START
CH_REL_CH   = CH_ADDR - CH_START

def _compute_cs(data):
    buf = bytearray(data[CAL_START:CAL_END])
    buf[CS_REL_CAL:CS_REL_CAL + 4] = b'\x00' * 4
    buf[CH_REL_CAL:CH_REL_CAL + 4] = b'\x00' * 4
    return _crc32(bytes(buf), CAL_INIT)

def _compute_ch(data):
    buf = bytearray(data[CH_START:CH_END])
    buf[CS_REL_CH:CS_REL_CH + 4] = b'\x00' * 4
    buf[CH_REL_CH:CH_REL_CH + 4] = b'\x00' * 4
    return _crc32(bytes(buf), CH_INIT)

def _read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def _write_u32(data, off, val):
    struct.pack_into("<I", data, off, val)

# ─── Операції патчування ────────────────────────────────────────────────────
OPERATIONS = [
    # (id, tab, label, description)
    ("egr_maps",       "EGR",    "Вимкнути EGR (Map1 + Map2)",
     "Обнулити EGR Map1 (0x302970–0x302B70) та Map2 (0x302BB0–0x302DB0)"),
    ("egr_monitor",    "EGR",    "Вимкнути моніторинг EGR",
     "Обнулити блок порогів DTC EGR (0x302DC4–0x302E18)"),
    ("dtc_p2495",      "DTC",    "Вимкнути DTC P2495",
     "Пороги P2495 (0x3032B8–0x30332A) → 0xFF  (перевищення t° EGR)"),
    ("dtc_p2264",      "DTC",    "Вимкнути DTC P2264",
     "0x035DAE → 0x0000  (несправність датчика якості палива)"),
    ("dtc_p2269",      "DTC",    "Вимкнути DTC P2269",
     "0x03089A, 0x0308FA → 0x0000  (вода у паливі)"),
    ("dtc_p0403_p0409","DTC",    "Вимкнути DTC P0403, P0409",
     "Пороги P0403/P0409 (0x3032F4–0x30332A) → 0xFF  (клапан EGR)"),
    ("tprot_off",      "Захист", "TPROT OFF",
     "0x300070: 0x00001001 → 0x00001000  (відключення захисту запису)"),
]

OP_BY_ID = {op[0]: op for op in OPERATIONS}

def apply_operation(data: bytearray, op_id: str) -> str:
    if op_id == "egr_maps":
        data[0x302970:0x302B70] = b'\x00' * (0x302B70 - 0x302970)
        data[0x302BB0:0x302DB0] = b'\x00' * (0x302DB0 - 0x302BB0)
        return "EGR Map1+Map2 обнулено"
    if op_id == "egr_monitor":
        data[0x302DC4:0x302E18] = b'\x00' * (0x302E18 - 0x302DC4)
        return "Моніторинг EGR обнулено"
    if op_id == "dtc_p2495":
        data[0x3032B8:0x30332B] = b'\xFF' * (0x30332B - 0x3032B8)
        return "P2495 пороги → 0xFF"
    if op_id == "dtc_p2264":
        data[0x035DAE:0x035DB0] = b'\x00' * 2
        return "P2264 → 0x0000"
    if op_id == "dtc_p2269":
        data[0x03089A:0x03089C] = b'\x00' * 2
        data[0x0308FA:0x0308FC] = b'\x00' * 2
        return "P2269 → 0x0000"
    if op_id == "dtc_p0403_p0409":
        data[0x3032F4:0x30332B] = b'\xFF' * (0x30332B - 0x3032F4)
        return "P0403/P0409 пороги → 0xFF"
    if op_id == "tprot_off":
        cur = _read_u32(data, TPROT_ADDR)
        _write_u32(data, TPROT_ADDR, 0x00001000)
        return f"TPROT: 0x{cur:08X} → 0x00001000"
    return f"Невідома операція: {op_id}"

def fix_checksums(data: bytearray):
    new_cs = _compute_cs(data)
    new_ch = _compute_ch(data)
    _write_u32(data, CS_ADDR, new_cs)
    _write_u32(data, CH_ADDR, new_ch)
    return new_cs, new_ch

# ─── Аудит: відомі діапазони ────────────────────────────────────────────────
KNOWN_RANGES = [
    (0x035DAE, 0x035DB0, "P2264 enable flag"),
    (0x03089A, 0x03089C, "P2269 index A"),
    (0x0308FA, 0x0308FC, "P2269 index B"),
    (0x300030, 0x300034, "Cal checksum CS"),
    (0x300070, 0x300074, "TPROT flag"),
    (0x300074, 0x300078, "Code hash CH"),
    (0x302970, 0x302B70, "EGR Map 1"),
    (0x302BB0, 0x302DB0, "EGR Map 2"),
    (0x302DC4, 0x302E40, "EGR DTC monitor"),
    (0x3032B8, 0x30332C, "P2495 / P0403 / P0409 thresholds"),
]

def _classify_addr(addr: int):
    for s, e, name in KNOWN_RANGES:
        if s <= addr < e:
            return name
    return None


# ─── Головне вікно ──────────────────────────────────────────────────────────
class EDC17Tool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EDC17CP42 Tool")
        self.minsize(750, 540)
        self.resizable(True, True)

        self._data: bytearray | None = None
        self._in_path  = tk.StringVar()
        self._out_path = tk.StringVar()
        self._status   = tk.StringVar(value="Оберіть вхідний файл на вкладці «Файли»")
        self._checks   = {op[0]: tk.BooleanVar(value=False) for op in OPERATIONS}

        self._build_ui()
        self._center()

    # ── UI skeleton ──────────────────────────────────────────────────────────
    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        nb = ttk.Notebook(self)
        nb.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

        tabs = {
            "files":  ttk.Frame(nb, padding=12),
            "egr":    ttk.Frame(nb, padding=12),
            "dtc":    ttk.Frame(nb, padding=12),
            "prot":   ttk.Frame(nb, padding=12),
            "crc":    ttk.Frame(nb, padding=12),
            "audit":  ttk.Frame(nb, padding=12),
        }
        nb.add(tabs["files"],  text="  Файли  ")
        nb.add(tabs["egr"],    text="  EGR  ")
        nb.add(tabs["dtc"],    text="  DTC  ")
        nb.add(tabs["prot"],   text="  Захист  ")
        nb.add(tabs["crc"],    text="  Контрольна сума  ")
        nb.add(tabs["audit"],  text="  Аудит  ")

        self._build_files_tab(tabs["files"])
        self._build_ops_tab(tabs["egr"],  "EGR",    _HELP_EGR)
        self._build_ops_tab(tabs["dtc"],  "DTC",    _HELP_DTC)
        self._build_ops_tab(tabs["prot"], "Захист", _HELP_PROT)
        self._build_crc_tab(tabs["crc"])
        self._build_audit_tab(tabs["audit"])

        # ── Нижня панель ─────────────────────────────────────────────────
        bot = ttk.Frame(self, padding=(6, 0, 6, 6))
        bot.grid(row=1, column=0, sticky="ew")
        bot.columnconfigure(1, weight=1)

        self._apply_btn = ttk.Button(
            bot, text="▶  Застосувати вибране",
            command=self._apply_selected, width=28)
        self._apply_btn.grid(row=0, column=0, padx=(0, 12))

        self._status_lbl = tk.Label(
            bot, textvariable=self._status,
            anchor="w", font=("Segoe UI", 9), fg="#444", bg=self.cget("bg"))
        self._status_lbl.grid(row=0, column=1, sticky="ew")

    # ── Вкладка: Файли ───────────────────────────────────────────────────────
    def _build_files_tab(self, f):
        f.columnconfigure(1, weight=1)

        rows = [
            ("Вхідний .bin файл:",  self._in_path,  self._browse_in,  0),
            ("Вихідний .bin файл:", self._out_path, self._browse_out, 1),
        ]
        for label, var, cmd, r in rows:
            ttk.Label(f, text=label, width=22, anchor="w").grid(
                row=r, column=0, sticky="w", pady=5)
            ttk.Entry(f, textvariable=var, width=62).grid(
                row=r, column=1, sticky="ew", padx=4)
            ttk.Button(f, text="…", width=3, command=cmd).grid(row=r, column=2)

        ttk.Button(f, text="Завантажити файл",
                   command=self._load_file, width=22).grid(
            row=2, column=0, columnspan=3, pady=(14, 6))

        self._file_info = tk.StringVar(value="Файл не завантажено.")
        tk.Label(f, textvariable=self._file_info,
                 font=("Courier", 9), fg="#555", bg=self.cget("bg"),
                 justify="left", anchor="w").grid(
            row=3, column=0, columnspan=3, sticky="w")

    # ── Вкладка: операції (EGR / DTC / Захист) ──────────────────────────────
    def _build_ops_tab(self, f, tab_name: str, help_text: str):
        f.columnconfigure(0, weight=1)
        f.rowconfigure(1, weight=1)

        ops_frame = ttk.LabelFrame(f, text=" Операції ", padding=8)
        ops_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ops_frame.columnconfigure(1, weight=1)

        tab_ops = [(op_id, lbl, desc)
                   for op_id, tab, lbl, desc in OPERATIONS
                   if tab == tab_name]

        for r, (op_id, lbl, desc) in enumerate(tab_ops):
            ttk.Checkbutton(ops_frame, variable=self._checks[op_id]).grid(
                row=r, column=0, padx=(2, 6))
            ttk.Label(ops_frame, text=lbl,
                      font=("Segoe UI", 10, "bold"), anchor="w").grid(
                row=r, column=1, sticky="w")
            ttk.Label(ops_frame, text=desc,
                      font=("Segoe UI", 8), foreground="#555", anchor="w").grid(
                row=r, column=2, sticky="w", padx=(12, 8))
            ttk.Button(
                ops_frame, text="Застосувати зараз", width=18,
                command=lambda oid=op_id: self._apply_one(oid)).grid(
                row=r, column=3, pady=3, padx=(0, 2))

        hlp = ttk.LabelFrame(f, text=" Довідка ", padding=8)
        hlp.grid(row=1, column=0, sticky="nsew")
        hlp.columnconfigure(0, weight=1)
        hlp.rowconfigure(0, weight=1)

        txt = tk.Text(hlp, wrap="word", font=("Segoe UI", 9), height=7,
                      state="disabled", bg=self.cget("bg"), relief="flat", bd=0)
        txt.grid(row=0, column=0, sticky="nsew")
        txt.config(state="normal")
        txt.insert("1.0", help_text.strip())
        txt.config(state="disabled")

    # ── Вкладка: Контрольна сума ─────────────────────────────────────────────
    def _build_crc_tab(self, f):
        f.columnconfigure(0, weight=1)

        info = ttk.LabelFrame(f, text=" Поточні значення ", padding=10)
        info.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        info.columnconfigure(2, weight=1)

        self._crc_vars = {}
        for r, (name, addr, key) in enumerate([
            ("Cal CS",  f"0x{CS_ADDR:06X}",    "cs"),
            ("Code CH", f"0x{CH_ADDR:06X}",    "ch"),
            ("TPROT",   f"0x{TPROT_ADDR:06X}", "tprot"),
        ]):
            ttk.Label(info, text=name, width=10, anchor="w",
                      font=("Courier", 10, "bold")).grid(row=r, column=0, sticky="w", pady=3)
            ttk.Label(info, text=addr, width=12, anchor="w",
                      font=("Courier", 10)).grid(row=r, column=1, sticky="w")
            var = tk.StringVar(value="—")
            self._crc_vars[key] = var
            ttk.Label(info, textvariable=var, width=16, anchor="w",
                      font=("Courier", 10)).grid(row=r, column=2, sticky="w")

        ttk.Button(f, text="Розрахувати та виправити CRC32",
                   command=self._run_crc, width=38).grid(row=1, column=0, pady=6)

        self._crc_msg = tk.StringVar()
        tk.Label(f, textvariable=self._crc_msg,
                 font=("Segoe UI", 9), fg="#007700", bg=self.cget("bg"),
                 anchor="w", justify="left").grid(row=2, column=0, sticky="w")

    def _refresh_crc_display(self):
        if self._data is None:
            return
        for key, addr in [("cs", CS_ADDR), ("ch", CH_ADDR), ("tprot", TPROT_ADDR)]:
            self._crc_vars[key].set(f"0x{_read_u32(self._data, addr):08X}")

    # ── Вкладка: Аудит ───────────────────────────────────────────────────────
    def _build_audit_tab(self, f):
        f.columnconfigure(0, weight=1)
        f.rowconfigure(2, weight=1)

        sel = ttk.Frame(f)
        sel.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        sel.columnconfigure(1, weight=1)
        sel.columnconfigure(4, weight=1)

        self._audit_a = tk.StringVar()
        self._audit_b = tk.StringVar()

        ttk.Label(sel, text="Файл A (оригінал):").grid(row=0, column=0, sticky="w", padx=(0, 4))
        ttk.Entry(sel, textvariable=self._audit_a, width=32).grid(row=0, column=1, sticky="ew")
        ttk.Button(sel, text="…", width=3,
                   command=lambda: self._pick_audit(self._audit_a)).grid(row=0, column=2, padx=4)

        ttk.Label(sel, text="Файл B (змінений):").grid(row=0, column=3, sticky="w", padx=(8, 4))
        ttk.Entry(sel, textvariable=self._audit_b, width=32).grid(row=0, column=4, sticky="ew")
        ttk.Button(sel, text="…", width=3,
                   command=lambda: self._pick_audit(self._audit_b)).grid(row=0, column=5, padx=4)

        ttk.Button(f, text="Порівняти файли",
                   command=self._run_audit, width=22).grid(row=1, column=0, pady=(0, 6))

        txt_wrap = ttk.Frame(f)
        txt_wrap.grid(row=2, column=0, sticky="nsew")
        txt_wrap.columnconfigure(0, weight=1)
        txt_wrap.rowconfigure(0, weight=1)

        self._audit_txt = tk.Text(
            txt_wrap, wrap="none", font=("Courier", 9), state="disabled")
        sb_v = ttk.Scrollbar(txt_wrap, orient="vertical",
                             command=self._audit_txt.yview)
        sb_h = ttk.Scrollbar(txt_wrap, orient="horizontal",
                             command=self._audit_txt.xview)
        self._audit_txt.configure(yscrollcommand=sb_v.set, xscrollcommand=sb_h.set)
        self._audit_txt.grid(row=0, column=0, sticky="nsew")
        sb_v.grid(row=0, column=1, sticky="ns")
        sb_h.grid(row=1, column=0, sticky="ew")

        self._audit_txt.tag_configure("known",
            foreground="#006600", background="#efffef")
        self._audit_txt.tag_configure("unknown",
            foreground="#cc0000", background="#fff0f0")
        self._audit_txt.tag_configure("header",
            foreground="#003399", font=("Courier", 9, "bold"))
        self._audit_txt.tag_configure("summary",
            foreground="#222", font=("Courier", 9, "bold"))

    # ── Файлові діалоги ───────────────────────────────────────────────────────
    def _browse_in(self):
        p = filedialog.askopenfilename(
            title="Вхідний файл прошивки",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if p:
            self._in_path.set(p)
            if not self._out_path.get():
                stem = p[:-4] if p.lower().endswith(".bin") else p
                self._out_path.set(stem + "_patched.bin")

    def _browse_out(self):
        p = filedialog.asksaveasfilename(
            title="Зберегти виправлений файл",
            defaultextension=".bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if p:
            self._out_path.set(p)

    def _pick_audit(self, var: tk.StringVar):
        p = filedialog.askopenfilename(
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if p:
            var.set(p)

    # ── Завантаження файлу ───────────────────────────────────────────────────
    def _load_file(self):
        path = self._in_path.get().strip()
        if not path:
            messagebox.showwarning("Увага", "Вкажіть вхідний файл.")
            return
        try:
            with open(path, "rb") as fh:
                data = bytearray(fh.read())
        except OSError as e:
            messagebox.showerror("Помилка читання", str(e))
            return
        if len(data) != FLASH_SIZE:
            messagebox.showerror(
                "Невірний розмір",
                f"Файл: {len(data):#x} байт, очікується {FLASH_SIZE:#x}.")
            return
        if _read_u32(data, MAGIC1_ADDR) != FADECAFE:
            if not messagebox.askyesno(
                    "Попередження",
                    "Маркер FADECAFE не знайдено.\n"
                    "Це може бути не EDC17CP42. Продовжити?"):
                return

        self._data = data
        cs    = _read_u32(data, CS_ADDR)
        ch    = _read_u32(data, CH_ADDR)
        tprot = _read_u32(data, TPROT_ADDR)
        self._file_info.set(
            f"Завантажено: {os.path.basename(path)}  ({len(data) // 1024} KB)\n"
            f"CS=0x{cs:08X}   CH=0x{ch:08X}   TPROT=0x{tprot:08X}")
        self._refresh_crc_display()
        self._set_status(f"Файл завантажено: {os.path.basename(path)}", "ok")

    # ── Застосування патчів ───────────────────────────────────────────────────
    def _require_data(self) -> bool:
        if self._data is None:
            messagebox.showwarning("Файл не завантажено",
                                   "Спочатку завантажте файл на вкладці «Файли».")
            return False
        return True

    def _apply_one(self, op_id: str):
        if not self._require_data():
            return
        msg = apply_operation(self._data, op_id)
        self._refresh_crc_display()
        self._set_status(f"✔ {msg}", "ok")

    def _apply_selected(self):
        if not self._require_data():
            return

        selected = [op_id for op_id, var in self._checks.items() if var.get()]
        if not selected:
            messagebox.showinfo("Нічого не вибрано",
                                "Відмітьте хоча б одну операцію (EGR / DTC / Захист).")
            return

        out_path = self._out_path.get().strip()
        if not out_path:
            messagebox.showwarning("Увага", "Вкажіть вихідний файл на вкладці «Файли».")
            return

        self._apply_btn.config(state="disabled")
        self._set_status("Застосування патчів…", "info")

        def worker():
            results = []
            for op_id in selected:
                results.append(apply_operation(self._data, op_id))

            new_cs, new_ch = fix_checksums(self._data)
            results.append(f"CRC32: CS=0x{new_cs:08X}  CH=0x{new_ch:08X}")

            try:
                with open(out_path, "wb") as fh:
                    fh.write(self._data)
                results.append(f"Збережено → {os.path.basename(out_path)}")
            except OSError as e:
                self.after(0, lambda: messagebox.showerror("Помилка запису", str(e)))
                self.after(0, lambda: self._apply_btn.config(state="normal"))
                return

            summary = "  |  ".join(results)
            self.after(0, self._refresh_crc_display)
            self.after(0, lambda: self._set_status(f"✔ {summary}", "ok"))
            self.after(0, lambda: self._apply_btn.config(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    # ── Контрольна сума ───────────────────────────────────────────────────────
    def _run_crc(self):
        if not self._require_data():
            return

        old_cs = _read_u32(self._data, CS_ADDR)
        old_ch = _read_u32(self._data, CH_ADDR)
        self._set_status("Розрахунок CRC32…", "info")
        self.update()

        new_cs, new_ch = fix_checksums(self._data)
        self._refresh_crc_display()

        parts = []
        if new_cs != old_cs:
            parts.append(f"CS: 0x{old_cs:08X} → 0x{new_cs:08X}")
        if new_ch != old_ch:
            parts.append(f"CH: 0x{old_ch:08X} → 0x{new_ch:08X}")
        msg = ("Контрольні суми вже вірні." if not parts
               else "Оновлено: " + "   ".join(parts))

        out_path = self._out_path.get().strip()
        if out_path:
            try:
                with open(out_path, "wb") as fh:
                    fh.write(self._data)
                msg += f"   →  Збережено: {os.path.basename(out_path)}"
            except OSError as e:
                messagebox.showerror("Помилка запису", str(e))
                return

        self._crc_msg.set(msg)
        self._set_status(f"✔ CRC32: {msg}", "ok")

    # ── Аудит ────────────────────────────────────────────────────────────────
    def _run_audit(self):
        path_a = self._audit_a.get().strip()
        path_b = self._audit_b.get().strip()
        if not path_a or not path_b:
            messagebox.showwarning("Увага", "Оберіть обидва файли для порівняння.")
            return
        try:
            with open(path_a, "rb") as fh:
                data_a = fh.read()
            with open(path_b, "rb") as fh:
                data_b = fh.read()
        except OSError as e:
            messagebox.showerror("Помилка читання", str(e))
            return

        self._set_status("Порівняння файлів…", "info")
        self.update()

        txt = self._audit_txt
        txt.config(state="normal")
        txt.delete("1.0", "end")

        n = min(len(data_a), len(data_b))
        diffs = [(i, data_a[i], data_b[i]) for i in range(n) if data_a[i] != data_b[i]]

        txt.insert("end",
            f"A: {os.path.basename(path_a)}\n"
            f"B: {os.path.basename(path_b)}\n"
            f"Всього відмінних байт: {len(diffs)}\n"
            + "─" * 68 + "\n", "header")

        # Групування в суцільні блоки
        runs = []
        if diffs:
            rs, prev, run = diffs[0][0], diffs[0][0], [diffs[0]]
            for addr, a, b in diffs[1:]:
                if addr == prev + 1:
                    run.append((addr, a, b))
                else:
                    runs.append((rs, run))
                    rs, run = addr, [(addr, a, b)]
                prev = addr
            runs.append((rs, run))

        n_known = n_unknown = 0
        for run_start, run in runs:
            run_end   = run[-1][0] + 1
            length    = len(run)
            cat       = _classify_addr(run_start)
            all_known = all(_classify_addr(a) is not None for a, _, _ in run)
            tag       = "known" if all_known else "unknown"
            icon      = "✅" if all_known else "❌"
            if all_known:
                n_known += 1
            else:
                n_unknown += 1

            txt.insert("end",
                f"{icon} 0x{run_start:06X}–0x{run_end:06X}"
                f"  ({length} байт)  [{cat or '*** НЕВІДОМО ***'}]\n", tag)

            show = run if length <= 16 else run[:6] + [None] + run[-4:]
            for item in show:
                if item is None:
                    txt.insert("end",
                        f"   ... ({length - 10} байт пропущено) ...\n", tag)
                    continue
                addr, a, b = item
                txt.insert("end", f"   0x{addr:06X}:  {a:02X} → {b:02X}\n", tag)

            # Інтерпретація
            note = ""
            if cat and "CS" in cat and length == 4:
                va = struct.unpack_from("<I", bytes(x for _, x, _ in run))[0]
                vb = struct.unpack_from("<I", bytes(x for _, _, x in run))[0]
                note = f"   Калібрувальна CS: 0x{va:08X} → 0x{vb:08X}\n"
            elif cat and "CH" in cat and length == 4:
                va = struct.unpack_from("<I", bytes(x for _, x, _ in run))[0]
                vb = struct.unpack_from("<I", bytes(x for _, _, x in run))[0]
                note = f"   Code hash CH: 0x{va:08X} → 0x{vb:08X}\n"
            elif cat and "TPROT" in cat:
                note = "   TPROT: 0x00001001 → 0x00001000 (захист знято)\n"
            elif cat and "EGR" in cat:
                zeros = all(b == 0 for _, _, b in run)
                note = f"   EGR → {'нулі (відключено)' if zeros else '⚠ несподіване значення!'}\n"
            elif cat and "threshold" in cat.lower():
                ffff = all(b == 0xFF for _, _, b in run)
                note = f"   Пороги → {'0xFF (DTC відключено)' if ffff else '⚠ несподіване значення!'}\n"
            elif cat and any(x in cat for x in ("P2264", "P2269")):
                zeros = all(b == 0 for _, _, b in run)
                note = f"   Прапорець → {'0x00 (відключено)' if zeros else '⚠ несподіване!'}\n"
            elif not all_known:
                note = "   ❌ НЕВІДОМА ЗМІНА — потребує перевірки!\n"
            if note:
                txt.insert("end", note, tag)
            txt.insert("end", "\n")

        txt.insert("end", "─" * 68 + "\n", "summary")
        txt.insert("end",
            f"ПІДСУМОК: {len(runs)} блоків  |  "
            f"✅ Очікуваних: {n_known}  |  ❌ Несподіваних: {n_unknown}\n", "summary")
        if n_unknown == 0:
            txt.insert("end",
                "✅ Всі зміни відповідають очікуваним. Безпечно заливати в ЕБУ.\n",
                "known")
        else:
            txt.insert("end",
                f"❌ {n_unknown} несподіваних блоків — перевірте перед заливкою!\n",
                "unknown")

        txt.config(state="disabled")
        self._set_status(
            f"Аудит: {len(runs)} блоків змін, {len(diffs)} байт", "ok")

    # ── Статус ───────────────────────────────────────────────────────────────
    def _set_status(self, msg: str, kind: str = "ok"):
        self._status.set(msg)
        self._status_lbl.config(fg={"ok": "#007700", "info": "#1a6bbf",
                                    "err": "#cc0000"}.get(kind, "#444"))

    # ── Центрування вікна ─────────────────────────────────────────────────────
    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")


# ─── Довідкові тексти ────────────────────────────────────────────────────────
_HELP_EGR = """
EGR (Exhaust Gas Recirculation) — рециркуляція вихлопних газів.

• Вимкнути EGR: обнулює калібрувальні карти — двигун перестає
  керувати клапаном EGR.
    Map1: 0x302970 – 0x302B70  (0x200 байт)
    Map2: 0x302BB0 – 0x302DB0  (0x200 байт)

• Вимкнути моніторинг EGR: обнулює блок порогів DTC,
  що запобігає появі помилок P0401/P0404 після відключення EGR.
    Діапазон: 0x302DC4 – 0x302E18  (0x54 байт)
"""

_HELP_DTC = """
DTC (Diagnostic Trouble Codes) — коди несправностей.

• P2495  (0x3032B8–0x30332A → 0xFF) — перевищення температури EGR
• P2264  (0x035DAE → 0x00)           — несправність датчика якості палива
• P2269  (0x03089A, 0x0308FA → 0x00) — вода у паливі (Water-in-Fuel)
• P0403/P0409  (0x3032F4–0x30332A → 0xFF) — клапан EGR

Заповнення порогів значенням 0xFF встановлює їх у максимум,
фактично відключаючи спрацювання відповідних DTC.
"""

_HELP_PROT = """
TPROT — Tuning Protection, захист від несанкціонованого запису.

• TPROT OFF: знімає програмний блок перезапису калібрувань.
    Адреса: 0x300070
    До:     0x00001001  (біт 0 = 1 → захист увімкнено)
    Після:  0x00001000  (біт 0 = 0 → захист знято)

Після зняття захисту ЕБУ дозволяє запис нових калібрувань
через діагностичний інтерфейс (KWP2000/UDS).
"""

if __name__ == "__main__":
    app = EDC17Tool()
    app.mainloop()
