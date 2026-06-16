#!/usr/bin/env python3
"""
Bosch EDC17CP42 - Checksum Fixer GUI
Виправляє контрольну суму Cal CS (0x300030) та Code CH (0x300074).
"""
import struct
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------------------------------------------------------------------------
# CRC32 algorithm (poly=0xEDB88320, reflected)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# EDC17CP42 layout
# ---------------------------------------------------------------------------
FLASH_SIZE   = 0x400000
CAL_START    = 0x300000;  CAL_END  = 0x3FEFFC
CH_START     = 0x1BFE74;  CH_END   = 0x3FEF70
CS_ADDR      = 0x300030
CH_ADDR      = 0x300074
TPROT_ADDR   = 0x300070
MAGIC1_ADDR  = 0x300040
FADECAFE     = 0xFADECAFE
CAL_INIT     = 0x707C3FD7
CH_INIT      = 0x938DE116
CS_REL_CAL   = CS_ADDR - CAL_START   # 0x30
CH_REL_CAL   = CH_ADDR - CAL_START   # 0x74
CS_REL_CH    = CS_ADDR - CH_START    # 0xE01BC
CH_REL_CH    = CH_ADDR - CH_START    # 0xE0200

def _compute_cs(data):
    buf = bytearray(data[CAL_START:CAL_END])
    buf[CS_REL_CAL:CS_REL_CAL+4] = b'\x00'*4
    buf[CH_REL_CAL:CH_REL_CAL+4] = b'\x00'*4
    return _crc32(bytes(buf), CAL_INIT)

def _compute_ch(data):
    buf = bytearray(data[CH_START:CH_END])
    buf[CS_REL_CH:CS_REL_CH+4] = b'\x00'*4
    buf[CH_REL_CH:CH_REL_CH+4] = b'\x00'*4
    return _crc32(bytes(buf), CH_INIT)

def _read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def _write_u32(data, off, val):
    struct.pack_into("<I", data, off, val)

# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EDC17CP42 — Checksum Fixer")
        self.resizable(False, False)
        self._build_ui()
        self._center()

    # ── layout ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        PAD = dict(padx=10, pady=4)

        # ── File selection ──────────────────────────────────────────────────
        frame_files = ttk.LabelFrame(self, text=" Файли ", padding=8)
        frame_files.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 4))
        frame_files.columnconfigure(1, weight=1)

        self._orig_var = tk.StringVar()
        self._mod_var  = tk.StringVar()
        self._out_var  = tk.StringVar()

        rows = [
            ("Оригінальний .bin:",  self._orig_var, self._browse_orig),
            ("Модифікований .bin:", self._mod_var,  self._browse_mod),
            ("Зберегти результат:", self._out_var,  self._browse_out),
        ]
        for r, (lbl, var, cmd) in enumerate(rows):
            ttk.Label(frame_files, text=lbl, width=22, anchor="w").grid(
                row=r, column=0, sticky="w", pady=3)
            e = ttk.Entry(frame_files, textvariable=var, width=52)
            e.grid(row=r, column=1, sticky="ew", padx=(4, 4))
            ttk.Button(frame_files, text="…", width=3, command=cmd).grid(
                row=r, column=2)

        # ── Info table ──────────────────────────────────────────────────────
        frame_info = ttk.LabelFrame(self, text=" Значення контрольних сум ", padding=8)
        frame_info.grid(row=1, column=0, sticky="ew", padx=12, pady=4)

        headers = ["Поле", "Адреса", "До", "Після"]
        col_w   = [18, 10, 14, 14]
        for c, (h, w) in enumerate(zip(headers, col_w)):
            ttk.Label(frame_info, text=h, width=w, anchor="center",
                      font=("Courier", 9, "bold")).grid(row=0, column=c, padx=2)

        self._rows_data = []
        fields = [
            ("Cal CS",  f"0x{CS_ADDR:06X}"),
            ("Code CH", f"0x{CH_ADDR:06X}"),
            ("TPROT",   f"0x{TPROT_ADDR:06X}"),
        ]
        for r, (name, addr) in enumerate(fields, start=1):
            ttk.Label(frame_info, text=name, width=18, anchor="w",
                      font=("Courier", 9)).grid(row=r, column=0, padx=2, pady=1)
            ttk.Label(frame_info, text=addr, width=10, anchor="center",
                      font=("Courier", 9)).grid(row=r, column=1, padx=2)
            v_before = tk.StringVar(value="—")
            v_after  = tk.StringVar(value="—")
            lbl_b = ttk.Label(frame_info, textvariable=v_before, width=14,
                              anchor="center", font=("Courier", 9))
            lbl_a = ttk.Label(frame_info, textvariable=v_after,  width=14,
                              anchor="center", font=("Courier", 9))
            lbl_b.grid(row=r, column=2, padx=2)
            lbl_a.grid(row=r, column=3, padx=2)
            self._rows_data.append((v_before, v_after, lbl_a))

        # ── Progress bar ────────────────────────────────────────────────────
        self._progress = ttk.Progressbar(self, mode="indeterminate", length=400)
        self._progress.grid(row=2, column=0, sticky="ew", padx=12, pady=(4, 0))

        # ── Status line ─────────────────────────────────────────────────────
        self._status_var = tk.StringVar(value="Оберіть файли та натисніть кнопку.")
        status_lbl = tk.Label(self, textvariable=self._status_var,
                              anchor="w", font=("Segoe UI", 9),
                              fg="#555555", bg=self.cget("bg"))
        status_lbl.grid(row=3, column=0, sticky="ew", padx=14, pady=(2, 0))
        self._status_lbl = status_lbl

        # ── Action button ───────────────────────────────────────────────────
        self._btn = ttk.Button(self, text="Розрахувати та зберегти",
                               command=self._run, width=32)
        self._btn.grid(row=4, column=0, pady=(8, 12))

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw-w)//2}+{(sh-h)//2}")

    # ── Browse callbacks ─────────────────────────────────────────────────────
    def _browse_orig(self):
        p = filedialog.askopenfilename(
            title="Оригінальний файл прошивки",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if p:
            self._orig_var.set(p)
            self._maybe_autofill_out()

    def _browse_mod(self):
        p = filedialog.askopenfilename(
            title="Модифікований файл прошивки",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if p:
            self._mod_var.set(p)
            self._maybe_autofill_out()

    def _browse_out(self):
        p = filedialog.asksaveasfilename(
            title="Зберегти виправлений файл",
            defaultextension=".bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if p:
            self._out_var.set(p)

    def _maybe_autofill_out(self):
        if self._out_var.get():
            return
        mod = self._mod_var.get()
        if mod:
            stem = mod[:-4] if mod.lower().endswith(".bin") else mod
            self._out_var.set(stem + "_fixed.bin")

    # ── Status helpers ────────────────────────────────────────────────────────
    def _set_status(self, msg, color="#555555"):
        self._status_var.set(msg)
        self._status_lbl.config(fg=color)

    def _set_cell(self, row, col, val, changed=False):
        var, color = (self._rows_data[row][0], "#333333") if col == 0 \
                else  (self._rows_data[row][1], "#cc0000" if changed else "#007700")
        var.set(val)
        if col == 1:
            self._rows_data[row][2].config(fg=color)

    def _reset_table(self):
        for vb, va, lbl in self._rows_data:
            vb.set("—"); va.set("—"); lbl.config(fg="#333333")

    # ── Main action ───────────────────────────────────────────────────────────
    def _run(self):
        orig_path = self._orig_var.get().strip()
        mod_path  = self._mod_var.get().strip()
        out_path  = self._out_var.get().strip()

        if not orig_path:
            messagebox.showwarning("Увага", "Оберіть оригінальний файл.")
            return
        if not mod_path:
            messagebox.showwarning("Увага", "Оберіть модифікований файл.")
            return
        if not out_path:
            messagebox.showwarning("Увага", "Вкажіть шлях для збереження результату.")
            return

        self._btn.config(state="disabled")
        self._reset_table()
        self._progress.start(12)
        self._set_status("Читання файлів…", "#1a6bbf")
        self.update()

        threading.Thread(target=self._worker,
                         args=(orig_path, mod_path, out_path),
                         daemon=True).start()

    def _worker(self, orig_path, mod_path, out_path):
        def done(msg, color, err=False):
            self._progress.stop()
            self._set_status(msg, color)
            self._btn.config(state="normal")
            if err:
                messagebox.showerror("Помилка", msg)

        # ── read files ────────────────────────────────────────────────────
        try:
            with open(orig_path, "rb") as f:
                orig = f.read()
            with open(mod_path, "rb") as f:
                mod = bytearray(f.read())
        except OSError as e:
            self.after(0, done, f"Помилка читання файлу: {e}", "#cc0000", True)
            return

        for label, data in [("оригінального", orig), ("модифікованого", mod)]:
            if len(data) != FLASH_SIZE:
                self.after(0, done,
                    f"Невірний розмір {label} файлу: {len(data):#x} (очікується {FLASH_SIZE:#x})",
                    "#cc0000", True)
                return

        # ── sanity check ──────────────────────────────────────────────────
        if _read_u32(mod, MAGIC1_ADDR) != FADECAFE:
            self.after(0, done,
                "FADECAFE маркер не знайдено. Перевірте, чи це прошивка EDC17CP42.",
                "#cc0000", True)
            return

        # ── read current values ───────────────────────────────────────────
        old_cs    = _read_u32(mod, CS_ADDR)
        old_ch    = _read_u32(mod, CH_ADDR)
        old_tprot = _read_u32(mod, TPROT_ADDR)

        orig_cs    = _read_u32(orig, CS_ADDR)
        orig_ch    = _read_u32(orig, CH_ADDR)
        orig_tprot = _read_u32(orig, TPROT_ADDR)

        def fill_before():
            self._set_cell(0, 0, f"0x{old_cs:#010x}"[2:])
            self._set_cell(1, 0, f"0x{old_ch:#010x}"[2:])
            self._set_cell(2, 0, f"0x{old_tprot:#010x}"[2:])
        self.after(0, fill_before)
        self.after(0, self._set_status, "Розрахунок CRC32…", "#1a6bbf")

        # ── compute ───────────────────────────────────────────────────────
        new_cs = _compute_cs(mod)
        new_ch = _compute_ch(mod)

        # ── write ─────────────────────────────────────────────────────────
        _write_u32(mod, CS_ADDR, new_cs)
        _write_u32(mod, CH_ADDR, new_ch)

        # ── self-verify ───────────────────────────────────────────────────
        if _compute_cs(mod) != new_cs or _compute_ch(mod) != new_ch:
            self.after(0, done, "Самоперевірка не пройдена — файл не збережено.", "#cc0000", True)
            return

        try:
            with open(out_path, "wb") as f:
                f.write(mod)
        except OSError as e:
            self.after(0, done, f"Помилка запису файлу: {e}", "#cc0000", True)
            return

        # ── fill table ────────────────────────────────────────────────────
        cs_changed    = new_cs    != old_cs
        ch_changed    = new_ch    != old_ch
        tprot_changed = old_tprot != orig_tprot

        def fill_after():
            self._set_cell(0, 1, f"0x{new_cs:#010x}"[2:],    cs_changed)
            self._set_cell(1, 1, f"0x{new_ch:#010x}"[2:],    ch_changed)
            self._set_cell(2, 1, f"0x{old_tprot:#010x}"[2:], tprot_changed)
        self.after(0, fill_after)

        n_changed = sum([cs_changed, ch_changed])
        if n_changed == 0:
            msg = "Контрольні суми вже були правильними. Файл збережено без змін."
            self.after(0, done, msg, "#007700")
        else:
            msg = f"Готово. Оновлено полів: {n_changed}. Збережено: {out_path}"
            self.after(0, done, msg, "#007700")

if __name__ == "__main__":
    app = App()
    app.mainloop()
