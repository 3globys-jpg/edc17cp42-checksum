# ТЗ: Пошук та виправлення контрольної суми EDC17CP42

## Контекст

Є два файли прошивки ЄБУ **Bosch EDC17CP42** (Land Rover Evoque 2.2 TD4, 224DT):

- `original.bin` — оригінальна прошивка, зчитана з ЄБУ, 100% валідна
- `patched.bin` — модифікована прошивка, потребує виправлення контрольної суми

Обидва файли: **4,194,304 байт (4MB)**, формат — повний дамп flash пам'яті.

---

## Ідентифікація ЄБУ

| Параметр | Значення |
|----------|----------|
| ЄБУ | Bosch EDC17CP42 |
| MCU | Infineon TriCore TC1797 |
| SW Number | 1037513068 |
| Calibration variant | P1070G24 |
| Part number LR | BJ32-12B684-VA |
| TPROT version | TPROT_V07.00.02/1767 |
| Flash розмір | 4MB |

---

## Що змінено в patched.bin

Всі зміни виключно в діапазоні `0x302000–0x303500` та `0x300070`:

| Адреса | Опис |
|--------|------|
| `0x302970–0x302B70` | EGR Map 1 занулено (512 байт) |
| `0x302BB0–0x302DB0` | EGR Map 2 занулено (512 байт) |
| `0x302DC4–0x302DCF` | EGR deviation thresholds → 0 |
| `0x302DEC–0x302DF0` | EGR DFC enable flags → 0 |
| `0x302E0E–0x302E18` | EGR monitoring enables → 0 |
| `0x30288C–0x30288E` | EGR monitoring enable → 0 |
| `0x302900–0x302904` | EGR monitoring enable → 0 |
| `0x3032B8–0x3032CE` | P2495 coolant thresholds → 0xFFFF |
| `0x3032F4–0x303302` | P2495 thresholds → 0xFFFF |
| `0x303308–0x30332A` | P0403/P0409 thresholds → 0xFFFF |
| `0x035DAE` | P2264 DTC enable flag → 0x0000 |
| `0x03089A` | P2269 DTC index → 0x0000 |
| `0x0308FA` | P2269 threshold pointer → 0x0000 |
| `0x300070` | TPROT flag: `0x00001001` → `0x00001000` |

**Загалом змінено: 582 байти з 4,194,304**

---

## Структура flash файлу

```
0x000000 - 0x003FFF  : порожньо (нулі)
0x004000 - 0x01BFFF  : Код блок 1 (TriCore TC1797 машинний код)
0x01C000 - 0x1BFFFF  : Код блок 2 (основний код)
0x1C0000 - 0x1FFFFF  : порожньо
0x200000 - 0x208FFF  : малий блок даних
0x209000 - 0x2FFFFF  : порожньо
0x300000 - 0x3E0FFF  : КАЛІБРУВАННЯ (наші зміни тут)
0x3E1000 - 0x3FEFBF  : заповнено 0xC3 (TriCore NOP)
0x3FEFC0 - 0x3FEFFF  : RSA підпис (64 байти)
0x3FF000 - 0x3FFFFF  : порожньо (нулі)
```

---

## Калібраційний заголовок (0x300000)

```
0x300000: 60 00 00 00                    - magic
0x300008: 00 f0 0f 00                    - ?
0x30000C: fc ef 3f 80                    - mapped end addr (0x803FEFFC)
0x300018: "1037513068"                   - SW number ASCII
0x300022: "P1070G24"                     - variant ASCII
0x300030: ab 9e 3a 6f                    - CHECKSUM WORD (калібрування?)
0x300034: 60 04 00 00                    - розмір калібрування
0x300038: 00 00 30 80                    - mapped start (0x80300000)
0x30003C: fb ef 3f 80                    - mapped end (0x803FEFFB)
0x300040: FADECAFE CAFEAFFE              - Bosch block marker 1
0x300048: 74 fe 1b 80                    - код start addr
0x30004C: 70 ef 3f 80                    - код end addr
0x300050: 00 10 00 00                    - flags (TPROT=0)
0x300054: 61 04 04 00                    - version/size
0x300058: a8 05 30 80                    - cal start mapped
0x30005C: 3f 2e 30 80                    - cal end mapped
0x300060: FADECAFE CAFEAFFE              - Bosch block marker 2
0x300070: 00 10 00 00                    - TPROT flag (після патча: OFF)
0x300074: d7 95 83 dd                    - hash коду
```

---

## Що потрібно зробити

### Завдання 1 — Реверс алгоритму контрольної суми

1. Встанови `capstone` (дизасемблер TriCore):
```bash
pip install capstone
```

2. Дизасемблюй код в районі перевірки суми.  
   Відома точка входу TPROT: рядок `"TPROT_V07.00.02/1767"` знаходиться за адресою `0x0171F8` у файлі.  
   Функція перевірки знаходиться поруч — шукай в діапазоні `0x017100–0x017400`.

3. Знайди функцію що:
   - Читає діапазон калібрування (`0x300000–0x3E0FFF` або підмножину)
   - Рахує суму/хеш
   - Порівнює зі збереженим значенням (кандидат: `0x300030 = ab 9e 3a 6f`)

4. Якщо capstone не підтримує TriCore — спробуй `radare2`:
```bash
r2 -a tricore original.bin
```
або використай Ghidra з плагіном TriCore.

### Завдання 2 — Перевірити кандидата контрольної суми

Перевір чи `0x300030` (значення `0x6f3a9eab`) є контрольною сумою калібрування:

```python
import struct

with open('original.bin', 'rb') as f:
    data = f.read()

# Спробуй різні алгоритми над калібруванням
cal = data[0x300000:0x3E1000]  # або інший діапазон

# Варіант 1: простий XOR 32-bit
xor32 = 0
for i in range(0, len(cal), 4):
    xor32 ^= struct.unpack_from('<I', cal, i)[0]

# Варіант 2: сума 32-bit слів
sum32 = sum(struct.unpack_from('<I', cal, i)[0] for i in range(0, len(cal), 4)) & 0xFFFFFFFF

# Варіант 3: сума байт
sum8 = sum(cal) & 0xFFFFFFFF

# Варіант 4: доповнення (щоб сума = 0)
# checksum_word = (-sum32) & 0xFFFFFFFF

stored = struct.unpack_from('<I', data, 0x300030)[0]
print(f"Stored at 0x300030: 0x{stored:08x}")
print(f"XOR32: 0x{xor32:08x}")
print(f"Sum32: 0x{sum32:08x}")
print(f"Sum8:  0x{sum8:08x}")
```

Якщо жоден не збігається — спробуй різні діапазони:
- `0x300034–0x3E0FFF` (виключаючи сам заголовок)
- `0x300040–0x3E0FFF`
- `0x300058–0x3E0FFF`

### Завдання 3 — Виправити суму в patched.bin

Після знаходження алгоритму:

```python
with open('original.bin', 'rb') as f:
    orig = bytearray(f.read())
with open('patched.bin', 'rb') as f:
    patched = bytearray(f.read())

# Обчисли нову суму для patched діапазону
new_checksum = compute_checksum(patched[start:end])

# Запиши в те саме місце де була оригінальна
struct.pack_into('<I', patched, 0x300030, new_checksum)  # або інша адреса

with open('patched_fixed.bin', 'wb') as f:
    f.write(patched)
```

### Завдання 4 — Перевірити RSA підпис

Перевір вміст блоку `0x3FEFC0–0x3FEFFF` (64 байти):

```python
sig = data[0x3FEFC0:0x3FF000]
print(sig.hex())
# Якщо це RSA — виправити неможливо без приватного ключа Bosch
# Якщо це простий хеш (MD5/SHA1) — можна перерахувати
```

---

## Додаткові підказки

- TriCore TC1797 — **little-endian**, 32-bit RISC архітектура
- Інструкція `LD.W` читає 32-bit слово, `ST.W` записує
- Цикл підрахунку суми буде виглядати як: `ADD`, `LD.W`, `LOOP` або `JNZ`
- Bosch використовує або **просту суму 32-bit слів** або **XOR** — складніші алгоритми рідкісні для калібрування
- Значення `0x6f3a9eab` у `0x300030` і значення `0xdd8395d7` у `0x300074` — два кандидати на зберігання сум

---

## Очікуваний результат

- Визначений алгоритм контрольної суми
- Файл `patched_fixed.bin` з виправленою сумою
- Підтвердження чи RSA підпис (`0x3FEFC0`) потребує окремого інструменту
