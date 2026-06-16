"""Generate EDC17CP42 Tool icon — automotive/ECU theme."""
from PIL import Image, ImageDraw, ImageFont
import os

def draw_icon(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size

    # Background — dark gradient-like (single dark fill for ICO compatibility)
    bg = (18, 22, 34)
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=s // 8, fill=bg)

    # Outer glow border
    border_color = (255, 140, 0)  # amber/orange
    bw = max(1, s // 32)
    d.rounded_rectangle([bw, bw, s - 1 - bw, s - 1 - bw],
                        radius=s // 8, outline=border_color, width=bw)

    # Inner circuit board — horizontal lines (PCB trace feel)
    pad = s // 6
    line_color = (40, 60, 100)
    step = max(2, s // 16)
    for y in range(pad + step, s - pad, step * 2):
        d.line([(pad, y), (s - pad, y)], fill=line_color, width=max(1, s // 64))

    # ECU chip rectangle
    chip_pad = s // 4
    chip_color = (30, 35, 55)
    chip_border = (0, 180, 220)  # cyan
    d.rectangle([chip_pad, chip_pad, s - chip_pad, s - chip_pad],
                fill=chip_color, outline=chip_border, width=max(1, s // 48))

    # Chip pins — left side
    pin_w = max(1, s // 24)
    pin_len = max(2, s // 12)
    pin_color = (200, 200, 200)
    num_pins = 4
    pin_spacing = (s - chip_pad * 2) // (num_pins + 1)
    for i in range(1, num_pins + 1):
        py = chip_pad + i * pin_spacing
        d.rectangle([chip_pad - pin_len, py - pin_w,
                     chip_pad, py + pin_w], fill=pin_color)
        d.rectangle([s - chip_pad, py - pin_w,
                     s - chip_pad + pin_len, py + pin_w], fill=pin_color)

    # Text "EDC17" inside chip
    text1 = "EDC17"
    text2 = "CP42"
    font_size1 = max(6, s // 7)
    font_size2 = max(4, s // 10)

    try:
        font1 = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", font_size1)
        font2 = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", font_size2)
    except Exception:
        font1 = ImageFont.load_default()
        font2 = font1

    # Measure and center text1
    bbox1 = d.textbbox((0, 0), text1, font=font1)
    tw1 = bbox1[2] - bbox1[0]
    th1 = bbox1[3] - bbox1[1]
    cx1 = (s - tw1) // 2 - bbox1[0]
    cy1 = s // 2 - th1 - max(1, s // 32)

    # Measure and center text2
    bbox2 = d.textbbox((0, 0), text2, font=font2)
    tw2 = bbox2[2] - bbox2[0]
    cx2 = (s - tw2) // 2 - bbox2[0]
    cy2 = s // 2 + max(1, s // 32)

    # Shadow for legibility
    shadow = (0, 100, 140)
    d.text((cx1 + 1, cy1 + 1), text1, font=font1, fill=shadow)
    d.text((cx1, cy1), text1, font=font1, fill=(255, 200, 0))

    d.text((cx2 + 1, cy2 + 1), text2, font=font2, fill=shadow)
    d.text((cx2, cy2), text2, font=font2, fill=(0, 220, 255))

    # Orange dot accent — top-right corner of chip
    dot_r = max(2, s // 20)
    dot_x = s - chip_pad - dot_r - max(1, s // 32)
    dot_y = chip_pad + dot_r + max(1, s // 32)
    d.ellipse([dot_x - dot_r, dot_y - dot_r,
               dot_x + dot_r, dot_y + dot_r], fill=(255, 80, 0))

    return img


sizes = [16, 24, 32, 48, 64, 128, 256]
frames = [draw_icon(s) for s in sizes]

out = os.path.join(os.path.dirname(__file__), "icon.ico")
frames[0].save(out, format="ICO", sizes=[(s, s) for s in sizes],
               append_images=frames[1:])
print(f"Icon saved: {out}")
