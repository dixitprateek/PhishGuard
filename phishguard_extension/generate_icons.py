"""
Run this once to generate the extension icons.
    pip install Pillow
    python generate_icons.py
"""
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Install Pillow first:  pip install Pillow")
    raise

ICONS_DIR = Path("icons")
ICONS_DIR.mkdir(exist_ok=True)

def make_icon(size: int):
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background circle
    pad = size // 10
    draw.ellipse([pad, pad, size-pad, size-pad], fill=(124, 106, 247, 255))

    # Shield shape (simplified as a rounded rect + triangle top)
    s = size * 0.55
    x0 = (size - s) / 2
    y0 = size * 0.2
    x1 = x0 + s
    y1 = size * 0.82

    draw.rounded_rectangle([x0, y0+(s*0.22), x1, y1],
                            radius=size*0.08,
                            fill=(255, 255, 255, 230))

    # Top arch of shield
    draw.pieslice([x0, y0, x1, y0+(s*0.5)],
                  start=180, end=0, fill=(255, 255, 255, 230))

    # Checkmark
    lw = max(2, size // 16)
    cx, cy = size / 2, size * 0.54
    draw.line([cx - s*0.22, cy, cx - s*0.04, cy + s*0.2,
               cx + s*0.26, cy - s*0.18],
              fill=(124, 106, 247, 255), width=lw, joint="curve")

    path = ICONS_DIR / f"icon{size}.png"
    img.save(path, "PNG")
    print(f"Created {path}")

for sz in (16, 48, 128):
    make_icon(sz)

print("Icons generated in icons/")