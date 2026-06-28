"""
Generate the GitHub social-preview PNG (1280x640) for this repo.

Run from project root:
    source venv/bin/activate
    pip install pillow
    python docs/assets/make_social_preview.py

Output: docs/assets/social-preview.png
Upload via: GitHub → Settings → General → Social preview → Edit → upload.
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).parent / "social-preview.png"

# Layout
W, H = 1280, 640
BG = (12, 14, 20)            # near-black, slight blue tint
INK = (235, 238, 245)        # off-white text
DIM = (140, 150, 165)        # secondary text
ACCENT_RED = (235, 90, 90)   # PWNED / vulnerable
ACCENT_GREEN = (90, 200, 130)  # blocked / defense win
ACCENT_BLUE = (110, 165, 240)  # neutral highlights
GRID = (28, 32, 42)

UBUNTU_MONO_R = "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf"
UBUNTU_MONO_B = "/usr/share/fonts/truetype/ubuntu/UbuntuMono-B.ttf"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    path = UBUNTU_MONO_B if bold else UBUNTU_MONO_R
    return ImageFont.truetype(path, size=size)


def draw_grid(d: ImageDraw.ImageDraw) -> None:
    step = 40
    for x in range(0, W, step):
        d.line([(x, 0), (x, H)], fill=GRID, width=1)
    for y in range(0, H, step):
        d.line([(0, y), (W, y)], fill=GRID, width=1)


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    draw_grid(d)

    # Left accent bar
    d.rectangle([(0, 0), (12, H)], fill=ACCENT_RED)

    # Top tag
    d.text((60, 60), "AI RED TEAM  ·  OWASP LLM TOP 10", font=font(28, bold=True), fill=ACCENT_BLUE)

    # Title
    d.text((60, 110), "vulnerable-ai-agent-lab", font=font(64, bold=True), fill=INK)

    # Subtitle
    d.text(
        (60, 200),
        "Intentionally vulnerable LLM agent.",
        font=font(30),
        fill=INK,
    )
    d.text(
        (60, 240),
        "Prompt injection · RCE · LFI · SSRF · layered defenses, measured.",
        font=font(26),
        fill=DIM,
    )

    # Results card
    card_x, card_y, card_w, card_h = 60, 320, 1160, 230
    d.rounded_rectangle(
        [(card_x, card_y), (card_x + card_w, card_y + card_h)],
        radius=14,
        outline=(60, 70, 90),
        width=2,
    )

    # Card header
    d.text(
        (card_x + 28, card_y + 22),
        "Stack defense — PWNED / total  (3 challenges, lower = better)",
        font=font(22, bold=True),
        fill=DIM,
    )

    # Three-column results
    col1_x = card_x + 28
    col2_x = card_x + 410
    col3_x = card_x + 800

    # Week 1
    d.text((col1_x, card_y + 70), "Wk 1  RCE shell", font=font(24, bold=True), fill=INK)
    d.text((col1_x, card_y + 105), "llama   qwen", font=font(18), fill=DIM)
    d.text((col1_x, card_y + 135), " 2/15    2/15", font=font(26, bold=True), fill=ACCENT_RED)
    d.text((col1_x, card_y + 178), "-85% vs baseline", font=font(18), fill=ACCENT_GREEN)

    # Week 2
    d.text((col2_x, card_y + 70), "Wk 2  LFI file_read", font=font(24, bold=True), fill=INK)
    d.text((col2_x, card_y + 105), "llama   qwen", font=font(18), fill=DIM)
    d.text((col2_x, card_y + 135), " 0/8     0/8", font=font(26, bold=True), fill=ACCENT_GREEN)
    d.text((col2_x, card_y + 178), "-100% path_allowlist", font=font(18), fill=ACCENT_GREEN)

    # Week 3
    d.text((col3_x, card_y + 70), "Wk 3  SSRF http_fetch", font=font(24, bold=True), fill=INK)
    d.text((col3_x, card_y + 105), "llama   qwen", font=font(18), fill=DIM)
    d.text((col3_x, card_y + 135), " 0/8     0/8", font=font(26, bold=True), fill=ACCENT_GREEN)
    d.text((col3_x, card_y + 178), "-100% url_allowlist", font=font(18), fill=ACCENT_GREEN)

    # Footer
    d.text(
        (60, H - 60),
        "github.com/B2TheEe/vulnerable-ai-agent-lab",
        font=font(22, bold=True),
        fill=INK,
    )
    d.text(
        (W - 360, H - 60),
        "Python 3.12  ·  Ollama  ·  MIT",
        font=font(20),
        fill=DIM,
    )

    img.save(OUT, "PNG", optimize=True)
    print(f"wrote {OUT}  ({OUT.stat().st_size // 1024} KB, {W}x{H})")


if __name__ == "__main__":
    main()
