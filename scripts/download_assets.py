#!/usr/bin/env python3
"""
scripts/download_assets.py
Automatiza o download de todos os ativos externos (Fontes, Chart.js, Lucide Icons)
para tornar o frontend do GvulStand 100% autossuficiente e offline (Air-Gapped).
"""

import os
import re
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend" / "public"
VENDOR_DIR = FRONTEND_DIR / "vendor"
FONTS_DIR = FRONTEND_DIR / "fonts"
CSS_DIR = FRONTEND_DIR / "css"

CHARTJS_URL = "https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"
LUCIDE_URL = "https://unpkg.com/lucide@0.447.0/dist/umd/lucide.min.js"
GOOGLE_FONTS_URL = (
    "https://fonts.googleapis.com/css2?"
    "family=Inter:wght@300;400;500;600;700;800&"
    "family=JetBrains+Mono:wght@400;500;600;700&"
    "family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&"
    "display=swap"
)

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def download_file(url: str, dest_path: Path):
    print(f"Baixando: {url} -> {dest_path.name}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req) as resp:
        with open(dest_path, "wb") as f:
            f.write(resp.read())

def main():
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    FONTS_DIR.mkdir(parents=True, exist_ok=True)
    CSS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Download Vendor Scripts
    download_file(CHARTJS_URL, VENDOR_DIR / "chart.min.js")
    download_file(LUCIDE_URL, VENDOR_DIR / "lucide.min.js")

    # 2. Download Google Fonts
    print("Obtendo especificações de fontes do Google Fonts...")
    req = urllib.request.Request(GOOGLE_FONTS_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req) as resp:
        css_content = resp.read().decode("utf-8")

    font_urls = list(set(re.findall(r"url\((https://fonts\.gstatic\.com/[^)]+)\)", css_content)))
    print(f"Total de arquivos de fonte encontrados: {len(font_urls)}")

    for u in font_urls:
        parts = u.split("/")
        family = parts[-3] if len(parts) >= 3 else "font"
        filename = f"{family}-{parts[-1]}"
        dest = FONTS_DIR / filename
        if not dest.exists():
            download_file(u, dest)
        css_content = css_content.replace(u, f"/static/fonts/{filename}")

    fonts_css_file = CSS_DIR / "fonts.css"
    with open(fonts_css_file, "w", encoding="utf-8") as f:
        f.write("/* Offline Local Webfonts for GvulStand */\n" + css_content)

    print(f"CSS de fontes salvo em: {fonts_css_file}")
    print("Download de ativos concluído com sucesso!")

if __name__ == "__main__":
    main()
