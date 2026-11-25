#!/usr/bin/env python3
"""
apply_branding.py — Create browser/branding/konfox inside a Firefox Nightly tree.

Strategy ("Könfox way"):
  1. Start from Mozilla's live `browser/branding/nightly/` directory so we
     automatically inherit all binary icon formats (.ico, .bmp, .png, MSIX
     assets, jar.mn, moz.build) required by the exact Nightly revision.
  2. Overlay our `branding/konfox/` files (configure.sh, branding.nsi,
     brand.ftl, brand.properties, firefox-branding.js, custom SVGs).
  3. Optionally rasterize our custom SVG into PNG/ICO if Pillow or rsvg-convert
     + ImageMagick is available on the build host.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def maybe_rasterize_icons(target_branding: Path) -> None:
    """Best-effort rasterization of about-logo.svg -> about-logo.png / @2x.png."""
    svg = target_branding / "content" / "about-logo.svg"
    if not svg.is_file():
        return

    rsvg = shutil.which("rsvg-convert")
    if not rsvg:
        print(
            "[konfox-branding] rsvg-convert not installed; keeping inherited "
            "Nightly raster PNG/ICO files alongside Könfox SVG logos."
        )
        return

    raster_targets = [
        (target_branding / "content" / "about-logo.png", 192),
        (target_branding / "content" / "about-logo@2x.png", 384),
        (target_branding / "default16.png", 16),
        (target_branding / "default22.png", 22),
        (target_branding / "default24.png", 24),
        (target_branding / "default32.png", 32),
        (target_branding / "default48.png", 48),
        (target_branding / "default64.png", 64),
        (target_branding / "default128.png", 128),
        (target_branding / "default256.png", 256),
    ]
    generated = 0
    for out_png, size in raster_targets:
        if out_png.parent.is_dir():
            subprocess.run(
                [rsvg, "-w", str(size), "-h", str(size), str(svg), "-o", str(out_png)],
                check=True,
            )
            generated += 1

    # Rebuild Windows .ico if ImageMagick `convert` or `magick` is present
    magick = shutil.which("magick") or shutil.which("convert")
    if magick:
        ico_sources = [
            str(target_branding / f"default{s}.png")
            for s in (16, 32, 48, 64, 128, 256)
            if (target_branding / f"default{s}.png").is_file()
        ]
        if ico_sources:
            for ico_name in ("firefox.ico", "firefox64.ico"):
                ico_path = target_branding / ico_name
                if ico_path.exists():
                    subprocess.run([magick, *ico_sources, str(ico_path)], check=True)
            print(f"[konfox-branding] Regenerated Windows .ico files from Könfox SVG.")

    print(f"[konfox-branding] Rasterized {generated} PNG assets from about-logo.svg.")


def apply_branding(firefox_dir: Path, overlay_dir: Path, rasterize: bool = True) -> Path:
    nightly_dir = firefox_dir / "browser" / "branding" / "nightly"
    target_dir = firefox_dir / "browser" / "branding" / "konfox"

    if not nightly_dir.is_dir():
        raise FileNotFoundError(f"Expected Nightly branding at {nightly_dir}")
    if not overlay_dir.is_dir():
        raise FileNotFoundError(f"Expected Könfox overlay at {overlay_dir}")

    if target_dir.exists():
        shutil.rmtree(target_dir)
    shutil.copytree(nightly_dir, target_dir)

    copied = []
    for src in sorted(overlay_dir.rglob("*")):
        if src.is_dir():
            continue
        rel = src.relative_to(overlay_dir)
        dst = target_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(rel.as_posix())

    if rasterize:
        maybe_rasterize_icons(target_dir)

    print(f"[konfox-branding] Created {target_dir} with {len(copied)} overlay file(s):")
    for rel in copied:
        print(f"  - {rel}")
    return target_dir


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Install Könfox Nightly branding into a Firefox source tree."
    )
    parser.add_argument("firefox_dir", type=Path, help="Path to mozilla-firefox/firefox checkout")
    parser.add_argument(
        "--overlay",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "branding" / "konfox",
        help="Path to Könfox branding overlay directory",
    )
    parser.add_argument(
        "--no-rasterize",
        action="store_true",
        help="Do not invoke rsvg-convert/ImageMagick even if installed",
    )
    args = parser.parse_args()
    apply_branding(args.firefox_dir, args.overlay, rasterize=not args.no_rasterize)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
