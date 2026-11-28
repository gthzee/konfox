#!/usr/bin/env python3
"""
apply_branding.py — Create browser/branding/konfox inside a Firefox Nightly tree
and apply Könfox icons across NSIS installer/uninstaller & 7z SFX packaging.

Strategy ("Könfox way"):
  1. Start from Mozilla's live `browser/branding/nightly/` directory so we
     automatically inherit all metadata/build files (jar.mn, moz.build,
     VisualElements manifests, etc.) required by the exact Nightly revision.
  2. Overlay our `branding/konfox/` files:
       - configure.sh, branding.nsi, brand.ftl, brand.properties,
         firefox-branding.js, content/aboutDialog.css, custom wordmarks/SVGs
       - Pre-generated high-res Windows .ico files (firefox.ico, firefox64.ico,
         pbmode.ico for private_browsing.exe, document.ico, document_pdf.ico,
         setup.ico)
       - NSIS installer/uninstaller bitmaps (wizWatermark.bmp, wizHeader.bmp,
         wizHeaderRTL.bmp)
       - High-res PNGs (default*.png, VisualElements_*.png, PrivateBrowsing_*.png,
         content/about-logo*.png, content/about.png)
  3. Install `setup.ico` into `toolkit/mozapps/installer/windows/nsis/setup.ico`
     so `setup.exe`, `uninstall/helper.exe`, and `maintenanceservice_installer.exe`
     use the Könfox icon instead of Firefox Nightly's icon.
  4. Patch `other-licenses/7zstub/firefox/7zSD.Win32.sfx` in-place with our
     Könfox icon (RT_ICON + RT_GROUP_ICON + PE CheckSum) so the packaged
     `konfox-*.installer.exe` outer executable uses the Könfox icon too.
"""

from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
from pathlib import Path


def _parse_ico(ico_bytes: bytes) -> dict[tuple[int, int], tuple[int, int, bytes]]:
    """Parse a Windows .ico file into {(width, height): (planes, bitcount, payload)}."""
    if len(ico_bytes) < 6:
        raise ValueError("ICO file too small")
    reserved, ico_type, count = struct.unpack_from("<HHH", ico_bytes, 0)
    if reserved != 0 or ico_type != 1 or count == 0:
        raise ValueError(f"Invalid ICO header: reserved={reserved} type={ico_type} count={count}")

    entries: dict[tuple[int, int], tuple[int, int, bytes]] = {}
    for i in range(count):
        wb, hb, _colors, _res, planes, bitcount, size, offset = struct.unpack_from(
            "<BBBBHHII", ico_bytes, 6 + i * 16
        )
        w = 256 if wb == 0 else wb
        h = 256 if hb == 0 else hb
        blob = ico_bytes[offset : offset + size]
        if len(blob) != size:
            raise ValueError(f"Truncated ICO entry {w}x{h}")
        entries[(w, h)] = (planes or 1, bitcount or 32, blob)
    return entries


def _compute_pe_checksum(data: bytes | bytearray, checksum_offset: int) -> int:
    """Compute standard Win32 PE CheckSum (same algorithm as imagehlp CheckSumMappedFile)."""
    buf = bytearray(data)
    if checksum_offset + 4 <= len(buf):
        buf[checksum_offset : checksum_offset + 4] = b"\x00\x00\x00\x00"
    if len(buf) % 2:
        buf.append(0)
    acc = 0
    for (word,) in struct.iter_unpack("<H", buf):
        acc += word
        acc = (acc & 0xFFFF) + (acc >> 16)
    acc = (acc & 0xFFFF) + (acc >> 16)
    return (acc + len(data)) & 0xFFFFFFFF


def _walk_rsrc_entries(
    buf: bytes | bytearray, rsrc_off: int, rsrc_rva: int, target_type: int
) -> dict[int, tuple[int, int, int]]:
    """Return {resource_id: (data_entry_file_off, data_file_off, data_size)} for a numeric RT_* type."""
    results: dict[int, tuple[int, int, int]] = {}

    def _dir_entries(rel_off: int) -> list[tuple[int, int]]:
        base = rsrc_off + rel_off
        n_named, n_id = struct.unpack_from("<HH", buf, base + 12)
        out = []
        for idx in range(n_named + n_id):
            name_or_id, data_or_subdir = struct.unpack_from("<II", buf, base + 16 + idx * 8)
            out.append((name_or_id, data_or_subdir))
        return out

    for t_id, t_off in _dir_entries(0):
        if t_id != target_type or not (t_off & 0x80000000):
            continue
        for res_id, name_off in _dir_entries(t_off & 0x7FFFFFFF):
            if res_id & 0x80000000 or not (name_off & 0x80000000):
                continue
            for _lang_id, leaf_off in _dir_entries(name_off & 0x7FFFFFFF):
                if leaf_off & 0x80000000:
                    continue
                entry_off = rsrc_off + leaf_off
                data_rva, data_size = struct.unpack_from("<II", buf, entry_off)
                data_off = rsrc_off + (data_rva - rsrc_rva)
                results[res_id] = (entry_off, data_off, data_size)
                break
    return results


def patch_pe_icon_resources(pe_path: Path, ico_path: Path) -> int:
    """
    Replace RT_ICON & RT_GROUP_ICON resources in-place inside a Windows PE binary
    (such as Mozilla's `other-licenses/7zstub/firefox/7zSD.Win32.sfx`) and update
    the PE OptionalHeader CheckSum.

    Returns the number of RT_ICON slots patched.
    """
    ico_entries = _parse_ico(ico_path.read_bytes())
    buf = bytearray(pe_path.read_bytes())

    if len(buf) < 0x100 or buf[:2] != b"MZ":
        raise ValueError(f"Not a valid PE file: {pe_path}")
    pe_off = struct.unpack_from("<I", buf, 0x3C)[0]
    if buf[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise ValueError(f"Missing PE signature in {pe_path}")

    n_sec = struct.unpack_from("<H", buf, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", buf, pe_off + 20)[0]
    opt_off = pe_off + 24
    checksum_off = opt_off + 64
    sec_off = opt_off + opt_size

    rsrc_rva = rsrc_off = 0
    for i in range(n_sec):
        s_base = sec_off + i * 40
        name = buf[s_base : s_base + 8].rstrip(b"\x00")
        if name == b".rsrc":
            rsrc_rva = struct.unpack_from("<I", buf, s_base + 12)[0]
            rsrc_off = struct.unpack_from("<I", buf, s_base + 20)[0]
            break
    if not rsrc_off:
        raise ValueError(f"No .rsrc section found in {pe_path}")

    rt_icons = _walk_rsrc_entries(buf, rsrc_off, rsrc_rva, target_type=3)
    rt_groups = _walk_rsrc_entries(buf, rsrc_off, rsrc_rva, target_type=14)
    if not rt_icons or not rt_groups:
        raise ValueError(f"No RT_ICON / RT_GROUP_ICON found in {pe_path}")

    patched = 0
    for _grp_id, (_grp_entry_off, grp_data_off, _grp_size) in sorted(rt_groups.items()):
        _res, gtype, gcount = struct.unpack_from("<HHH", buf, grp_data_off)
        if gtype != 1:
            continue
        for idx in range(gcount):
            e_off = grp_data_off + 6 + idx * 14
            wb, hb, _cc, _r, _pl, _bc, _old_bytes, icon_id = struct.unpack_from("<BBBBHHIH", buf, e_off)
            w = 256 if wb == 0 else wb
            h = 256 if hb == 0 else hb
            if (w, h) not in ico_entries or icon_id not in rt_icons:
                continue
            planes, bitcount, new_blob = ico_entries[(w, h)]
            data_entry_off, slot_off, slot_cap = rt_icons[icon_id]
            if len(new_blob) > slot_cap:
                raise ValueError(
                    f"Icon {w}x{h} ({len(new_blob)} bytes) exceeds existing PE RT_ICON #{icon_id} "
                    f"slot capacity ({slot_cap} bytes) in {pe_path}"
                )
            # Write replacement icon data into the existing slot and zero-pad remainder
            buf[slot_off : slot_off + len(new_blob)] = new_blob
            if len(new_blob) < slot_cap:
                buf[slot_off + len(new_blob) : slot_off + slot_cap] = b"\x00" * (slot_cap - len(new_blob))
            # Update IMAGE_RESOURCE_DATA_ENTRY.Size
            struct.pack_into("<I", buf, data_entry_off + 4, len(new_blob))
            # Update GRPICONDIRENTRY metadata & dwBytesInRes
            struct.pack_into("<HHI", buf, e_off + 4, planes, bitcount, len(new_blob))
            patched += 1

    if patched == 0:
        raise ValueError(f"No matching icon sizes patched in {pe_path}")

    new_checksum = _compute_pe_checksum(buf, checksum_off)
    struct.pack_into("<I", buf, checksum_off, new_checksum)
    pe_path.write_bytes(bytes(buf))
    return patched


def maybe_rasterize_icons(target_branding: Path, overlay_files: set[str]) -> None:
    """
    Fallback SVG rasterization ONLY when pre-generated PNG/ICO assets were not
    supplied in the Könfox branding overlay.
    """
    if "firefox.ico" in overlay_files and "default256.png" in overlay_files:
        print(
            "[konfox-branding] Using pre-generated high-res Könfox ICO/PNG/BMP assets "
            "(skipping SVG re-rasterization)."
        )
        return

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
            print("[konfox-branding] Regenerated Windows .ico files from Könfox SVG.")

    print(f"[konfox-branding] Rasterized {generated} PNG assets from about-logo.svg.")


def apply_installer_packaging_icons(firefox_dir: Path, overlay_dir: Path) -> None:
    """
    Replace Firefox Nightly icons used by NSIS setup/uninstaller (`setup.ico`)
    and the 7-Zip SFX packaging stub (`7zSD.Win32.sfx`).
    """
    setup_ico_src = overlay_dir / "setup.ico"
    if not setup_ico_src.is_file():
        setup_ico_src = overlay_dir / "firefox.ico"
    if not setup_ico_src.is_file():
        return

    # 1. NSIS toolkit setup.ico -> controls icon of setup.exe, uninstall/helper.exe,
    #    and maintenanceservice_installer.exe
    nsis_setup_ico = (
        firefox_dir / "toolkit" / "mozapps" / "installer" / "windows" / "nsis" / "setup.ico"
    )
    if nsis_setup_ico.parent.is_dir():
        shutil.copy2(setup_ico_src, nsis_setup_ico)
        print(f"[konfox-branding] Installed Könfox setup icon -> {nsis_setup_ico}")

    # 2. 7z SFX outer installer stub -> controls icon of konfox-*.win64.installer.exe
    for sfx_rel in (
        "other-licenses/7zstub/firefox/7zSD.Win32.sfx",
        "other-licenses/7zstub/firefox/7zSD.ARM64.sfx",
    ):
        sfx_path = firefox_dir / sfx_rel
        if sfx_path.is_file():
            try:
                count = patch_pe_icon_resources(sfx_path, setup_ico_src)
                print(
                    f"[konfox-branding] Patched {count} RT_ICON slot(s) in {sfx_rel} "
                    f"(PE CheckSum updated)"
                )
            except Exception as exc:
                print(f"[konfox-branding] WARNING: failed to patch {sfx_rel}: {exc}")


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
        # setup.ico is installed into toolkit/mozapps/installer/windows/nsis/setup.ico
        # rather than cluttering browser/branding/konfox/
        if rel.as_posix() == "setup.ico":
            continue
        dst = target_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(rel.as_posix())

    if rasterize:
        maybe_rasterize_icons(target_dir, set(copied))

    apply_installer_packaging_icons(firefox_dir, overlay_dir)

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
