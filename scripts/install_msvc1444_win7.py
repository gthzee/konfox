#!/usr/bin/env python3
"""
Replace Visual Studio 2026's Win10+-only MSVC 14.5x toolset & CRT redist inside
Mozilla's bootstrapped `~/.mozbuild/vs` sysroot with Visual Studio 2022 17.14
LTSC's MSVC 14.44 toolset & CRT redist — the last MSVC release whose
msvcp140.dll and msvcp140_atomic_wait.dll have zero Windows 8+/10+ static
imports (no CreateFile2, no GetSystemTimePreciseAsFileTime, no
api-ms-win-core-synch-l1-2-0.dll).

Windows Kits/10 (SDK headers & UCRT redist) and DIA SDK inside `~/.mozbuild/vs`
are preserved untouched, `.lib` filenames are lowercased, `.exe` files are
marked executable, and `overlay.yaml` is regenerated identically to Mozilla's
`taskcluster/scripts/misc/get_vs.py`.

Usage:
    python3 scripts/install_msvc1444_win7.py <vs_sysroot_dir> [--force]
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

VS2022_CHANNEL_URL = "https://aka.ms/vs/17/release/channel"

# Exact VS 2022 17.14 LTSC (MSVC 14.44) packages needed to cross-compile
# Firefox x86_64-pc-windows-msvc with clang-cl + lld-link and ship Win7-clean
# MSVC CRT redistributables.
REQUIRED_PACKAGES = (
    "Microsoft.VC.14.44.17.14.CRT.Headers.base",
    "Microsoft.VC.14.44.17.14.CRT.x64.Desktop.base",
    "Microsoft.VC.14.44.17.14.CRT.x86.Desktop.base",
    "Microsoft.VC.14.44.17.14.CRT.Redist.X64.base",
    "Microsoft.VC.14.44.17.14.ATL.Headers.base",
    "Microsoft.VC.14.44.17.14.ATL.X64.base",
    "Microsoft.VC.14.44.17.14.ATL.X86.base",
    "Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX64.base",
    "Microsoft.VC.14.44.17.14.ASAN.Headers.base",
)


def is_already_msvc1444(vs_dir: Path) -> bool:
    tools_root = vs_dir / "VC" / "Tools" / "MSVC"
    redist_root = vs_dir / "VC" / "Redist" / "MSVC"
    if not tools_root.is_dir() or not redist_root.is_dir():
        return False
    tool_vers = [p.name for p in tools_root.iterdir() if p.is_dir()]
    redist_vers = [p.name for p in redist_root.iterdir() if p.is_dir()]
    if not tool_vers or not redist_vers:
        return False
    return (
        all(v.startswith("14.44.") for v in tool_vers)
        and all(v.startswith("14.44.") for v in redist_vers)
    )


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "Konfox-Win7-Builder/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def resolve_package_urls() -> list[tuple[str, str]]:
    print(f"[msvc1444] Fetching VS 2022 channel manifest from {VS2022_CHANNEL_URL} ...")
    channel = fetch_json(VS2022_CHANNEL_URL)
    vsman_url = None
    for item in channel.get("channelItems", []):
        if item.get("id") == "Microsoft.VisualStudio.Manifests.VisualStudio":
            payloads = item.get("payloads", [])
            if payloads:
                vsman_url = payloads[0]["url"]
                break
    if not vsman_url:
        raise RuntimeError("Could not locate VisualStudio.vsman URL in VS 2022 channel manifest.")

    manifest = fetch_json(vsman_url)
    wanted = {pid.lower(): pid for pid in REQUIRED_PACKAGES}
    found: dict[str, tuple[str, str]] = {}
    for pkg in manifest.get("packages", []):
        pid = pkg.get("id", "")
        key = pid.lower()
        if key in wanted:
            payloads = pkg.get("payloads", [])
            if payloads:
                found[key] = (pid, payloads[0]["url"])

    missing = [orig for low, orig in wanted.items() if low not in found]
    if missing:
        raise RuntimeError(f"Missing required MSVC 14.44 packages in VS 2022 manifest: {missing}")

    return [found[pid.lower()] for pid in REQUIRED_PACKAGES]


def extract_vc_vsix(vsix_bytes: bytes, vs_dir: Path) -> int:
    count = 0
    with zipfile.ZipFile(io.BytesIO(vsix_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = urllib.parse.unquote(info.filename).replace("\\", "/")
            if not name.startswith("Contents/VC/"):
                continue
            rel = name[len("Contents/"):]
            parts = rel.split("/")
            fname = parts[-1]
            lower_f = fname.lower()
            # Match Mozilla's taskcluster/scripts/misc/get_vs.py conventions:
            # lowercase .lib files for case-sensitive Linux filesystems and
            # mark .exe files executable so moz.configure find_program succeeds.
            if lower_f.endswith(".lib"):
                parts[-1] = lower_f
            out_path = vs_dir.joinpath(*parts)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, out_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            if lower_f.endswith(".exe"):
                os.chmod(out_path, 0o755)
            count += 1
    return count


def regenerate_overlay_yaml(vs_dir: Path) -> Path:
    """Rebuild clang -ivfsoverlay case-insensitive overlay.yaml across VC, Windows Kits/10, DIA SDK."""
    vfs: dict[str, list[str]] = {}
    for subpath in ("VC", "Windows Kits/10", "DIA SDK"):
        base = vs_dir / subpath
        if not base.is_dir():
            continue
        for root, _dirs, files in os.walk(base):
            rel = Path(root).relative_to(vs_dir).as_posix()
            for f in files:
                if f.lower().endswith((".h", ".idl")):
                    vfs.setdefault(rel, []).append(f)

    # Clang's -ivfsoverlay accepts JSON natively (valid YAML 1.2) and requires no PyYAML dependency.
    overlay = {
        "version": 0,
        "case-sensitive": False,
        "root-relative": "overlay-dir",
        "overlay-relative": True,
        "roots": [
            {
                "name": p,
                "type": "directory",
                "contents": [
                    {
                        "name": f,
                        "type": "file",
                        "external-contents": f"{p}/{f}",
                    }
                    for f in sorted(files)
                ],
            }
            for p, files in sorted(vfs.items())
        ],
    }
    overlay_path = vs_dir / "overlay.yaml"
    overlay_path.write_text(json.dumps(overlay, indent=2) + "\n", encoding="utf-8")
    return overlay_path


def verify_redist_dlls(vs_dir: Path) -> None:
    script_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(script_dir))
    import verify_win7_pe as vp  # noqa: E402

    redist_matches = sorted((vs_dir / "VC" / "Redist" / "MSVC").glob("14.44.*/x64/Microsoft.VC143.CRT"))
    if not redist_matches:
        raise RuntimeError(f"Could not find 14.44.*/x64/Microsoft.VC143.CRT under {vs_dir}")
    crt_dir = redist_matches[-1]
    required = ("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "msvcp140_atomic_wait.dll")
    for dll in required:
        path = crt_dir / dll
        if not path.is_file():
            raise RuntimeError(f"Expected redist DLL missing: {path}")
        findings = vp.audit_pe_file(path)
        if findings:
            raise RuntimeError(
                f"MSVC 14.44 redist DLL {path} unexpectedly has Win8+ imports:\n  "
                + "\n  ".join(findings)
            )
    print(f"[msvc1444] Verified Win7-clean CRT redist DLLs in {crt_dir} (0 findings).")


def install_msvc1444(vs_dir: Path, force: bool = False) -> None:
    if not vs_dir.is_dir():
        raise SystemExit(f"[msvc1444:error] VS sysroot does not exist: {vs_dir}")

    if not force and is_already_msvc1444(vs_dir):
        print(f"[msvc1444] {vs_dir} already uses Win7-compatible MSVC 14.44 — skipping download.")
        return

    packages = resolve_package_urls()
    vc_dir = vs_dir / "VC"
    staging_vc = vs_dir / "VC.msvc1444.staging"
    if staging_vc.exists():
        shutil.rmtree(staging_vc)
    staging_root = staging_vc.parent / "_msvc1444_tmp"
    if staging_root.exists():
        shutil.rmtree(staging_root)
    staging_root.mkdir(parents=True)

    try:
        total_files = 0
        for pid, url in packages:
            print(f"[msvc1444] Downloading {pid} ...")
            req = urllib.request.Request(url, headers={"User-Agent": "Konfox-Win7-Builder/1.0"})
            with urllib.request.urlopen(req, timeout=180) as resp:
                data = resp.read()
            extracted = extract_vc_vsix(data, staging_root)
            total_files += extracted
            print(f"  extracted {extracted} files ({len(data) / 1048576:.1f} MiB)")

        if not (staging_root / "VC" / "Tools" / "MSVC").is_dir():
            raise RuntimeError("Staging extraction did not produce VC/Tools/MSVC")

        if vc_dir.exists():
            shutil.rmtree(vc_dir)
        shutil.move(str(staging_root / "VC"), str(vc_dir))
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root)

    overlay_path = regenerate_overlay_yaml(vs_dir)
    print(f"[msvc1444] Installed MSVC 14.44 ({total_files} files) and rebuilt {overlay_path}")
    verify_redist_dlls(vs_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vs_dir", type=Path, help="Path to Mozilla bootstrapped VS sysroot (~/.mozbuild/vs)")
    parser.add_argument("--force", action="store_true", help="Reinstall MSVC 14.44 even if already present")
    args = parser.parse_args()
    install_msvc1444(args.vs_dir.resolve(), force=args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
