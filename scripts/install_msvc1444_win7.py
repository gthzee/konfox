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
#
# NOTE: Microsoft splits Desktop x64/x86 CRT libraries across TWO VSIXs:
#   - `*.CRT.x64.Desktop.base`: static CRT libs (libcmt.lib, libcpmt.lib, libvcruntime.lib)
#   - `*.CRT.x64.Store.base`:   dynamic CRT & core linker libs (oldnames.lib, msvcrt.lib,
#                               msvcprt.lib, vcruntime.lib, delayimp.lib, comsuppw.lib, ...)
# Both extract into `VC/Tools/MSVC/14.44.*/lib/x64/` and BOTH are mandatory!
REQUIRED_PACKAGES = (
    "Microsoft.VC.14.44.17.14.CRT.Headers.base",
    "Microsoft.VC.14.44.17.14.CRT.x64.Desktop.base",
    "Microsoft.VC.14.44.17.14.CRT.x64.Store.base",
    "Microsoft.VC.14.44.17.14.CRT.x86.Desktop.base",
    "Microsoft.VC.14.44.17.14.CRT.x86.Store.base",
    "Microsoft.VC.14.44.17.14.CRT.Redist.X64.base",
    "Microsoft.VC.14.44.17.14.ATL.Headers.base",
    "Microsoft.VC.14.44.17.14.ATL.X64.base",
    "Microsoft.VC.14.44.17.14.ATL.X86.base",
    "Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX64.base",
    "Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX86.base",
    "Microsoft.VC.14.44.17.14.ASAN.Headers.base",
    "Microsoft.VC.14.44.17.14.Props",
    "Microsoft.VC.14.44.17.14.Props.x64",
    "Microsoft.VC.14.44.17.14.Props.ATLMFC",
    "Microsoft.VC.14.44.17.14.Servicing",
    "Microsoft.VC.14.44.17.14.Servicing.CrtHeaders",
    "Microsoft.VC.14.44.17.14.Servicing.ATL",
    "Microsoft.VC.14.44.17.14.Servicing.Compilers",
)

# Critical x64 libraries that MUST exist under VC/Tools/MSVC/14.44.*/lib/x64/
REQUIRED_X64_LIBS = (
    "oldnames.lib",
    "msvcrt.lib",
    "msvcprt.lib",
    "vcruntime.lib",
    "libcmt.lib",
    "libcpmt.lib",
    "libvcruntime.lib",
    "delayimp.lib",
    "comsuppw.lib",
    "concrt.lib",
    "legacy_stdio_definitions.lib",
)

REQUIRED_REDIST_DLLS = (
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140.dll",
    "msvcp140_atomic_wait.dll",
)


def _find_msvc1444_tool_dir(vs_dir: Path) -> Path | None:
    tools_root = vs_dir / "VC" / "Tools" / "MSVC"
    if not tools_root.is_dir():
        return None
    dirs = sorted(p for p in tools_root.iterdir() if p.is_dir())
    if not dirs or not all(p.name.startswith("14.44.") for p in dirs):
        return None
    return dirs[-1]


def _find_msvc1444_crt_dir(vs_dir: Path) -> Path | None:
    redist_root = vs_dir / "VC" / "Redist" / "MSVC"
    if not redist_root.is_dir():
        return None
    dirs = sorted(p for p in redist_root.iterdir() if p.is_dir())
    if not dirs or not all(p.name.startswith("14.44.") for p in dirs):
        return None
    crt_dirs = sorted(dirs[-1].glob("x64/Microsoft.VC*CRT"))
    return crt_dirs[-1] if crt_dirs else None


def is_already_msvc1444(vs_dir: Path) -> bool:
    tool_dir = _find_msvc1444_tool_dir(vs_dir)
    crt_dir = _find_msvc1444_crt_dir(vs_dir)
    if not tool_dir or not crt_dir:
        return False

    lib_x64 = tool_dir / "lib" / "x64"
    if not all((lib_x64 / lib).is_file() for lib in REQUIRED_X64_LIBS):
        return False
    if not (tool_dir / "atlmfc" / "lib" / "x64" / "atls.lib").is_file():
        return False
    if not (tool_dir / "include" / "vector").is_file():
        return False
    if not (tool_dir / "bin" / "Hostx64" / "x64" / "cl.exe").is_file():
        return False
    if not all((crt_dir / dll).is_file() for dll in REQUIRED_REDIST_DLLS):
        return False
    return True


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "Konfox-Win7-Builder/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def resolve_package_urls() -> list[tuple[str, list[str]]]:
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
    found: dict[str, tuple[str, list[str]]] = {}
    for pkg in manifest.get("packages", []):
        pid = pkg.get("id", "")
        key = pid.lower()
        if key in wanted:
            urls = [pl["url"] for pl in pkg.get("payloads", []) if "url" in pl]
            if urls:
                found[key] = (pid, urls)

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


def verify_msvc1444_install(vs_dir: Path) -> None:
    tool_dir = _find_msvc1444_tool_dir(vs_dir)
    if not tool_dir:
        raise RuntimeError(f"MSVC 14.44 toolset directory missing under {vs_dir}/VC/Tools/MSVC")

    lib_x64 = tool_dir / "lib" / "x64"
    missing_libs = [lib for lib in REQUIRED_X64_LIBS if not (lib_x64 / lib).is_file()]
    if missing_libs:
        raise RuntimeError(f"Missing critical MSVC 14.44 x64 libraries in {lib_x64}: {missing_libs}")

    for must_exist in (
        tool_dir / "atlmfc" / "lib" / "x64" / "atls.lib",
        tool_dir / "include" / "vector",
        tool_dir / "include" / "vcruntime.h",
        tool_dir / "atlmfc" / "include" / "atlbase.h",
        tool_dir / "bin" / "Hostx64" / "x64" / "cl.exe",
    ):
        if not must_exist.is_file():
            raise RuntimeError(f"Expected MSVC 14.44 file missing: {must_exist}")

    cl_exe = tool_dir / "bin" / "Hostx64" / "x64" / "cl.exe"
    if not (os.stat(cl_exe).st_mode & 0o111):
        raise RuntimeError(f"cl.exe is not marked executable: {cl_exe}")

    crt_dir = _find_msvc1444_crt_dir(vs_dir)
    if not crt_dir:
        raise RuntimeError(f"Could not find 14.44.*/x64/Microsoft.VC*CRT under {vs_dir}")

    script_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(script_dir))
    import verify_win7_pe as vp  # noqa: E402

    for dll in REQUIRED_REDIST_DLLS:
        path = crt_dir / dll
        if not path.is_file():
            raise RuntimeError(f"Expected redist DLL missing: {path}")
        findings = vp.audit_pe_file(path)
        if findings:
            raise RuntimeError(
                f"MSVC 14.44 redist DLL {path} unexpectedly has Win8+ imports:\n  "
                + "\n  ".join(findings)
            )
    print(
        f"[msvc1444] Verified complete MSVC 14.44 toolset ({tool_dir.name}, "
        f"{len(REQUIRED_X64_LIBS)} core x64 libs) & Win7-clean CRT redist ({crt_dir.name}, 0 findings)."
    )


def install_msvc1444(vs_dir: Path, force: bool = False) -> None:
    if not vs_dir.is_dir():
        raise SystemExit(f"[msvc1444:error] VS sysroot does not exist: {vs_dir}")

    if not force and is_already_msvc1444(vs_dir):
        print(f"[msvc1444] {vs_dir} already has complete Win7-compatible MSVC 14.44 — skipping download.")
        return

    packages = resolve_package_urls()
    vc_dir = vs_dir / "VC"
    staging_root = vs_dir / "_msvc1444_tmp"
    if staging_root.exists():
        shutil.rmtree(staging_root)
    staging_root.mkdir(parents=True)

    try:
        total_files = 0
        for pid, urls in packages:
            for url in urls:
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
    verify_msvc1444_install(vs_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vs_dir", type=Path, help="Path to Mozilla bootstrapped VS sysroot (~/.mozbuild/vs)")
    parser.add_argument("--force", action="store_true", help="Reinstall MSVC 14.44 even if already present")
    args = parser.parse_args()
    install_msvc1444(args.vs_dir.resolve(), force=args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
