#!/usr/bin/env python3
"""
apply_win7_patches.py — Clean, strictly Windows 7 SP1 x64 patcher for Firefox Nightly.

Why this is cleaner than a 220-patch legacy queue:
  * We target Windows 7 SP1 x64 ONLY — no Windows XP/Vista/32-bit workarounds
    (SRWLOCK, CONDITION_VARIABLE, SetWaitableTimerEx, K32 PSAPI, and Firefox's
    Windows content sandbox all work natively on Win7 SP1 x64!).
  * Built-in surgical Python transforms handle Nightly code drift cleanly
    (idempotent: safe to re-run without double-patching).
  * Automatically updates `.cargo-checksum.json` whenever any vendored crate in
    `third_party/rust/` is patched.
  * Applies any extra `.patch` / `.diff` files listed in `patches/series` at the end.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def update_cargo_checksum(crate_dir: Path, rel_file: str) -> None:
    """Recalculate a modified file's SHA-256 inside `.cargo-checksum.json`."""
    checksum_file = crate_dir / ".cargo-checksum.json"
    if not checksum_file.is_file():
        return
    data = json.loads(checksum_file.read_text(encoding="utf-8"))
    files = data.get("files", {})
    norm = rel_file.replace("\\", "/")
    if norm in files:
        files[norm] = sha256_file(crate_dir / norm)
        checksum_file.write_text(
            json.dumps(data, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# Transform 1: Relax NSIS installer OS version checks from Win10 -> Win7 SP1
# ---------------------------------------------------------------------------
def patch_nsis_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    touched: list[str] = []

    defines_path = firefox_dir / "browser/installer/windows/nsis/defines.nsi.in"
    if defines_path.is_file():
        text = defines_path.read_text(encoding="utf-8")
        new_text = text.replace(
            '!define MinSupportedVer "Microsoft Windows 10 x64"',
            '!define MinSupportedVer "Microsoft Windows 7 SP1 x64"',
        ).replace(
            '!define MinSupportedVer "Microsoft Windows 10"',
            '!define MinSupportedVer "Microsoft Windows 7 SP1"',
        )
        if new_text != text:
            if not dry_run:
                defines_path.write_text(new_text, encoding="utf-8")
            touched.append("browser/installer/windows/nsis/defines.nsi.in")

    nsis_files = [
        "browser/installer/windows/nsis/installer.nsi",
        "browser/installer/windows/nsis/stub.nsh",
        "browser/installer/windows/nsis/maintenanceservice_installer.nsi",
        "toolkit/mozapps/installer/windows/nsis/common.nsh",
        "toolkit/components/maintenanceservice/bootstrapinstaller/maintenanceservice_installer.nsi",
    ]
    for rel in nsis_files:
        p = firefox_dir / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8")
        # Only relax x64/x86 Win10 checks; leave ARM64 (Windows 10+ only) untouched.
        lines = text.splitlines(keepends=True)
        changed = False
        out_lines = []
        for idx, line in enumerate(lines):
            context = "".join(lines[max(0, idx - 3) : idx + 1])
            if "${AtLeastWin10}" in line and "ARM64" not in context and "AArch64" not in context:
                line = line.replace("${AtLeastWin10}", "${AtLeastWin7}")
                changed = True
            out_lines.append(line)
        if changed:
            if not dry_run:
                p.write_text("".join(out_lines), encoding="utf-8")
            touched.append(rel)

    return touched


# ---------------------------------------------------------------------------
# Transform 2: Restore IsWin7OrLater / IsWin8OrLater / IsWin10OrLater helpers
# ---------------------------------------------------------------------------
WINVER_ADDITION = """\
// [Könfox Win7] Restored version helpers for runtime Win7/Win8/Win10 guards.
inline bool IsWindowsVersionOrLater(uint32_t aVersion) {
  static Atomic<uint32_t> minVersion(0);
  static Atomic<uint32_t> maxVersion(UINT32_MAX);

  if (minVersion >= aVersion) {
    return true;
  }
  if (aVersion >= maxVersion) {
    return false;
  }

  OSVERSIONINFOEXW info;
  ZeroMemory(&info, sizeof(OSVERSIONINFOEXW));
  info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
  info.dwMajorVersion = (aVersion & 0xFF000000) >> 24;
  info.dwMinorVersion = (aVersion & 0x00FF0000) >> 16;
  info.wServicePackMajor = (aVersion & 0x0000FF00) >> 8;
  info.wServicePackMinor = (aVersion & 0x000000FF);

  DWORDLONG conditionMask = 0;
  VER_SET_CONDITION(conditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
  VER_SET_CONDITION(conditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
  VER_SET_CONDITION(conditionMask, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
  VER_SET_CONDITION(conditionMask, VER_SERVICEPACKMINOR, VER_GREATER_EQUAL);

  if (VerifyVersionInfoW(&info,
                         VER_MAJORVERSION | VER_MINORVERSION |
                             VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR,
                         conditionMask)) {
    minVersion = aVersion;
    return true;
  }
  maxVersion = aVersion;
  return false;
}

MOZ_ALWAYS_INLINE bool IsWin7SP1OrLater() {
  return IsWindowsVersionOrLater(0x06010100ul);
}

MOZ_ALWAYS_INLINE bool IsWin8OrLater() {
  return IsWindowsVersionOrLater(0x06020000ul);
}

MOZ_ALWAYS_INLINE bool IsWin8Point1OrLater() {
  return IsWindowsVersionOrLater(0x06030000ul);
}

MOZ_ALWAYS_INLINE bool IsWin10OrLater() {
  return IsWindowsVersionOrLater(0x0A000000ul);
}

"""


def patch_windows_version_h(firefox_dir: Path, dry_run: bool) -> list[str]:
    p = firefox_dir / "mfbt/WindowsVersion.h"
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8")
    if "IsWin10OrLater()" in text or "[Könfox Win7]" in text:
        return []
    anchor = "inline bool IsWindows10BuildOrLater(uint32_t aBuild)"
    if anchor not in text:
        return []
    new_text = text.replace(anchor, WINVER_ADDITION + anchor, 1)
    if not dry_run:
        p.write_text(new_text, encoding="utf-8")
    return ["mfbt/WindowsVersion.h"]


# ---------------------------------------------------------------------------
# Transform 3: Dynamically load Win8+ CM_Register_Notification / Unregister
#              in dom/webserial/Win32SerialPlatformService.cpp
# ---------------------------------------------------------------------------
CFGMGR_SHIM_REGISTER = """\
  // [Könfox Win7] CM_Register_Notification requires Windows 8+.
  CONFIGRET cr = CR_CALL_NOT_IMPLEMENTED;
  if (HMODULE cfgmgr = LoadLibraryW(L"CfgMgr32.dll")) {
    using RegisterNotificationFn = CONFIGRET(WINAPI*)(
        PCM_NOTIFY_FILTER, PVOID, PCM_NOTIFY_CALLBACK, PHCMNOTIFICATION);
    if (auto fn = reinterpret_cast<RegisterNotificationFn>(
            GetProcAddress(cfgmgr, "CM_Register_Notification"))) {
      cr = fn(&filter, this, DeviceNotificationCallback, &mDeviceNotification);
    }
    FreeLibrary(cfgmgr);
  }"""

CFGMGR_SHIM_UNREGISTER = """\
  if (mDeviceNotification) {
    // [Könfox Win7] CM_Unregister_Notification requires Windows 8+.
    if (HMODULE cfgmgr = LoadLibraryW(L"CfgMgr32.dll")) {
      using UnregisterNotificationFn = CONFIGRET(WINAPI*)(HCMNOTIFICATION);
      if (auto fn = reinterpret_cast<UnregisterNotificationFn>(
              GetProcAddress(cfgmgr, "CM_Unregister_Notification"))) {
        fn(mDeviceNotification);
      }
      FreeLibrary(cfgmgr);
    }
    mDeviceNotification = nullptr;
  }"""


def patch_webserial_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    p = firefox_dir / "dom/webserial/Win32SerialPlatformService.cpp"
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8")
    if "[Könfox Win7]" in text:
        return []

    re_reg = re.compile(
        r"CONFIGRET\s+cr\s*=\s*CM_Register_Notification\s*\(\s*"
        r"&filter,\s*this,\s*DeviceNotificationCallback,\s*&mDeviceNotification\s*\)\s*;",
        re.MULTILINE,
    )
    re_unreg = re.compile(
        r"if\s*\(\s*mDeviceNotification\s*\)\s*\{\s*"
        r"CM_Unregister_Notification\s*\(\s*mDeviceNotification\s*\)\s*;\s*"
        r"mDeviceNotification\s*=\s*nullptr\s*;\s*\}",
        re.MULTILINE,
    )

    new_text, n1 = re_reg.subn(CFGMGR_SHIM_REGISTER, text, count=1)
    new_text, n2 = re_unreg.subn(CFGMGR_SHIM_UNREGISTER, new_text, count=1)
    if n1 == 0 and n2 == 0:
        return []
    if not dry_run:
        p.write_text(new_text, encoding="utf-8")
    return ["dom/webserial/Win32SerialPlatformService.cpp"]


# ---------------------------------------------------------------------------
# Transform 4: Guard Win8+/10+ APIs in vendored Rust crates + refresh checksums
# ---------------------------------------------------------------------------
def patch_vendored_rust_crates(firefox_dir: Path, dry_run: bool) -> list[str]:
    touched: list[str] = []
    vendor_root = firefox_dir / "third_party/rust"
    if not vendor_root.is_dir():
        return touched

    # 1. `getrandom` v0.3+ ships both `windows.rs` (Win10+ ProcessPrng) and
    #    `windows7.rs` (Win7-safe advapi32 RtlGenRandom/SystemFunction036).
    #    Force `backends.rs` to always select `windows7` on Windows targets
    #    and refresh `.cargo-checksum.json` so Cargo offline verification passes.
    re_getrandom_win7 = re.compile(
        r'all\(\s*windows\s*,\s*any\(\s*target_vendor\s*=\s*"win7"\s*,\s*getrandom_windows_legacy\s*\)\s*\)'
    )
    for crate_dir in sorted(vendor_root.glob("getrandom*")):
        backends_rs = crate_dir / "src/backends.rs"
        if not backends_rs.is_file():
            continue
        text = backends_rs.read_text(encoding="utf-8")
        new_text, count = re_getrandom_win7.subn("windows", text)
        if count > 0 and new_text != text:
            rel = backends_rs.relative_to(firefox_dir).as_posix()
            if not dry_run:
                backends_rs.write_text(new_text, encoding="utf-8")
                update_cargo_checksum(crate_dir, "src/backends.rs")
            touched.append(f"{rel} (+ .cargo-checksum.json)")

    # 2. Scan remaining vendored crates for any other ProcessPrng references.
    for rs_file in sorted(vendor_root.rglob("*.rs")):
        if "getrandom" in rs_file.parts:
            continue
        try:
            text = rs_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        if "bcryptprimitives" in text and "ProcessPrng" in text:
            rel = rs_file.relative_to(firefox_dir).as_posix()
            print(
                f"[konfox-patches] NOTICE: vendored crate references ProcessPrng: {rel} "
                "(check verify_win7_pe.py output after build; add a patch to patches/series if linked)"
            )

    return touched


# ---------------------------------------------------------------------------
# Transform 5: Apply optional ordered git patches from patches/series
# ---------------------------------------------------------------------------
def apply_patch_series(firefox_dir: Path, patches_dir: Path, dry_run: bool) -> list[str]:
    series_file = patches_dir / "series"
    if not series_file.is_file():
        return []

    applied: list[str] = []
    for raw_line in series_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        patch_path = patches_dir / line
        if not patch_path.is_file():
            raise FileNotFoundError(f"Patch listed in series not found: {patch_path}")

        # Check if already applied in reverse
        rev_check = subprocess.run(
            ["git", "-C", str(firefox_dir), "apply", "--reverse", "--check", "--ignore-space-change", str(patch_path)],
            capture_output=True,
            text=True,
        )
        if rev_check.returncode == 0:
            print(f"[konfox-patches] already applied (skipping): {line}")
            continue

        cmd = ["git", "-C", str(firefox_dir), "apply", "--ignore-space-change"]
        if dry_run:
            cmd.append("--check")
        cmd.append(str(patch_path))

        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(
                f"Failed to apply patch {line}:\n{res.stderr.strip()}"
            )
        applied.append(line)

    return applied


def patch_windows_subsystem(firefox_dir: Path, dry_run: bool) -> list[str]:
    """Lower Windows PE subsystem version from 10.0 to 6.01 (Windows 7 SP1).

    Upstream build/moz.configure/windows.configure hardcodes:
        def win32_subsystem_version():
            return "10.0"
    Windows 7 SP1 rejects executables with PE subsystem >= 10.0 as
    "not a valid Win32 application". Setting 6.01 enables launching on
    Windows 7 SP1 and all newer Windows versions.
    """
    win_cfg = firefox_dir / "build/moz.configure/windows.configure"
    if not win_cfg.is_file():
        return []

    original = win_cfg.read_text(encoding="utf-8")
    updated = re.sub(
        r'(def\s+win32_subsystem_version\s*\(\s*\)\s*:\s*\n\s*return\s+)(["\'])10\.0\2',
        r'\g<1>\g<2>6.01\g<2>',
        original,
    )
    if updated != original:
        if not dry_run:
            win_cfg.write_text(updated, encoding="utf-8")
        return ["build/moz.configure/windows.configure"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply Könfox Windows 7 SP1 x64 patches to a Firefox Nightly checkout."
    )
    parser.add_argument("firefox_dir", type=Path, help="Path to mozilla-firefox/firefox checkout")
    parser.add_argument(
        "--patches-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "patches",
        help="Directory containing patches/series and extra .patch/.diff files",
    )
    parser.add_argument("--dry-run", action="store_true", help="Check only; do not write files")
    args = parser.parse_args()

    if not (args.firefox_dir / "mach").is_file():
        raise FileNotFoundError(f"{args.firefox_dir} does not look like a Firefox source tree (missing mach)")

    all_touched: list[str] = []
    for step_name, fn in (
        ("Windows PE subsystem 6.01 (Win7 SP1)", lambda: patch_windows_subsystem(args.firefox_dir, args.dry_run)),
        ("NSIS Win7 installer gate", lambda: patch_nsis_win7(args.firefox_dir, args.dry_run)),
        ("WindowsVersion.h helpers", lambda: patch_windows_version_h(args.firefox_dir, args.dry_run)),
        ("WebSerial CfgMgr32 dynamic load", lambda: patch_webserial_win7(args.firefox_dir, args.dry_run)),
        ("Vendored Rust crate scan", lambda: patch_vendored_rust_crates(args.firefox_dir, args.dry_run)),
        ("patches/series", lambda: apply_patch_series(args.firefox_dir, args.patches_dir, args.dry_run)),
    ):
        touched = fn()
        if touched:
            print(f"[konfox-patches] {step_name}: {len(touched)} change(s)")
            for item in touched:
                print(f"  - {item}")
            all_touched.extend(touched)
        else:
            print(f"[konfox-patches] {step_name}: up to date / no changes needed")

    mode = "DRY-RUN complete" if args.dry_run else "Applied"
    print(f"[konfox-patches] {mode} ({len(all_touched)} total file/patch updates).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
