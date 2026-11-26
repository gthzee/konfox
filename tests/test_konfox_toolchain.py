#!/usr/bin/env python3
"""
test_konfox_toolchain.py — End-to-end self-test suite for the Könfox build toolkit.

Verifies:
  1. scripts/patch_rust_win7.py (rewriting win7 vendor cfg predicates safely & idempotently)
  2. scripts/apply_branding.py (Könfox Nightly branding overlay inheritance & overrides)
  3. scripts/apply_win7_patches.py (NSIS Win7 gate, ARM64 preservation, WindowsVersion.h,
     WebSerial CfgMgr32 dynamic loading, Cargo checksum hashing, idempotency)
  4. scripts/verify_win7_pe.py (real synthetic PE32+ x64 binary import parsing — both
     Win7-clean PASS and Win10-polluted FAIL cases)
"""

from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import apply_branding
import apply_win7_patches
import patch_rust_win7
import verify_win7_pe


def build_synthetic_pe64(imports: list[tuple[str, list[str]]]) -> bytes:
    """Construct a minimal valid PE32+ (x64) binary with a real .rdata Import Table."""
    # DOS header (64 bytes) with e_lfanew = 0x80
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    # PE signature + COFF header (20 bytes) + Optional header PE32+ (240 bytes) + 1 section (40 bytes)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)

    rdata_rva = 0x2000
    rdata_raw = 0x400

    # Build .rdata import descriptors, ILTs, DLL names, and Hint/Name entries
    num_dlls = len(imports)
    desc_size = (num_dlls + 1) * 20
    cursor = desc_size
    ilt_offsets: list[int] = []
    for _, funcs in imports:
        ilt_offsets.append(cursor)
        cursor += (len(funcs) + 1) * 8

    dll_name_offsets: list[int] = []
    strings_blob = bytearray()
    for dll, _ in imports:
        dll_name_offsets.append(cursor + len(strings_blob))
        strings_blob.extend(dll.encode("ascii") + b"\x00")

    hint_name_offsets: list[list[int]] = []
    for _, funcs in imports:
        fn_offs: list[int] = []
        for fn in funcs:
            if len(strings_blob) % 2:
                strings_blob.append(0)
            fn_offs.append(cursor + len(strings_blob))
            strings_blob.extend(b"\x00\x00" + fn.encode("ascii") + b"\x00")
        hint_name_offsets.append(fn_offs)

    rdata = bytearray(cursor + len(strings_blob))
    for idx, (_, funcs) in enumerate(imports):
        ilt_rva = rdata_rva + ilt_offsets[idx]
        name_rva = rdata_rva + dll_name_offsets[idx]
        struct.pack_into("<IIIII", rdata, idx * 20, ilt_rva, 0, 0, name_rva, ilt_rva)
        for f_idx, hn_off in enumerate(hint_name_offsets[idx]):
            struct.pack_into("<Q", rdata, ilt_offsets[idx] + f_idx * 8, rdata_rva + hn_off)
    rdata[cursor:] = strings_blob

    # Pad .rdata to 0x200 boundary
    if len(rdata) % 0x200:
        rdata.extend(b"\x00" * (0x200 - (len(rdata) % 0x200)))

    # Optional Header (PE32+ = 240 bytes: 112 fixed + 16*8 data directories)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)  # PE32+
    struct.pack_into("<I", opt, 108, 16)   # NumberOfRvaAndSizes
    # Data Directory[1] = Import Table (RVA, Size)
    struct.pack_into("<II", opt, 112 + 1 * 8, rdata_rva, desc_size)

    # Section header for .rdata
    sec = bytearray(40)
    sec[0:6] = b".rdata"
    struct.pack_into("<IIII", sec, 8, len(rdata), rdata_rva, len(rdata), rdata_raw)

    headers = bytes(dos) + pe_sig + coff + bytes(opt) + bytes(sec)
    assert len(headers) <= rdata_raw
    return headers + b"\x00" * (rdata_raw - len(headers)) + bytes(rdata)


class KonfoxToolchainTests(unittest.TestCase):
    def test_rust_win7_patcher_and_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rust = Path(tmp) / "rust"
            (rust / "library/std/src/sys/pal/windows").mkdir(parents=True)
            (rust / "library/std/src/sys/random").mkdir(parents=True)
            (rust / "library/std/src/sys/sync/mutex").mkdir(parents=True)
            (rust / "library/std/src/sys/sync/thread_parking").mkdir(parents=True)
            (rust / "library/windows_targets/src").mkdir(parents=True)
            (rust / "library/backtrace/src/symbolize").mkdir(parents=True)

            (rust / "library/std/src/sys/pal/windows/c.rs").write_text(
                '#[cfg(not(target_vendor = "win7"))]\n'
                'extern "system" { pub fn ProcessPrng(); }\n'
                '#[cfg(target_vendor = "win7")]\n'
                'compat_fn_optional! { pub fn WaitOnAddress(); }\n',
                encoding="utf-8",
            )
            (rust / "library/std/src/sys/random/windows.rs").write_text(
                '#[cfg(not(target_vendor = "win7"))]\n'
                'pub fn fill_bytes() {}\n'
                '#[cfg(target_vendor = "win7")]\n'
                'pub fn fill_bytes() {}\n',
                encoding="utf-8",
            )
            (rust / "library/std/src/sys/sync/mutex/mod.rs").write_text(
                'cfg_select! {\n'
                '  any(all(target_os = "windows", not(target_vendor="win7")), target_os = "linux") => {}\n'
                '  all(target_os = "windows", target_vendor = "win7") => { mod windows7; }\n'
                '}\n',
                encoding="utf-8",
            )
            (rust / "library/std/src/sys/sync/thread_parking/mod.rs").write_text(
                'cfg_select! {\n'
                '  target_vendor = "win7" => { mod windows7; }\n'
                '}\n',
                encoding="utf-8",
            )
            (rust / "library/windows_targets/src/lib.rs").write_text(
                '#[cfg_attr(target_vendor = "win7", link(name = "advapi32"))]\n',
                encoding="utf-8",
            )
            (rust / "library/backtrace/src/symbolize/dbghelp.rs").write_text(
                '#[cfg(not(target_vendor = "win7"))]\nfn a() {}\n'
                '#[cfg(target_vendor = "win7")]\nfn b() {}\n',
                encoding="utf-8",
            )

            changes = patch_rust_win7.patch_rust_tree(rust)
            self.assertEqual(len(changes), 6)

            c_rs = (rust / "library/std/src/sys/pal/windows/c.rs").read_text(encoding="utf-8")
            self.assertIn('#[cfg(not(target_os = "windows"))]', c_rs)
            self.assertIn('#[cfg(target_os = "windows")]', c_rs)
            self.assertNotIn("win7", c_rs)

            park = (rust / "library/std/src/sys/sync/thread_parking/mod.rs").read_text(encoding="utf-8")
            self.assertIn('target_os = "windows" => { mod windows7; }', park)

            wt = (rust / "library/windows_targets/src/lib.rs").read_text(encoding="utf-8")
            self.assertIn('#[cfg_attr(target_os = "windows", link(name = "advapi32"))]', wt)

            # Second run must be a no-op
            changes_second = patch_rust_win7.patch_rust_tree(rust)
            self.assertEqual(changes_second, {})

    def test_branding_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ff = Path(tmp) / "firefox"
            nightly = ff / "browser/branding/nightly"
            (nightly / "content").mkdir(parents=True)
            (nightly / "locales/en-US").mkdir(parents=True)
            (nightly / "pref").mkdir(parents=True)
            (nightly / "moz.build").write_text("FirefoxBranding()\n", encoding="utf-8")
            (nightly / "firefox.ico").write_bytes(b"FAKEICO")
            (nightly / "configure.sh").write_text('MOZ_APP_DISPLAYNAME="Firefox Nightly"\n', encoding="utf-8")

            out = apply_branding.apply_branding(ff, ROOT / "branding/konfox", rasterize=False)
            self.assertTrue((out / "moz.build").is_file())
            self.assertTrue((out / "firefox.ico").is_file())
            self.assertIn("Könfox Nightly", (out / "configure.sh").read_text(encoding="utf-8"))
            self.assertIn('pref("app.update.enabled", false);', (out / "pref/firefox-branding.js").read_text(encoding="utf-8"))
            self.assertIn("-brand-shorter-name = Könfox", (out / "locales/en-US/brand.ftl").read_text(encoding="utf-8"))
            self.assertTrue((out / "content/about-logo.svg").is_file())

    def test_win7_patches_and_checksum_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ff = Path(tmp) / "firefox"
            (ff / "browser/installer/windows/nsis").mkdir(parents=True)
            (ff / "build/moz.configure").mkdir(parents=True)
            (ff / "mach").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            (ff / "mfbt").mkdir(parents=True)
            (ff / "dom/webserial").mkdir(parents=True)

            (ff / "build/moz.configure/windows.configure").write_text(
                '    def win32_subsystem_version():\n'
                '        return "10.0"\n',
                encoding="utf-8",
            )
            (ff / "browser/installer/windows/nsis/defines.nsi.in").write_text(
                '!define MinSupportedVer "Microsoft Windows 10 x64"\n', encoding="utf-8"
            )
            (ff / "browser/installer/windows/nsis/installer.nsi").write_text(
                '  ${If} "${ARCH}" == "AArch64"\n'
                '    ${IfNot} ${AtLeastWin10}\n'
                '      Quit\n'
                '    ${EndIf}\n'
                '  ${Else}\n'
                '    ${Unless} ${AtLeastWin10}\n'
                '      Quit\n'
                '    ${EndUnless}\n'
                '  ${EndIf}\n',
                encoding="utf-8",
            )
            (ff / "mfbt/WindowsVersion.h").write_text(
                "namespace mozilla {\ninline bool IsWindows10BuildOrLater(uint32_t aBuild) { return true; }\n}\n",
                encoding="utf-8",
            )
            (ff / "dom/webserial/Win32SerialPlatformService.cpp").write_text(
                "CONFIGRET cr = CM_Register_Notification(\n"
                "    &filter, this, DeviceNotificationCallback, &mDeviceNotification);\n"
                "if (mDeviceNotification) {\n"
                "  CM_Unregister_Notification(mDeviceNotification);\n"
                "  mDeviceNotification = nullptr;\n"
                "}\n",
                encoding="utf-8",
            )

            self.assertEqual(len(apply_win7_patches.patch_windows_subsystem(ff, False)), 1)
            self.assertIn('return "6.01"', (ff / "build/moz.configure/windows.configure").read_text(encoding="utf-8"))
            self.assertEqual(apply_win7_patches.patch_windows_subsystem(ff, False), [])

            self.assertEqual(len(apply_win7_patches.patch_nsis_win7(ff, False)), 2)
            self.assertEqual(len(apply_win7_patches.patch_windows_version_h(ff, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_webserial_win7(ff, False)), 1)

            # Verify ARM64 kept AtLeastWin10 while x64 became AtLeastWin7
            inst = (ff / "browser/installer/windows/nsis/installer.nsi").read_text(encoding="utf-8")
            self.assertIn("${IfNot} ${AtLeastWin10}", inst)
            self.assertIn("${Unless} ${AtLeastWin7}", inst)

            # Verify WebSerial shim uses CfgMgr32.dll (no typo) and dynamic GetProcAddress
            ws = (ff / "dom/webserial/Win32SerialPlatformService.cpp").read_text(encoding="utf-8")
            self.assertIn('LoadLibraryW(L"CfgMgr32.dll")', ws)
            self.assertIn('"CM_Register_Notification"', ws)
            self.assertIn('"CM_Unregister_Notification"', ws)

            # Verify idempotency
            self.assertEqual(apply_win7_patches.patch_nsis_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_windows_version_h(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_webserial_win7(ff, False), [])

            # Verify vendored `getrandom` Win7 backend switch + automatic Cargo checksum update
            crate = ff / "third_party/rust/getrandom"
            (crate / "src").mkdir(parents=True)
            (crate / "src/backends.rs").write_text(
                '} else if #[cfg(all(windows, any(target_vendor = "win7", getrandom_windows_legacy)))] {\n'
                '    mod windows7;\n'
                '    pub use windows7::*;\n'
                '} else if #[cfg(windows)] {\n'
                '    mod windows;\n'
                '}\n',
                encoding="utf-8",
            )
            (crate / ".cargo-checksum.json").write_text(
                json.dumps({"files": {"src/backends.rs": "oldhash"}, "package": "pkg"}),
                encoding="utf-8",
            )
            patched_crates = apply_win7_patches.patch_vendored_rust_crates(ff, False)
            self.assertEqual(len(patched_crates), 1)
            self.assertIn("} else if #[cfg(windows)] {\n    mod windows7;", (crate / "src/backends.rs").read_text(encoding="utf-8"))
            updated = json.loads((crate / ".cargo-checksum.json").read_text(encoding="utf-8"))
            self.assertEqual(
                updated["files"]["src/backends.rs"],
                apply_win7_patches.sha256_file(crate / "src/backends.rs"),
            )
            # Idempotent on second run
            self.assertEqual(apply_win7_patches.patch_vendored_rust_crates(ff, False), [])

    def test_pe64_win7_import_auditor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            clean_exe = Path(tmp) / "konfox_clean.exe"
            clean_exe.write_bytes(
                build_synthetic_pe64(
                    [
                        ("KERNEL32.dll", ["CreateFileW", "GetSystemTimeAsFileTime", "AcquireSRWLockExclusive"]),
                        ("ADVAPI32.dll", ["SystemFunction036"]),
                    ]
                )
            )
            self.assertEqual(verify_win7_pe.audit_pe_file(clean_exe), [])

            broken_dll = Path(tmp) / "xul_broken.dll"
            broken_dll.write_bytes(
                build_synthetic_pe64(
                    [
                        ("bcryptprimitives.dll", ["ProcessPrng"]),
                        ("api-ms-win-core-synch-l1-2-0.dll", ["WaitOnAddress"]),
                        ("KERNEL32.dll", ["CreateFileW", "GetTempPath2W"]),
                        ("CfgMgr32.dll", ["CM_Register_Notification"]),
                    ]
                )
            )
            findings = verify_win7_pe.audit_pe_file(broken_dll)
            self.assertEqual(len(findings), 4, f"Unexpected findings: {findings}")
            joined = "\n".join(findings)
            self.assertIn("bcryptprimitives.dll", joined)
            self.assertIn("api-ms-win-core-synch-l1-2-0.dll", joined)
            self.assertIn("GetTempPath2W", joined)
            self.assertIn("CM_Register_Notification", joined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
