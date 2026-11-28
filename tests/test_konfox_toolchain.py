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
import install_msvc1444_win7
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

            # Verify expanded Win8+ API-set allowlist & newly added Win8+ APIs
            pathcch_dll = Path(tmp) / "widget_broken.dll"
            pathcch_dll.write_bytes(
                build_synthetic_pe64(
                    [
                        ("api-ms-win-core-path-l1-1-0.dll", ["PathCchCanonicalize"]),
                        ("api-ms-win-core-memory-l1-1-5.dll", ["VirtualAlloc2"]),
                        ("KERNEL32.dll", ["GetCurrentPackageFullName", "CopyFile2"]),
                        ("api-ms-win-crt-runtime-l1-1-0.dll", ["_initterm"]),
                        ("api-ms-win-core-synch-l1-1-0.dll", ["Sleep"]),
                    ]
                )
            )
            findings2 = verify_win7_pe.audit_pe_file(pathcch_dll)
            self.assertEqual(len(findings2), 4, f"Unexpected findings: {findings2}")
            joined2 = "\n".join(findings2)
            self.assertIn("api-ms-win-core-path-l1-1-0.dll", joined2)
            self.assertIn("api-ms-win-core-memory-l1-1-5.dll", joined2)
            self.assertIn("GetCurrentPackageFullName", joined2)
            self.assertIn("CopyFile2", joined2)

    def test_win7_all_new_pe_import_patches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ff = Path(tmp) / "firefox"
            files = {
                "browser/app/winlauncher/moz.build": (
                    'OS_LIBS += [\n    "ole32",\n    "runtimeobject",\n    "shlwapi",\n]\n'
                ),
                "browser/app/winlauncher/LauncherProcessWin.cpp": (
                    "    ComPtr<IAppInstanceStatics> appInstanceStatics;\n"
                    "    HRESULT hr = GetActivationFactory(\n"
                    "        HStringReference(RuntimeClass_Windows_ApplicationModel_AppInstance)\n"
                    "            .Get(),\n"
                    "        appInstanceStatics.GetAddressOf());\n"
                    "  LONG rc = GetCurrentPackageFullName(&length, NULL);\n"
                ),
                "browser/components/shell/WindowsUserChoice.cpp": (
                    "  UINT32 pfnLen = 0;\n"
                    "  LONG rv = GetCurrentPackageFullName(&pfnLen, nullptr);\n"
                    "  NS_ENSURE_TRUE(rv != APPMODEL_ERROR_NO_PACKAGE, NS_ERROR_FAILURE);\n\n"
                    "  auto pfn = std::make_unique<wchar_t[]>(pfnLen);\n"
                    "  rv = GetCurrentPackageFullName(&pfnLen, pfn.get());\n"
                ),
                "toolkit/mozapps/defaultagent/SetDefaultBrowser.cpp": (
                    "  UINT32 pfnLen = 0;\n"
                    "  bool inMsix =\n"
                    "      GetCurrentPackageFullName(&pfnLen, nullptr) != APPMODEL_ERROR_NO_PACKAGE;\n"
                ),
                "security/sandbox/chromium/sandbox/win/src/process_mitigations.cc": (
                    "    if (!::GetProcessMitigationPolicy(::GetCurrentProcess(),\n"
                    "                                      ProcessMitigationOptionsMask,\n"
                    "                                      &mitigations, mits_size)) {\n"
                    "      NOTREACHED();\n"
                    "    }\n"
                    "  PCHECK(::SetProcessMitigationPolicy(policy, lpBuffer, dwLength))\n"
                    '      << "SetProcessMitigationPolicy failed with Policy: " << policy;\n'
                    "  if (flags & MITIGATION_DLL_SEARCH_ORDER) {\n"
                    "    if (!::SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)) {\n"
                    "      return false;\n"
                    "    }\n\n"
                    "    applied_flags |= MITIGATION_DLL_SEARCH_ORDER;\n"
                    "  }\n"
                    "    if (!::SetThreadInformation(::GetCurrentThread(), ThreadDynamicCodePolicy,\n"
                    "                                &thread_policy, sizeof(thread_policy))) {\n"
                    "      return false;\n"
                    "    }\n"
                ),
                "security/sandbox/chromium/base/win/win_util.cc": (
                    "    if (::GetProcessMitigationPolicy(GetCurrentProcess(),\n"
                    "                                     ProcessSystemCallDisablePolicy, &policy,\n"
                    "                                     sizeof(policy))) {\n"
                ),
                "security/sandbox/chromium/base/time/time_win.cc": (
                    "  ::GetSystemTimePreciseAsFileTime(&ft);\n"
                ),
                "mozglue/misc/moz.build": '    OS_LIBS += ["dbghelp", "oleaut32", "ole32", "mincore"]\n',
                "mozglue/misc/Futex_windows.cpp": "return ::WaitOnAddress(&mValue, &aExpected, 4, 0);\n",
                "mozglue/misc/AwakeTimeStamp.cpp": (
                    "AwakeTimeStamp AwakeTimeStamp::Now() {\n"
                    "  ULONGLONG interrupt_time;\n"
                    "  QueryUnbiasedInterruptTimePrecise(&interrupt_time);\n\n"
                    "  return AwakeTimeStamp(interrupt_time / kHNSperUS);\n"
                    "}\n"
                ),
                "third_party/angle/src/common/SimpleMutex.h": (
                    "#    elif defined(ANGLE_PLATFORM_WINDOWS) && !defined(ANGLE_ENABLE_WINDOWS_UWP) && \\\n"
                    "        !defined(ANGLE_WINDOWS_NO_FUTEX)\n"
                    "// Windows has futexes since version 8, which is already end of life (let alone older versions).\n"
                    "// Assume support.\n"
                    "#        define ANGLE_USE_FUTEX 1\n"
                ),
                "widget/windows/moz.build": 'OS_LIBS += [\n    "pathcch",\n    "shcore",\n    "winmm",\n]\n',
                "widget/windows/WinUtils.cpp": (
                    "float WinUtils::MonitorDPI(HMONITOR aMonitor) {\n"
                    "  UINT dpiX, dpiY = 96;\n"
                    "  GetDpiForMonitor(aMonitor ? aMonitor : GetPrimaryMonitor(), MDT_EFFECTIVE_DPI,\n"
                    "                   &dpiX, &dpiY);\n"
                    "  return dpiY;\n"
                    "}\n"
                    "bool WinUtils::CanonicalizePath(nsAString& aPath) {\n"
                    "  wchar_t tempPath[MAX_PATH + 1];\n"
                    "  HRESULT hr = PathCchCanonicalize(tempPath, std::size(tempPath),\n"
                    "                                   (char16ptr_t)PromiseFlatString(aPath).get());\n"
                    "  if (FAILED(hr)) {\n"
                    "    return false;\n"
                    "  }\n"
                ),
                "toolkit/mozapps/update/common/moz.build": '    OS_LIBS += [\n        "pathcch",\n        "shell32",\n    ]\n',
                "toolkit/mozapps/update/common/updatecommon.cpp": (
                    "  if (FAILED(PathCchCanonicalize(canonicalPath, MAXPATHLEN, testPath))) {\n"
                ),
                "third_party/libwebrtc/modules/desktop_capture/desktop_capture_gn/moz.build": '    "shcore",\n',
                "third_party/libwebrtc/webrtc_gn/moz.build": '    "shcore",\n',
                "third_party/libwebrtc/modules/desktop_capture/win/screen_capture_utils.cc": (
                    "  HRESULT hr = ::GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &dpi_x, &dpi_y);\n"
                ),
                "third_party/libwebrtc/modules/desktop_capture/win/dxgi_output_duplicator.cc": (
                    "  HRESULT hr = GetScaleFactorForMonitor(monitor_, &device_scale_factor);\n"
                ),
                "third_party/libwebrtc/modules/desktop_capture/win/wgc_capture_session.cc": (
                    "  HRESULT scale_factor_hr =\n"
                    "      GetScaleFactorForMonitor(monitor_.value(), &device_scale_factor);\n"
                    "    HRESULT hr =\n"
                    "        GetScaleFactorForMonitor(monitor_.value(), &device_scale_factor);\n"
                ),
                "hal/windows/WindowsHeterogeneousCpuInfo.cpp": (
                    "  ULONG returnedLength;\n"
                    "  GetSystemCpuSetInformation(NULL, 0, &returnedLength, NULL, 0);\n\n"
                    "  if (!returnedLength) {\n"
                    "    return Nothing();\n"
                    "  }\n\n"
                    "  AutoTArray<uint8_t, 1024> cpuSets;\n\n"
                    "  cpuSets.SetLength(returnedLength);\n\n"
                    "  if (!GetSystemCpuSetInformation(\n"
                    "          reinterpret_cast<SYSTEM_CPU_SET_INFORMATION*>(cpuSets.Elements()),\n"
                    "          returnedLength, &returnedLength, NULL, 0)) {\n"
                ),
                "js/src/vm/Time.cpp": "  GetSystemTimePreciseAsFileTime(&ft);\n",
                "tools/profiler/public/ETWTools.h": "#  include <TraceLoggingProvider.h>\n",
                "third_party/llama.cpp/ggml/src/ggml-cpu/ggml-cpu-c.c": (
                    "        if (!SetThreadInformation(GetCurrentThread(), ThreadPowerThrottling, &t, sizeof(t))) {\n"
                    '            GGML_LOG_DEBUG("failed to disable thread power throttling %d : (%d)\\n", prio, (int) GetLastError());\n'
                    "            return false;\n"
                    "        }\n"
                ),
            }
            for rel, content in files.items():
                p = ff / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")

            self.assertEqual(len(apply_win7_patches.patch_winlauncher_and_appmodel(ff, False)), 4)
            self.assertEqual(len(apply_win7_patches.patch_chromium_sandbox_win7(ff, False)), 3)
            self.assertEqual(len(apply_win7_patches.patch_mozglue_futex_and_mincore(ff, False)), 3)
            self.assertEqual(len(apply_win7_patches.patch_angle_futex(ff, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_shcore_and_pathcch(ff, False)), 9)
            self.assertEqual(len(apply_win7_patches.patch_cpu_sets_win7(ff, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_precise_time_win7(ff, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_etw_tracelogging_win7(ff, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_llama_cpp_win7(ff, False)), 1)

            # Spot-check critical outputs
            self.assertNotIn('"mincore"', (ff / "mozglue/misc/moz.build").read_text(encoding="utf-8"))
            self.assertNotIn('"runtimeobject"', (ff / "browser/app/winlauncher/moz.build").read_text(encoding="utf-8"))
            self.assertIn("SleepConditionVariableSRW", (ff / "mozglue/misc/Futex_windows.cpp").read_text(encoding="utf-8"))
            awake_out = (ff / "mozglue/misc/AwakeTimeStamp.cpp").read_text(encoding="utf-8")
            self.assertIn("QueryUnbiasedInterruptTime(&interrupt_time)", awake_out)
            self.assertIn('"QueryUnbiasedInterruptTimePrecise"', awake_out)
            self.assertNotIn("  QueryUnbiasedInterruptTimePrecise(&interrupt_time)", awake_out)
            self.assertIn("pQueryUnbiasedInterruptTimePrecise(&interrupt_time)", awake_out)
            self.assertIn("TLG_HAVE_EVENT_SET_INFORMATION 2", (ff / "tools/profiler/public/ETWTools.h").read_text(encoding="utf-8"))
            winutils_out = (ff / "widget/windows/WinUtils.cpp").read_text(encoding="utf-8")
            self.assertIn('"PathCanonicalizeW"', winutils_out)
            self.assertNotIn("::PathCanonicalizeW", winutils_out)
            self.assertIn("SystemDPI()", winutils_out)
            updatecommon_out = (ff / "toolkit/mozapps/update/common/updatecommon.cpp").read_text(encoding="utf-8")
            self.assertIn('"PathCanonicalizeW"', updatecommon_out)
            self.assertNotIn("::PathCanonicalizeW", updatecommon_out)

            # All 9 transforms must be idempotent on a second pass
            self.assertEqual(apply_win7_patches.patch_winlauncher_and_appmodel(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_chromium_sandbox_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_mozglue_futex_and_mincore(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_angle_futex(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_shcore_and_pathcch(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_cpu_sets_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_precise_time_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_etw_tracelogging_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_llama_cpp_win7(ff, False), [])

    def test_msvc1444_vsix_extraction_and_overlay(self) -> None:
        import io
        import os
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            vs = Path(tmp) / "vs"
            (vs / "Windows Kits/10/Include/10.0.28000.0/um").mkdir(parents=True)
            (vs / "Windows Kits/10/Include/10.0.28000.0/um/Windows.h").write_text("// sdk\n", encoding="utf-8")

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("Contents/VC/Tools/MSVC/14.44.35207/include/vector", "// stl\n")
                zf.writestr("Contents/VC/Tools/MSVC/14.44.35207/include/yvals.h", "// hdr\n")
                zf.writestr("Contents/VC/Tools/MSVC/14.44.35207/include/vcruntime.h", "// hdr\n")
                zf.writestr("Contents/VC/Tools/MSVC/14.44.35207/atlmfc/include/atlbase.h", "// atl\n")
                zf.writestr("Contents/VC/Tools/MSVC/14.44.35207/atlmfc/lib/x64/ATLS.lib", b"LIB")
                zf.writestr("Contents/VC/Tools/MSVC/14.44.35207/lib/x64/LIBCMT.lib", b"LIB")
                zf.writestr("Contents/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/cl.exe", b"MZ")
                for dll in install_msvc1444_win7.REQUIRED_REDIST_DLLS:
                    zf.writestr(
                        f"Contents/VC/Redist/MSVC/14.44.35211/x64/Microsoft.VC143.CRT/{dll}",
                        b"MZ",
                    )
                zf.writestr("_rels/.rels", "ignored")

            extracted = install_msvc1444_win7.extract_vc_vsix(buf.getvalue(), vs)
            self.assertEqual(extracted, 11)
            # Missing oldnames.lib / msvcrt.lib (from CRT.x64.Store.base) -> MUST be False!
            self.assertFalse(install_msvc1444_win7.is_already_msvc1444(vs))

            # Now extract the remaining dynamic CRT libs (simulating CRT.x64.Store.base)
            buf2 = io.BytesIO()
            with zipfile.ZipFile(buf2, "w") as zf:
                for lib in install_msvc1444_win7.REQUIRED_X64_LIBS:
                    zf.writestr(f"Contents/VC/Tools/MSVC/14.44.35207/lib/x64/{lib.upper()}", b"LIB")
            install_msvc1444_win7.extract_vc_vsix(buf2.getvalue(), vs)
            self.assertTrue(install_msvc1444_win7.is_already_msvc1444(vs))

            # .lib must be lowercased; .exe must be executable
            self.assertTrue((vs / "VC/Tools/MSVC/14.44.35207/lib/x64/oldnames.lib").is_file())
            self.assertTrue((vs / "VC/Tools/MSVC/14.44.35207/lib/x64/libcmt.lib").is_file())
            self.assertTrue((vs / "VC/Tools/MSVC/14.44.35207/atlmfc/lib/x64/atls.lib").is_file())
            cl_exe = vs / "VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/cl.exe"
            self.assertTrue(bool(os.stat(cl_exe).st_mode & 0o111))

            overlay_path = install_msvc1444_win7.regenerate_overlay_yaml(vs)
            overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
            self.assertFalse(overlay["case-sensitive"])
            root_names = {r["name"] for r in overlay["roots"]}
            self.assertIn("VC/Tools/MSVC/14.44.35207/include", root_names)
            self.assertIn("Windows Kits/10/Include/10.0.28000.0/um", root_names)

    def test_release10_win7_runtime_patches_and_idempotency(self) -> None:
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            ff = Path(tmp) / "firefox"
            ff.mkdir(parents=True)
            (ff / "mach").write_text("#!/bin/sh\n", encoding="utf-8")

            # Seed minimal snippets for Steps 16-24
            files = {
                "browser/app/firefox.exe.manifest": (
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<assembly><assemblyIdentity name="Firefox"/>'
                    "<description>Firefox</description>"
                    '<dependentAssembly><assemblyIdentity name="mozglue"/></dependentAssembly>'
                    '<application><supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/></application>'
                    "</assembly>\n"
                ),
                "third_party/rust/windows-core/src/imp/bindings.rs": (
                    'windows_link::link!("combase.dll" "system" fn CoIncrementMTAUsage(pcookie : *mut CO_MTA_USAGE_COOKIE) -> HRESULT);\n'
                    'windows_link::link!("combase.dll" "system" fn CoTaskMemAlloc(cb : usize) -> *mut core::ffi::c_void);\n'
                    'windows_link::link!("combase.dll" "system" fn CoTaskMemFree(pv : *const core::ffi::c_void));\n'
                ),
                "third_party/rust/windows-core/src/imp/marshaler.rs": (
                    'windows_link::link!("combase.dll" "system" fn CoCreateFreeThreadedMarshaler(punkouter: *mut c_void, ppunkmarshal: *mut *mut c_void) -> HRESULT);\n'
                ),
                "third_party/rust/windows-core/src/imp/com_bindings.rs": (
                    '    windows_core::link!("combase.dll" "system" fn RoGetAgileReference(options : AgileReferenceOptions, riid : *const windows_core::GUID, punk : * mut core::ffi::c_void, ppagilereference : *mut * mut core::ffi::c_void) -> windows_core::HRESULT);\n'
                    "    unsafe {\n"
                    "        let mut result__ = core::mem::zeroed();\n"
                    "        RoGetAgileReference(options, riid, punk.param().abi(), &mut result__)\n"
                    "            .and_then(|| windows_core::Type::from_abi(result__))\n"
                    "    }\n"
                ),
                "third_party/rust/windows-link/src/lib.rs": (
                    '#[cfg(all(windows, target_arch = "x86"))]\n'
                    "#[macro_export]\n"
                    "macro_rules! link {\n"
                    "    ($library:literal $abi:literal $($link_name:literal)? fn $($function:tt)*) => (\n"
                    '        #[link(name = $library, kind = "raw-dylib", modifiers = "+verbatim", import_name_type = "undecorated")]\n'
                    "        extern $abi {\n"
                    "            $(#[link_name=$link_name])?\n"
                    "            pub fn $($function)*;\n"
                    "        }\n"
                    "    )\n"
                    "}\n\n"
                    '#[cfg(all(windows, not(target_arch = "x86")))]\n'
                    "#[macro_export]\n"
                    "macro_rules! link {\n"
                    "    ($library:literal $abi:literal $($link_name:literal)? fn $($function:tt)*) => (\n"
                    '        #[link(name = $library, kind = "raw-dylib", modifiers = "+verbatim")]\n'
                    "        extern $abi {\n"
                    "            $(#[link_name=$link_name])?\n"
                    "            pub fn $($function)*;\n"
                    "        }\n"
                    "    )\n"
                    "}\n"
                ),
                "third_party/rust/windows-sys/src/Windows/Win32/System/Com/mod.rs": (
                    'windows_link::link!("combase.dll" "system" fn CoTaskMemAlloc(cb : usize) -> *mut core::ffi::c_void);\n'
                ),
                "ipc/mscom/AgileReference.cpp": (
                    '#include "mozilla/mscom/AgileReference.h"\n'
                    '#include "mozilla/Assertions.h"\n'
                    "HRESULT AgileReference_CreateImpl(RefPtr<IAgileReference>& aRefPtr, REFIID riid,\n"
                    "                                  IUnknown* aObject) {\n"
                    "  MOZ_ASSERT(aObject);\n"
                    "  MOZ_ASSERT(IsCOMInitializedOnCurrentThread());\n"
                    "  return ::RoGetAgileReference(AGILEREFERENCE_DEFAULT, riid, aObject,\n"
                    "                               getter_AddRefs(aRefPtr));\n"
                    "}\n"
                ),
                "js/src/jit/ProcessExecutableMemory.cpp": (
                    'extern "C" NTSYSAPI DWORD NTAPI RtlAddGrowableFunctionTable(\n'
                    "    PVOID* DynamicTable, PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount,\n"
                    "    DWORD MaximumEntryCount, ULONG_PTR RangeBase, ULONG_PTR RangeEnd);\n"
                    "    DWORD result = RtlAddGrowableFunctionTable(\n"
                    "        &r->dynamicTable, &r->runtimeFunction, 1, 1, (ULONG_PTR)p,\n"
                    "        (ULONG_PTR)p + bytes - pageSize);\n"
                    "    if (result != S_OK) {\n"
                    "      return false;\n"
                    "    }\n"
                ),
                "widget/windows/ToastNotification.cpp": (
                    '#include "ToastNotification.h"\n'
                    "nsresult ToastNotification::Init() {\n"
                    "  return NS_OK;\n"
                    "}\n"
                    "bool ToastNotification::AssignIfMsixAumid(Maybe<nsAutoString>& aAumid) {\n"
                    "  UINT32 len = 0;\n"
                    "  // ERROR_INSUFFICIENT_BUFFER signals that we're in an MSIX package, and\n"
                    "  // therefore should use the package's AUMID.\n"
                    "  if (GetCurrentApplicationUserModelId(&len, nullptr) !=\n"
                    "      ERROR_INSUFFICIENT_BUFFER) {\n"
                    '    MOZ_LOG(sWASLog, LogLevel::Debug, ("Not an MSIX package"));\n'
                    "    return false;\n"
                    "  }\n"
                    "  mozilla::Buffer<wchar_t> buffer(len);\n"
                    "  LONG success = GetCurrentApplicationUserModelId(&len, buffer.Elements());\n"
                    "  return success == ERROR_SUCCESS;\n"
                    "}\n"
                ),
                "widget/windows/nsWindow.cpp": (
                    "  if (!sWinCloakEventHook) {}\n"
                    "        (void)NS_WARN_IF(\n"
                    "            GetCurrentApplicationUserModelId(&maxLength, aumid.get()));\n"
                ),
                "mfbt/RandomNum.cpp": (
                    "  static const mozilla::StaticDynamicallyLinkedFunctionPtr<BOOL(WINAPI*)(\n"
                    "      PBYTE, SIZE_T)>\n"
                    '      pProcessPrng(L"bcryptprimitives.dll", "ProcessPrng");\n'
                    "  return pProcessPrng && !!pProcessPrng(static_cast<PBYTE>(aBuffer), aLength);\n"
                ),
                "security/sandbox/chromium/base/rand_util_win.cc": (
                    "decltype(&ProcessPrng) GetProcessPrng() {\n"
                    '  HMODULE hmod = LoadLibraryW(L"bcryptprimitives.dll");\n'
                    "  CHECK(hmod);\n"
                    "  decltype(&ProcessPrng) process_prng_fn =\n"
                    "      reinterpret_cast<decltype(&ProcessPrng)>(\n"
                    '          GetProcAddress(hmod, "ProcessPrng"));\n'
                    "  CHECK(process_prng_fn);\n"
                    "  return process_prng_fn;\n"
                    "}\n"
                ),
                "gfx/config/gfxConfigManager.cpp": (
                    '#ifdef XP_WIN\n#  include "mozilla/gfx/DeviceManagerDx.h"\n#endif\n'
                    "  mFeatureWrDComp->EnableByDefault();\n"
                ),
                "gfx/thebes/DeviceManagerDx.cpp": (
                    '#include "DeviceManagerDx.h"\n'
                    "  mFeatureLevels.AppendElement(D3D_FEATURE_LEVEL_11_1);\n"
                ),
                "mozglue/misc/WindowsDpiInitialization.cpp": (
                    "  } else {\n"
                    "    DynamicallyLinkedFunctionPtr<SetProcessDpiAwarenessType> f;\n"
                    "    return WindowsDpiInitializationResult::Success;\n"
                    "  }\n"
                    "}\n"
                ),
                "xpcom/base/AvailableMemoryTracker.cpp": (
                    "#if defined(XP_WIN)\n#endif\n"
                    "void nsJemallocFreeDirtyPagesRunnable::OptimizeSystemHeap() {\n"
                    "}\n"
                ),
            }
            for rel, content in files.items():
                p = ff / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")

            for crate, rels in (
                ("third_party/rust/windows-core", ["src/imp/bindings.rs", "src/imp/marshaler.rs", "src/imp/com_bindings.rs"]),
                ("third_party/rust/windows-link", ["src/lib.rs"]),
                ("third_party/rust/windows-sys", ["src/Windows/Win32/System/Com/mod.rs"]),
            ):
                cdir = ff / crate
                ck = {r: hashlib.sha256((cdir / r).read_bytes()).hexdigest() for r in rels}
                (cdir / ".cargo-checksum.json").write_text(json.dumps({"files": ck}), encoding="utf-8")

            # Seed a mock bootstrapped ~/.mozbuild/windows-rs directory too
            winrs = Path(tmp) / "windows-rs"
            winrs_com = winrs / "src/Windows/Win32/System/Com/mod.rs"
            winrs_com.parent.mkdir(parents=True, exist_ok=True)
            winrs_com.write_text(
                'windows_core::link!("combase.dll" "system" fn CoCreateFreeThreadedMarshaler(a: *mut core::ffi::c_void));\n'
                'windows_core::link!("combase.dll" "system" fn CoTaskMemAlloc(cb: usize) -> *mut core::ffi::c_void);\n'
                'windows_core::link!("combase.dll" "system" fn CoTaskMemFree(pv: *const core::ffi::c_void));\n',
                encoding="utf-8",
            )

            # Pass 1: apply every new step
            self.assertEqual(len(apply_win7_patches.patch_konfox_app_manifest(ff, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_combase_and_agile_reference(ff, False)), 9)
            self.assertEqual(len(apply_win7_patches.patch_bootstrapped_windows_rs(winrs, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_jit_unwind_win7(ff, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_aumid_dynamic_load(ff, False)), 2)
            self.assertEqual(len(apply_win7_patches.patch_win7_prng_fallbacks(ff, False)), 2)
            self.assertEqual(len(apply_win7_patches.patch_graphics_win7(ff, False)), 2)
            self.assertEqual(len(apply_win7_patches.patch_winrt_and_widget_win7(ff, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_memory_tracker_win7(ff, False)), 1)

            # Verify outputs
            self.assertIn('name="Konfox"', (ff / "browser/app/konfox.exe.manifest").read_text())
            self.assertNotIn('link!("combase.dll"', (ff / "third_party/rust/windows-core/src/imp/bindings.rs").read_text())
            self.assertNotIn('link!("combase.dll"', (ff / "third_party/rust/windows-core/src/imp/com_bindings.rs").read_text())
            self.assertIn('name = "ole32.dll"', (ff / "third_party/rust/windows-link/src/lib.rs").read_text())
            self.assertNotIn('link!("combase.dll"', winrs_com.read_text())
            self.assertIn("GitAgileReference", (ff / "ipc/mscom/AgileReference.cpp").read_text())
            self.assertIn("RtlInstallFunctionTableCallback", (ff / "js/src/jit/ProcessExecutableMemory.cpp").read_text())
            self.assertNotIn("GetCurrentApplicationUserModelId(", (ff / "widget/windows/ToastNotification.cpp").read_text())
            self.assertIn("SystemFunction036", (ff / "mfbt/RandomNum.cpp").read_text())
            self.assertIn("KonfoxWin7RtlGenRandom", (ff / "security/sandbox/chromium/base/rand_util_win.cc").read_text())
            self.assertIn("FEATURE_FAILURE_WIN7_NO_DCOMP", (ff / "gfx/config/gfxConfigManager.cpp").read_text())
            self.assertIn("SetProcessDPIAware", (ff / "mozglue/misc/WindowsDpiInitialization.cpp").read_text())

            # Pass 2: all steps must be 100% idempotent
            self.assertEqual(apply_win7_patches.patch_konfox_app_manifest(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_combase_and_agile_reference(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_bootstrapped_windows_rs(winrs, False), [])
            self.assertEqual(apply_win7_patches.patch_jit_unwind_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_aumid_dynamic_load(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_win7_prng_fallbacks(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_graphics_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_winrt_and_widget_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_memory_tracker_win7(ff, False), [])

    def test_verify_win7_pe_catches_combase_aumid_jit_websocket_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            # 1. Polluted xul.dll with combase.dll + AUMID + RtlAddGrowableFunctionTable
            bad_xul = tdir / "xul.dll"
            bad_xul.write_bytes(
                build_synthetic_pe64([
                    ("combase.dll", ["CoTaskMemAlloc", "RoGetAgileReference"]),
                    ("kernel32.dll", ["GetCurrentApplicationUserModelId"]),
                    ("ntdll.dll", ["RtlAddGrowableFunctionTable"]),
                    ("winhttp.dll", ["WinHttpWebSocketSend"]),
                ])
            )
            findings = verify_win7_pe.audit_pe_file(bad_xul)
            joined = "\n".join(findings)
            self.assertIn("combase.dll", joined)
            self.assertIn("GetCurrentApplicationUserModelId", joined)
            self.assertIn("RtlAddGrowableFunctionTable", joined)
            self.assertIn("WinHttpWebSocketSend", joined)

            # 2. konfox.exe missing RT_MANIFEST -> FAIL
            no_manifest = tdir / "konfox.exe"
            no_manifest.write_bytes(build_synthetic_pe64([("kernel32.dll", ["CreateFileW"])]))
            m_findings = verify_win7_pe.audit_pe_file(no_manifest)
            self.assertTrue(any("[MANIFEST]" in f for f in m_findings), m_findings)

            # 3. konfox.exe WITH embedded Win7 RT_MANIFEST + mozglue -> PASS
            manifest_xml = (
                b'<assembly><dependentAssembly><assemblyIdentity name="mozglue"/>'
                b'</dependentAssembly><supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/></assembly>'
            )
            no_manifest.write_bytes(build_synthetic_pe64([("kernel32.dll", ["CreateFileW"])]) + manifest_xml)
            self.assertEqual(verify_win7_pe.audit_pe_file(no_manifest), [])

    def test_win7_browsing_titlebar_icons_and_ai_removal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ff = Path(tmp) / "firefox"
            ff.mkdir(parents=True)
            (ff / "mach").write_text("#!/bin/sh\n", encoding="utf-8")

            files = {
                "security/sandbox/chromium/sandbox/win/src/process_mitigations.cc": (
                    "  if (flags & MITIGATION_DLL_SEARCH_ORDER) {\n"
                    "    if (!::SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)) {\n"
                    "      return false;\n"
                    "    }\n"
                    "  }\n"
                    "void ConvertProcessMitigationsToComponentFilter(MitigationFlags flags,\n"
                    "                                                COMPONENT_FILTER* filter) {\n"
                    "  filter->ComponentFlags = 0;\n"
                    "  if (flags & MITIGATION_KTM_COMPONENT) {\n"
                    "    filter->ComponentFlags = COMPONENT_KTM;\n"
                    "  }\n"
                    "}\n"
                ),
                "security/sandbox/chromium/sandbox/win/src/startup_information_helper.cc": (
                    "  if (component_filter_.ComponentFlags) {\n"
                    "    if (!startup_info_.UpdateProcThreadAttribute(\n"
                    "            PROC_THREAD_ATTRIBUTE_COMPONENT_FILTER, &component_filter_,\n"
                    "            sizeof(component_filter_)) &&\n"
                    "        ::GetLastError() != ERROR_NOT_SUPPORTED) {\n"
                    "      return false;\n"
                    "    }\n"
                    "  }\n"
                ),
                "ipc/mscom/ProcessRuntime.cpp": (
                    '#include "mozilla/WindowsProcessMitigations.h"\n'
                    "  if (aProcessCategory == ProcessCategory::GeckoBrowserParent) {\n"
                    "    ::CreateWellKnownSid(WinBuiltinAnyPackageSid, nullptr, &s, &sz);\n"
                    "  }\n"
                    "  bool haveAppContainerSid =\n"
                    "      ::GetTokenInformation(processToken, TokenAppContainerSid, info, len, &len);\n"
                ),
                "ipc/glue/SharedMemoryPlatform_windows.cpp": (
                    '#include "nsDebug.h"\n'
                    "  ACL dacl;\n\n"
                    "  if (aFreezable) {\n"
                    "        NS_WARN_IF(!::SetSecurityDescriptorDacl(&sd, TRUE, &dacl, FALSE))) {\n"
                    "      return Nothing();\n"
                    "    }\n"
                    "  }\n\n"
                    "  auto handle = MozCreateFileMappingW(psa, PAGE_READWRITE, 0,\n"
                    "                                      static_cast<DWORD>(aSize), nullptr);\n"
                ),
                "netwerk/socket/neqo_glue/src/lib.rs": (
                    '            .pmtud_iface_mtu(cfg!(not(target_os = "openbsd")))\n'
                ),
                "browser/themes/windows/browser.css": (
                    "  &::before {\n"
                    "    display: inline-block;\n"
                    "    content: inherit;\n"
                    "\n"
                    "    &:-moz-locale-dir(rtl) {\n"
                    "      transform: scaleX(-1);\n"
                    "    }\n"
                    "  }\n"
                    ".titlebar-min {\n"
                    "  /* Even though we use appearance: none, -moz-default-appearance is necessary\n"
                    '   * for Windows 11\'s "snap layouts" feature, see\n'
                    "   * DealWithWindowsAppearanceHacks */\n"
                    "  -moz-default-appearance: -moz-window-button-minimize;\n"
                    '  content: "\\e921"; /* ChromeMinimize */\n'
                    "  @media (prefers-contrast) {\n"
                    '    content: "\\ef2d"; /* ChromeMinimizeContrast */\n'
                    "  }\n"
                    "}\n"
                    "\n"
                    ".titlebar-max {\n"
                    "  -moz-default-appearance: -moz-window-button-maximize;\n"
                    '  content: "\\e922"; /* ChromeMaximize */\n'
                    "  @media (prefers-contrast) {\n"
                    '    content: "\\ef2e"; /* ChromeMaximizeContrast */\n'
                    "  }\n"
                    "}\n"
                    "\n"
                    ".titlebar-restore {\n"
                    "  -moz-default-appearance: -moz-window-button-restore;\n"
                    '  content: "\\e923"; /* ChromeRestore */\n'
                    "  @media (prefers-contrast) {\n"
                    '    content: "\\ef2f"; /* ChromeRestoreContrast */\n'
                    "  }\n"
                    "}\n"
                    "\n"
                    ".titlebar-close {\n"
                    "  -moz-default-appearance: -moz-window-button-close;\n"
                    '  content: "\\e8bb"; /* ChromeClose */\n'
                    "  @media (prefers-contrast) {\n"
                    '    content: "\\ef2c"; /* ChromeCloseContrast */\n'
                    "  }\n"
                    "}\n"
                ),
                "browser/components/preferences/preferences.xhtml": (
                    '<html:moz-page-nav-button id="category-ai-features"\n'
                    '        view="paneAi">\n'
                ),
                "browser/components/preferences/preferences.js": (
                    "  ai: {\n"
                    "    visible: () =>\n"
                    '      Services.prefs.getBoolPref("browser.preferences.aiControls", false),\n'
                    "  },\n"
                ),
                "browser/components/sidebar/SidebarManager.sys.mjs": (
                    'const DEFAULT_LAUNCHER_TOOLS =\n'
                    '  "opentabs,bookmarks,aichat,history,syncedtabs,passwords";\n'
                ),
                "modules/libpref/init/all.js": (
                    'pref("extensions.ml.enabled", true);\n'
                    'pref("browser.ai.control.default", "available");\n'
                    'pref("browser.ml.enable", true);\n'
                ),
                "browser/app/profile/firefox.js": (
                    'pref("browser.preferences.aiControls", true);\n'
                    'pref("browser.ml.chat.enabled", true);\n'
                    'pref("browser.tabs.groups.smart.enabled", true);\n'
                ),
                "modules/libpref/init/StaticPrefList.yaml": (
                    "- name: browser.smartwindow.aitab.enabled\n"
                    "  type: bool\n"
                    "  value: @IS_NIGHTLY_BUILD@\n"
                ),
            }
            for rel, content in files.items():
                p = ff / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")

            self.assertEqual(len(apply_win7_patches.patch_chromium_sandbox_runtime_win7(ff, False)), 2)
            self.assertEqual(len(apply_win7_patches.patch_ipc_and_networking_win7(ff, False)), 3)
            self.assertEqual(len(apply_win7_patches.patch_win7_titlebar_icons(ff, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_remove_ai_features(ff, False)), 6)

            # Verify key outcomes
            self.assertIn("WIN10_20H1", (ff / "security/sandbox/chromium/sandbox/win/src/process_mitigations.cc").read_text(encoding="utf-8"))
            self.assertIn("ERROR_INVALID_PARAMETER", (ff / "security/sandbox/chromium/sandbox/win/src/startup_information_helper.cc").read_text(encoding="utf-8"))
            self.assertIn("appContainersSupported", (ff / "ipc/mscom/ProcessRuntime.cpp").read_text(encoding="utf-8"))
            self.assertIn("MozSharedMem_", (ff / "ipc/glue/SharedMemoryPlatform_windows.cpp").read_text(encoding="utf-8"))
            self.assertIn('target_os = "windows"', (ff / "netwerk/socket/neqo_glue/src/lib.rs").read_text(encoding="utf-8"))

            bcss = (ff / "browser/themes/windows/browser.css").read_text(encoding="utf-8")
            self.assertIn("mask-image: url(\"data:image/svg+xml", bcss)
            self.assertNotIn("\\e921", bcss)
            self.assertNotIn("\\e8bb", bcss)

            self.assertIn('hidden="true"', (ff / "browser/components/preferences/preferences.xhtml").read_text(encoding="utf-8"))
            self.assertIn("visible: () => false,", (ff / "browser/components/preferences/preferences.js").read_text(encoding="utf-8"))
            self.assertNotIn("aichat", (ff / "browser/components/sidebar/SidebarManager.sys.mjs").read_text(encoding="utf-8"))
            self.assertIn('pref("browser.ai.control.default", "blocked");', (ff / "modules/libpref/init/all.js").read_text(encoding="utf-8"))
            self.assertIn('pref("browser.preferences.aiControls", false);', (ff / "browser/app/profile/firefox.js").read_text(encoding="utf-8"))

            # Verify branding prefs disable all AI controls & features
            brand_prefs = (ROOT / "branding/konfox/pref/firefox-branding.js").read_text(encoding="utf-8")
            self.assertIn('pref("browser.preferences.aiControls", false);', brand_prefs)
            self.assertIn('pref("browser.ai.control.default", "blocked");', brand_prefs)
            self.assertIn('pref("browser.ml.enable", false);', brand_prefs)
            self.assertIn('pref("browser.ml.chat.enabled", false);', brand_prefs)

            # Pass 2: 100% idempotent
            self.assertEqual(apply_win7_patches.patch_chromium_sandbox_runtime_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_ipc_and_networking_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_win7_titlebar_icons(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_remove_ai_features(ff, False), [])

    def test_win7_run13_runtime_hang_and_crash_fixes(self) -> None:
        """Verify Run #13 fixes for Win7 browsing hang, initial crash, zombie exit, and freezes."""
        with tempfile.TemporaryDirectory() as tmp:
            ff = Path(tmp) / "firefox"
            files = {
                "mozglue/misc/Futex_windows.cpp": "return ::WaitOnAddress(&mValue, &aExpected, 4, 0);\n",
                "intl/locale/windows/OSPreferences_win.cpp": (
                    '#include "OSPreferences.h"\n'
                    "  if (SUCCEEDED(RoGetActivationFactory(\n"
                    "          HStringReference(\n"
                    "              RuntimeClass_Windows_System_UserProfile_GlobalizationPreferences)\n"
                    "              .Get(),\n"
                ),
                "toolkit/xre/nsEmbedFunctions.cpp": (
                    '#  include "WinUtils.h"\n'
                    "  if (aChildData->sandboxTargetServices) {\n"
                    "    SandboxTarget::Instance()->SetTargetServices(\n"
                    "        aChildData->sandboxTargetServices);\n"
                    "  }\n"
                ),
                "widget/windows/WinRegistry.cpp": (
                    '#include "WinRegistry.h"\n'
                    "  DWORD flags = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES |\n"
                    "                REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY |\n"
                    "                REG_NOTIFY_THREAD_AGNOSTIC;\n"
                ),
                "toolkit/system/windowsproxy/WindowsInternetFunctionsWrapper.cpp": (
                    "    if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION,\n"
                    "                              &list, &size)) {\n"
                    '      LOG(("ReadAllOptionsLocked: InternetQueryOptionW failed"));\n'
                    "      return NS_ERROR_FAILURE;\n"
                    "    }\n"
                ),
                "ipc/mscom/Utils.cpp": (
                    '#include "mozilla/mscom/Utils.h"\n'
                    "  // If aInitBuf is null then initSize must be 0.\n"
                    "  UINT initSize = aInitBuf ? aInitBufSize : 0;\n"
                    "  stream = already_AddRefed<IStream>(::SHCreateMemStream(aInitBuf, initSize));\n"
                    "  if (!stream) {\n"
                    "    return E_OUTOFMEMORY;\n"
                    "  }\n\n"
                    "  if (!aInitBuf) {\n"
                    "    // Now we'll set the required size\n"
                    "    ULARGE_INTEGER newSize;\n"
                    "    newSize.QuadPart = aInitBufSize;\n"
                    "    hr = stream->SetSize(newSize);\n"
                    "    if (FAILED(hr)) {\n"
                    "      return hr;\n"
                    "    }\n"
                    "  }\n"
                ),
                "third_party/rust/quinn-udp/src/windows.rs": (
                    "                    if code == WinSock::WSAENOPROTOOPT\n"
                    "                    || code == WinSock::WSAEOPNOTSUPP\n"
                    "            max_gso_segments: AtomicUsize::new(max_gso_segments(&*socket.0)),\n"
                    "    let mut len = 0;\n"
                    "    let rc = unsafe {\n"
                    "        WinSock::WSASendMsg(\n"
                    "            socket.0.as_raw_socket() as usize,\n"
                    "            &wsa_msg,\n"
                    "            0,\n"
                    "            &mut len,\n"
                    "            ptr::null_mut(),\n"
                    "            None,\n"
                    "        )\n"
                    "    };\n\n"
                    "    match rc {\n"
                    "        0 => Ok(()),\n"
                    "        _ => Err(io::Error::last_os_error()),\n"
                    "    }\n"
                ),
                "third_party/rust/quinn-udp/.cargo-checksum.json": (
                    '{"files":{"src/windows.rs":"0000"},"package":null}'
                ),
            }
            for rel, content in files.items():
                p = ff / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")

            self.assertEqual(len(apply_win7_patches.patch_mozglue_futex_and_mincore(ff, False)), 1)
            self.assertEqual(len(apply_win7_patches.patch_winrt_and_widget_win7(ff, False)), 2)
            self.assertEqual(len(apply_win7_patches.patch_ipc_and_networking_win7(ff, False)), 4)

            futex_code = "\n".join(
                l for l in (ff / "mozglue/misc/Futex_windows.cpp").read_text(encoding="utf-8").splitlines()
                if not l.lstrip().startswith("//")
            )
            self.assertNotIn("LoadLibrary", futex_code)
            self.assertNotIn("InitOnceExecuteOnce", futex_code)
            self.assertIn('GetModuleHandleW(L"kernelbase.dll")', futex_code)

            self.assertIn("mozilla::IsWin8OrLater()", (ff / "intl/locale/windows/OSPreferences_win.cpp").read_text(encoding="utf-8"))
            self.assertIn("mozilla::RandomUint64OrDie()", (ff / "toolkit/xre/nsEmbedFunctions.cpp").read_text(encoding="utf-8"))
            self.assertIn("flags |= REG_NOTIFY_THREAD_AGNOSTIC;", (ff / "widget/windows/WinRegistry.cpp").read_text(encoding="utf-8"))
            self.assertIn("INTERNET_PER_CONN_FLAGS;", (ff / "toolkit/system/windowsproxy/WindowsInternetFunctionsWrapper.cpp").read_text(encoding="utf-8"))
            self.assertIn("CreateStreamOnHGlobal", (ff / "ipc/mscom/Utils.cpp").read_text(encoding="utf-8"))
            quinn_text = (ff / "third_party/rust/quinn-udp/src/windows.rs").read_text(encoding="utf-8")
            self.assertIn("WinSock::WSAEINVAL", quinn_text)
            self.assertIn("socket.0.send_to(transmit.contents, &daddr)", quinn_text)
            cs = json.loads((ff / "third_party/rust/quinn-udp/.cargo-checksum.json").read_text(encoding="utf-8"))
            self.assertNotEqual(cs["files"]["src/windows.rs"], "0000")

            # Pass 2: 100% idempotent
            self.assertEqual(apply_win7_patches.patch_mozglue_futex_and_mincore(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_winrt_and_widget_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_ipc_and_networking_win7(ff, False), [])

    def test_run14_win7_winrt_sandbox_loader_net_fixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ff = Path(tmp)
            files = {
                "third_party/rust/windows-core/src/imp/bindings.rs": (
                    'windows_link::link!("combase.dll" "system" fn CoIncrementMTAUsage(pcookie : *mut CO_MTA_USAGE_COOKIE) -> HRESULT);\n'
                    'windows_link::link!("combase.dll" "system" fn CoTaskMemAlloc(cb : usize) -> *mut core::ffi::c_void);\n'
                    'windows_link::link!("combase.dll" "system" fn CoTaskMemFree(pv : *const core::ffi::c_void));\n'
                    'windows_link::link!("api-ms-win-core-winrt-l1-1-0.dll" "system" fn RoGetActivationFactory(activatableclassid : HSTRING, iid : *const GUID, factory : *mut *mut core::ffi::c_void) -> HRESULT);\n'
                ),
                "third_party/rust/windows-core/.cargo-checksum.json": (
                    '{"files":{"src/imp/bindings.rs":"0000"},"package":null}'
                ),
                "security/sandbox/chromium/sandbox/win/src/window.cc": (
                    '#include "base/win/security_descriptor.h"\n'
                    "  if (sd->dacl() && sd->dacl()->is_null()) {\n"
                    "    sd->SetDaclEntry(base::win::WellKnownSid::kAllApplicationPackages,\n"
                    "                     base::win::SecurityAccessMode::kGrant, GENERIC_ALL, 0);\n"
                    "  }\n"
                ),
                "security/sandbox/win/src/sandboxbroker/sandboxBroker.cpp": (
                    "static sandbox::ResultCode AddWin32kLockdownConfig(\n"
                    "    sandbox::TargetConfig* aConfig) {\n"
                    "  return sandbox::SBOX_ALL_OK;\n"
                    "}\n"
                    "static sandbox::ResultCode AddCigToConfig(\n"
                    "    sandbox::TargetConfig* aConfig, bool aAlwaysProxyBinDirLoading = false) {\n"
                    "  return sandbox::SBOX_ALL_OK;\n"
                    "}\n"
                    "void SandboxBroker::SetSecurityLevelForContentProcess(int32_t aSandboxLevel, bool aIsFileProcess) {\n"
                    "  MOZ_RELEASE_ASSERT(aSandboxLevel >= 1,\n"
                    '                     "Should not be called with aSandboxLevel < 1");\n'
                    "  // Add the policy for the client side of the crash server pipe.\n"
                    "  result = config->AllowFileAccess(sandbox::FileSemantics::kAllowAny,\n"
                    '                                   L"\\\\??\\\\pipe\\\\gecko-crash-server-pipe.*");\n'
                    "}\n"
                    "void SandboxBroker::SetSecurityLevelForGPUProcess(int32_t aSandboxLevel) {\n"
                    "  if (aSandboxLevel >= 2) {\n"
                    "    if (UseFontFileRule()) {\n"
                    "    }\n"
                    "  }\n"
                    "}\n"
                    "bool SandboxBroker::SetSecurityLevelForGMPlugin(GMPSandboxKind aGMPSandboxKind) {\n"
                    "  if (StaticPrefs::security_sandbox_gmp_win32k_disable() &&\n"
                    "      aGMPSandboxKind != Widevine && aGMPSandboxKind != Clearkey &&\n"
                    "      aGMPSandboxKind != Fake) {\n"
                    "    return true;\n"
                    "  }\n"
                    "  return true;\n"
                    "}\n"
                ),
                "security/sandbox/chromium/sandbox/win/src/target_process.cc": (
                    '#include "base/win/current_module.h"\n'
                    "  if (startup_info->has_extended_startup_info())\n"
                    "    flags |= EXTENDED_STARTUPINFO_PRESENT;\n"
                ),
                "security/sandbox/chromium/sandbox/win/src/win_utils.cc": (
                    "decltype(&ProcessPrng) GetProcessPrng() {\n"
                    '  HMODULE hmod = LoadLibraryW(L"bcryptprimitives.dll");\n'
                    "  CHECK(hmod);\n"
                    "  decltype(&ProcessPrng) process_prng_fn =\n"
                    "      reinterpret_cast<decltype(&ProcessPrng)>(\n"
                    '          GetProcAddress(hmod, "ProcessPrng"));\n'
                    "  CHECK(process_prng_fn);\n"
                    "  return process_prng_fn;\n"
                    "}\n"
                ),
                "security/sandbox/chromium/base/win/win_util.cc": (
                    "    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY policy = {};\n"
                    "    if (::GetProcessMitigationPolicy(GetCurrentProcess(),\n"
                    "                                     ProcessSystemCallDisablePolicy, &policy,\n"
                    "                                     sizeof(policy))) {\n"
                    "      return policy.DisallowWin32kSystemCalls == 0;\n"
                    "    }\n"
                ),
                "security/sandbox/chromium/base/threading/platform_thread_win.cc": (
                    "    [[maybe_unused]] const BOOL memory_priority_success =\n"
                    "        SetThreadInformation(platform_handle, ::ThreadMemoryPriority,\n"
                    "                             &memory_priority, sizeof(memory_priority));\n"
                    "  [[maybe_unused]] const BOOL success = ::SetThreadInformation(\n"
                    "      thread_handle.platform_handle(), ::ThreadPowerThrottling,\n"
                    "      &thread_power_throttling_state, sizeof(thread_power_throttling_state));\n"
                ),
                "browser/components/shell/rust/shell_windows/src/taskbar/shortcut.rs": (
                    "use windows::{\n"
                    "    core::{Error as WinError, Interface, PCWSTR},\n"
                    "    Storage::UserDataPaths,\n"
                    "    Win32::{\n"
                    "        Foundation::{E_FAIL, MAX_PATH},\n"
                    "        Storage::{\n"
                    "            EnhancedStorage::PKEY_AppUserModel_ID,\n"
                    "            Packaging::Appx::APPLICATION_USER_MODEL_ID_MAX_LENGTH,\n"
                    "        },\n"
                    "        System::Com::{\n"
                    "            CoCreateInstance, IPersistFile,\n"
                    "            StructuredStorage::{PropVariantClear, PropVariantToString},\n"
                    "            CLSCTX_INPROC_SERVER, STGM,\n"
                    "        },\n"
                    "        UI::Shell::{IShellLinkW, PropertiesSystem::IPropertyStore, ShellLink as ShellLinkClsid},\n"
                    "    },\n"
                    "};\n"
                    "    let appdata_folder = UserDataPaths::GetDefault()\n"
                    "        .and_then(|paths| paths.RoamingAppData())\n"
                    "        .map(|path| PathBuf::from(path.to_os_string()))\n"
                    "        .map_err(IsPinnedError::GetAppData)?;\n"
                    "        let mut aumid = [0u16; APPLICATION_USER_MODEL_ID_MAX_LENGTH as usize];\n"
                    "        // SAFETY: `propvar` pointer derived from a reference.\n"
                    "        unsafe { PropVariantToString(&*pv, &mut aumid) }?;\n\n"
                    "        // Strip the trailing nulls, including the null terminator.\n"
                    "        let aumid = aumid.split(|&c| c == 0).next().unwrap_or(&[]);\n"
                ),
                "browser/components/migration/MSMigrationUtils.sys.mjs": (
                    'import { ctypes } from "resource://gre/modules/ctypes.sys.mjs";\n'
                    "  get exists() {\n"
                    "    // check if there are passwords available for migration.\n"
                    "    return this.migrate(() => {}, true);\n"
                    "  },\n"
                ),
                "xpcom/base/nsWindowsHelpers.h": (
                    "HMODULE inline LoadLibrarySystem32(LPCWSTR aModule) {\n"
                    "  return LoadLibraryExW(aModule, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);\n"
                    "}\n"
                ),
                "browser/app/nsBrowserApp.cpp": (
                    '  ::LoadLibraryExW(L"cryptbase.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);\n'
                ),
                "xpcom/threads/TimerThreadMonitor_windows.cpp": (
                    '#include "mozilla/Assertions.h"\n'
                    "      mHiResTimer(CreateWaitableTimerEx(nullptr, nullptr,\n"
                    "                                        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,\n"
                    "                                        TIMER_ALL_ACCESS)),\n"
                    "      mLoResTimer(CreateWaitableTimerEx(nullptr, nullptr, 0, TIMER_ALL_ACCESS)),\n"
                    "  [[maybe_unused]] const BOOL ok = SetWaitableTimerEx(\n"
                    "      timer, &dueTime, 0, nullptr, nullptr, nullptr, timerTolerance);\n"
                ),
                "toolkit/xre/nsAppRunner.cpp": (
                    '#  include "mozilla/WindowsDllBlocklist.h"\n'
                    "#  if defined(MOZ_SANDBOX)\n"
                    "  mAppData->sandboxBrokerServices = aConfig.sandboxBrokerServices;\n"
                    "#  endif  // defined(MOZ_SANDBOX)\n"
                ),
                "third_party/rust/quinn-udp/src/windows.rs": (
                    "        let v6only = unsafe {\n"
                    "            get_socket_option::<u32>(&*socket.0, WinSock::IPPROTO_IPV6, WinSock::IPV6_V6ONLY as _)\n"
                    "        }?;\n"
                    "                    if code == WinSock::WSAENOPROTOOPT\n"
                    "                    || code == WinSock::WSAEOPNOTSUPP\n"
                    "            set_socket_option(\n"
                    "                &*socket.0,\n"
                    "                WinSock::IPPROTO_IPV6,\n"
                    "                WinSock::IPV6_DONTFRAG,\n"
                    "                OPTION_ON,\n"
                    "            )?;\n"
                    "            max_gso_segments: AtomicUsize::new(max_gso_segments(&*socket.0)),\n"
                    "    pub fn gro_segments(&self) -> usize {\n"
                    "        // Arbitrary reasonable value inspired by Linux and msquic\n"
                    "        64\n"
                    "    }\n"
                ),
                "third_party/rust/quinn-udp/.cargo-checksum.json": (
                    '{"files":{"src/windows.rs":"0000"},"package":null}'
                ),
            }
            for rel, content in files.items():
                p = ff / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")

            self.assertEqual(len(apply_win7_patches.patch_combase_and_agile_reference(ff, False)), 2)
            self.assertEqual(len(apply_win7_patches.patch_chromium_sandbox_runtime_win7(ff, False)), 6)
            self.assertEqual(len(apply_win7_patches.patch_winrt_and_widget_win7(ff, False)), 6)
            self.assertEqual(len(apply_win7_patches.patch_ipc_and_networking_win7(ff, False)), 1)

            bindings = (ff / "third_party/rust/windows-core/src/imp/bindings.rs").read_text(encoding="utf-8")
            self.assertIn("pub unsafe fn RoGetActivationFactory", bindings)
            self.assertNotIn('link!("api-ms-win-core-winrt-l1-1-0.dll"', bindings)
            wc_cs = json.loads((ff / "third_party/rust/windows-core/.cargo-checksum.json").read_text(encoding="utf-8"))
            self.assertNotEqual(wc_cs["files"]["src/imp/bindings.rs"], "0000")

            self.assertIn("ALL APPLICATION PACKAGES SID", (ff / "security/sandbox/chromium/sandbox/win/src/window.cc").read_text(encoding="utf-8"))
            sb = (ff / "security/sandbox/win/src/sandboxbroker/sandboxBroker.cpp").read_text(encoding="utf-8")
            self.assertIn("aSandboxLevel = 6;", sb)
            self.assertIn(r'\Device\KsecDD', sb)
            self.assertIn("FOLDERID_Fonts", sb)
            self.assertIn("CREATE_BREAKAWAY_FROM_JOB", (ff / "security/sandbox/chromium/sandbox/win/src/target_process.cc").read_text(encoding="utf-8"))
            self.assertIn("KonfoxRtlGenRandomAdapter", (ff / "security/sandbox/chromium/sandbox/win/src/win_utils.cc").read_text(encoding="utf-8"))
            self.assertIn("pGetProcessMitigationPolicy", (ff / "security/sandbox/chromium/base/win/win_util.cc").read_text(encoding="utf-8"))
            self.assertEqual((ff / "security/sandbox/chromium/base/threading/platform_thread_win.cc").read_text(encoding="utf-8").count("pSetThreadInformation"), 6)

            sc = (ff / "browser/components/shell/rust/shell_windows/src/taskbar/shortcut.rs").read_text(encoding="utf-8")
            self.assertIn("SHGetFolderPathW(", sc)
            self.assertNotIn("UserDataPaths::", sc)
            self.assertIn("VT_LPWSTR", sc)
            self.assertIn('isPlatformAndVersionAtLeast("win", "6.2")', (ff / "browser/components/migration/MSMigrationUtils.sys.mjs").read_text(encoding="utf-8"))
            self.assertIn("ConstructSystem32Path", (ff / "xpcom/base/nsWindowsHelpers.h").read_text(encoding="utf-8"))
            self.assertIn('::LoadLibraryW(L"cryptbase.dll");', (ff / "browser/app/nsBrowserApp.cpp").read_text(encoding="utf-8"))
            self.assertIn("CreateWaitableTimerW(nullptr, FALSE, nullptr)", (ff / "xpcom/threads/TimerThreadMonitor_windows.cpp").read_text(encoding="utf-8"))
            self.assertIn("mozilla::RandomUint64OrDie()", (ff / "toolkit/xre/nsAppRunner.cpp").read_text(encoding="utf-8"))

            qu = (ff / "third_party/rust/quinn-udp/src/windows.rs").read_text(encoding="utf-8")
            self.assertIn("let v6only = if is_ipv6 {", qu)
            self.assertIn("if !is_ecn_unsupported(&e)", qu)
            self.assertIn("Windows 7 does not support UDP GRO.", qu)

            # Branding pref check
            branding_js = (
                Path(__file__).resolve().parent.parent
                / "branding/konfox/pref/firefox-branding.js"
            ).read_text(encoding="utf-8")
            self.assertIn('pref("network.proxy.detect_system_proxy_changes", false);', branding_js)

            # Pass 2: 100% idempotent
            self.assertEqual(apply_win7_patches.patch_combase_and_agile_reference(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_chromium_sandbox_runtime_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_winrt_and_widget_win7(ff, False), [])
            self.assertEqual(apply_win7_patches.patch_ipc_and_networking_win7(ff, False), [])

    def test_step28_profile_launcher_and_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ff = Path(tmp) / "firefox"
            files = {
                "browser/app/winlauncher/LauncherProcessWin.cpp": (
                    "Maybe<int> LauncherMain(int& argc, wchar_t* argv[]) {\n"
                    "  // Called from the launcher process *and* the browser process.\n"
                    "  EnablePreferLoadFromSystem32IfCompatible();\n"
                    "  return Nothing();\n"
                    "}\n"
                ),
                "browser/moz.configure": (
                    'imply_option("MOZ_APP_VENDOR", "Mozilla")\n'
                    'imply_option("MOZ_APP_ID", "{ec8030f7-c20a-464f-9b0e-13a3a9e97384}")\n'
                ),
                "mozglue/misc/PreXULSkeletonUI.cpp": (
                    "  std::wstring profileDbPath(roamingAppData.get());\n"
                    "  profileDbPath.append(\n"
                    '      L"\\\\" MOZ_APP_VENDOR L"\\\\" MOZ_APP_BASENAME L"\\\\profiles.ini");\n'
                ),
                "toolkit/crashreporter/crash_helper_server/src/logging/env.rs": (
                    '        } else if #[cfg(target_os = "windows")] {\n'
                    '            Some(home_dir.join("AppData").join("Roaming").join(config::MOZ_APP_VENDOR).join(config::MOZ_APP_BASENAME))\n'
                    "        }\n"
                ),
                "xpcom/build/LateWriteChecks.cpp": (
                    "void InitLateWriteChecks() {\n"
                    "  sLateWriteObserver = nullptr;\n"
                    "}\n\n"
                    "void BeginLateWriteChecks() {\n"
                    "  if (sLateWriteObserver) {}\n"
                    "}\n"
                ),
                "toolkit/components/telemetry/core/Telemetry.cpp": (
                    "NS_IMETHODIMP\n"
                    "TelemetryImpl::SetCanRecordBase(bool canRecord) {\n"
                    "  mCanRecordBase = canRecord;\n"
                    "  return NS_OK;\n"
                    "}\n\n"
                    "NS_IMETHODIMP\n"
                    "TelemetryImpl::SetCanRecordExtended(bool canRecord) {\n"
                    "  mCanRecordExtended = canRecord;\n"
                    "  return NS_OK;\n"
                    "}\n"
                ),
                "toolkit/components/glean/xpcom/FOG.cpp": (
                    "void FOG::Shutdown() {\n"
                    "  MOZ_ASSERT(XRE_IsParentProcess());\n"
                    "\n"
                    "  if (mIsShutdown) {\n"
                    "    return;\n"
                    "  }\n"
                    "\n"
                    "  UnregisterWeakMemoryReporter(this);\n"
                    "  glean::impl::fog_shutdown();\n"
                    "}\n\n"
                    "NS_IMETHODIMP\n"
                    "FOG::InitializeFOG(const nsACString& aDataPathOverride,\n"
                    "                   const nsACString& aAppIdOverride,\n"
                    "                   const bool aDisableInternalPings) {\n"
                    "  MOZ_ASSERT(XRE_IsParentProcess());\n"
                    "  gInitializeCalled = true;\n"
                    "  return NS_OK;\n"
                    "}\n"
                ),
            }
            for rel, content in files.items():
                p = ff / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")

            touched = apply_win7_patches.patch_konfox_profile_launcher_and_telemetry(ff, False)
            self.assertEqual(len(touched), 7)

            self.assertIn("if (!mozilla::IsWin8OrLater())", (ff / "browser/app/winlauncher/LauncherProcessWin.cpp").read_text(encoding="utf-8"))
            bm = (ff / "browser/moz.configure").read_text(encoding="utf-8")
            self.assertIn('imply_option("MOZ_APP_VENDOR", "Konfox")', bm)
            self.assertIn('imply_option("MOZ_APP_PROFILE", "Konfox")', bm)
            self.assertIn('L"\\\\" MOZ_APP_BASENAME L"\\\\profiles.ini"', (ff / "mozglue/misc/PreXULSkeletonUI.cpp").read_text(encoding="utf-8"))
            self.assertNotIn("MOZ_APP_VENDOR", (ff / "toolkit/crashreporter/crash_helper_server/src/logging/env.rs").read_text(encoding="utf-8"))
            lwc = (ff / "xpcom/build/LateWriteChecks.cpp").read_text(encoding="utf-8")
            self.assertIn("never write Telemetry.LateWriteFinal-* files", lwc)
            self.assertIn("never register late-write IO interposer", lwc)
            tel = (ff / "toolkit/components/telemetry/core/Telemetry.cpp").read_text(encoding="utf-8")
            self.assertEqual(tel.count("[Könfox] Telemetry completely disabled."), 2)
            fog = (ff / "toolkit/components/glean/xpcom/FOG.cpp").read_text(encoding="utf-8")
            self.assertIn("sKonfoxFogSkipped = true;", fog)
            self.assertIn("if (sKonfoxFogSkipped)", fog)

            # Check mozconfigs and branding prefs
            root = Path(__file__).resolve().parent.parent
            for mc_name in ("mozconfigs/konfox-fast-win64.mozconfig", "mozconfigs/konfox-nightly-win64.mozconfig"):
                mc = (root / mc_name).read_text(encoding="utf-8")
                self.assertIn("ac_add_options --disable-launcher-process", mc)
                self.assertIn("ac_add_options --disable-legacy-profile-creation", mc)
                self.assertIn("ac_add_options MOZ_TELEMETRY_REPORTING=", mc)

            bjs = (root / "branding/konfox/pref/firefox-branding.js").read_text(encoding="utf-8")
            for key in (
                'pref("browser.launcherProcess.enabled", false);',
                'pref("datareporting.policy.dataSubmissionEnabled", false);',
                'pref("datareporting.healthreport.uploadEnabled", false);',
                'pref("toolkit.telemetry.enabled", false);',
                'pref("toolkit.telemetry.unified", false);',
                'pref("toolkit.shutdown.lateWriteChecksStage", 0);',
            ):
                self.assertIn(key, bjs)

            # Pass 2: 100% idempotent
            self.assertEqual(apply_win7_patches.patch_konfox_profile_launcher_and_telemetry(ff, False), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
