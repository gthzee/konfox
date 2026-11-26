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


if __name__ == "__main__":
    unittest.main(verbosity=2)
