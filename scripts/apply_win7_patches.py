#!/usr/bin/env python3
"""
apply_win7_patches.py — Clean, strictly Windows 7 SP1 x64 patcher for Firefox Nightly.

Why this is cleaner than a 220-patch legacy queue:
  * We target Windows 7 SP1 x64 ONLY — no Windows XP/Vista/32-bit workarounds
    (SRWLOCK, CONDITION_VARIABLE, SetWaitableTimerEx, K32 PSAPI, and Firefox's
    Windows content sandbox all work natively on Win7 SP1 x64!).
  * Built-in surgical Python transforms handle Nightly code drift cleanly
    (idempotent: safe to re-run without double-patching).
  * Eliminates every Windows 8 / 8.1 / 10+ static PE import across konfox.exe,
    xul.dll, mozglue.dll, plugin-container.exe, libGLESv2.dll, mozinference.dll,
    and helper binaries via dynamic GetProcAddress lookups with Win7 SP1 fallbacks
    (while keeping 100% native behavior on Windows 8/10/11!).
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


def _remove_mozbuild_lib(path: Path, lib_name: str, dry_run: bool) -> bool:
    """Remove a quoted library entry like `"mincore"` from a moz.build file."""
    if not path.is_file():
        return False
    original = path.read_text(encoding="utf-8")
    # Case 1: standalone list line:   "pathcch",\n
    updated = re.sub(
        rf'^[ \t]*"{re.escape(lib_name)}"[ \t]*,?[ \t]*\r?\n',
        "",
        original,
        flags=re.MULTILINE,
    )
    # Case 2: inline list item:  , "mincore"  or  "mincore", 
    updated = re.sub(rf',\s*"{re.escape(lib_name)}"', "", updated)
    updated = re.sub(rf'"{re.escape(lib_name)}"\s*,\s*', "", updated)
    if updated != original:
        if not dry_run:
            path.write_text(updated, encoding="utf-8")
        return True
    return False


# ---------------------------------------------------------------------------
# Transform 1: Lower PE subsystem version from 10.0 -> 6.01 (Windows 7 SP1)
# ---------------------------------------------------------------------------
def patch_windows_subsystem(firefox_dir: Path, dry_run: bool) -> list[str]:
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


# ---------------------------------------------------------------------------
# Transform 2: Relax NSIS installer OS version checks from Win10 -> Win7 SP1
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
# Transform 3: Restore IsWin7OrLater / IsWin8OrLater / IsWin10OrLater helpers
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
# Transform 4: Dynamically load Win8+ CM_Register_Notification / Unregister
#              in dom/webserial/Win32SerialPlatformService.cpp
# ---------------------------------------------------------------------------
CFGMGR_SHIM_REGISTER = """\
  // [Könfox Win7] CM_Register_Notification requires Windows 8+.
  CONFIGRET cr = CR_CALL_NOT_IMPLEMENTED;
  if (HMODULE cfgmgr = LoadLibraryW(L"CfgMgr32.dll")) {
    using RegisterNotificationFn = CONFIGRET(WINAPI*)(
        PCM_NOTIFY_FILTER, PVOID, PCM_NOTIFY_CALLBACK, PHCMNOTIFICATION);
    if (auto fn = reinterpret_cast<RegisterNotificationFn>(
            reinterpret_cast<void*>(GetProcAddress(cfgmgr, "CM_Register_Notification")))) {
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
            reinterpret_cast<void*>(GetProcAddress(cfgmgr, "CM_Unregister_Notification")))) {
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
# Transform 5: Eliminate WinRT & GetCurrentPackageFullName static imports
#              from konfox.exe (winlauncher), WindowsUserChoice, defaultagent
# ---------------------------------------------------------------------------
LAUNCHER_GET_FACTORY_OLD = """\
    ComPtr<IAppInstanceStatics> appInstanceStatics;
    HRESULT hr = GetActivationFactory(
        HStringReference(RuntimeClass_Windows_ApplicationModel_AppInstance)
            .Get(),
        appInstanceStatics.GetAddressOf());"""

LAUNCHER_GET_FACTORY_NEW = """\
    // [Könfox Win7] Dynamically resolve WinRT so konfox.exe has zero static
    // imports from api-ms-win-core-winrt-*.dll on Windows 7 SP1.
    using WindowsCreateStringReferenceFn =
        HRESULT(WINAPI*)(PCWSTR, UINT32, HSTRING_HEADER*, HSTRING*);
    using RoGetActivationFactoryFn = HRESULT(WINAPI*)(HSTRING, REFIID, void**);
    HMODULE hStr = ::LoadLibraryW(L"api-ms-win-core-winrt-string-l1-1-0.dll");
    HMODULE hRt = ::LoadLibraryW(L"api-ms-win-core-winrt-l1-1-0.dll");
    auto pCreateStrRef =
        hStr ? reinterpret_cast<WindowsCreateStringReferenceFn>(
            reinterpret_cast<void*>(::GetProcAddress(hStr, "WindowsCreateStringReference")))
             : nullptr;
    auto pRoGetFactory =
        hRt ? reinterpret_cast<RoGetActivationFactoryFn>(
            reinterpret_cast<void*>(::GetProcAddress(hRt, "RoGetActivationFactory")))
            : nullptr;
    ComPtr<IAppInstanceStatics> appInstanceStatics;
    HRESULT hr = E_NOTIMPL;
    if (pCreateStrRef && pRoGetFactory) {
      const wchar_t* kClassName =
          RuntimeClass_Windows_ApplicationModel_AppInstance;
      HSTRING_HEADER header{};
      HSTRING hClassName = nullptr;
      hr = pCreateStrRef(kClassName, static_cast<UINT32>(::lstrlenW(kClassName)),
                         &header, &hClassName);
      if (SUCCEEDED(hr)) {
        hr = pRoGetFactory(
            hClassName, __uuidof(IAppInstanceStatics),
            reinterpret_cast<void**>(appInstanceStatics.GetAddressOf()));
      }
    }"""

LAUNCHER_PACKAGE_OLD = "  LONG rc = GetCurrentPackageFullName(&length, NULL);"
LAUNCHER_PACKAGE_NEW = """\
  // [Könfox Win7] GetCurrentPackageFullName requires Windows 8+.
  using GetCurrentPackageFullNameFn = LONG(WINAPI*)(UINT32*, PWSTR);
  static const auto pGetCurrentPackageFullName =
      reinterpret_cast<GetCurrentPackageFullNameFn>(
            reinterpret_cast<void*>(::GetProcAddress(
          ::GetModuleHandleW(L"kernel32.dll"), "GetCurrentPackageFullName")));
  if (!pGetCurrentPackageFullName) {
    return false;
  }
  LONG rc = pGetCurrentPackageFullName(&length, NULL);"""


def patch_winlauncher_and_appmodel(firefox_dir: Path, dry_run: bool) -> list[str]:
    touched: list[str] = []

    if _remove_mozbuild_lib(firefox_dir / "browser/app/winlauncher/moz.build", "runtimeobject", dry_run):
        touched.append("browser/app/winlauncher/moz.build")

    lp = firefox_dir / "browser/app/winlauncher/LauncherProcessWin.cpp"
    if lp.is_file():
        text = lp.read_text(encoding="utf-8")
        new_text = text
        if LAUNCHER_GET_FACTORY_OLD in new_text:
            new_text = new_text.replace(LAUNCHER_GET_FACTORY_OLD, LAUNCHER_GET_FACTORY_NEW, 1)
        if LAUNCHER_PACKAGE_OLD in new_text:
            new_text = new_text.replace(LAUNCHER_PACKAGE_OLD, LAUNCHER_PACKAGE_NEW, 1)
        if new_text != text:
            if not dry_run:
                lp.write_text(new_text, encoding="utf-8")
            touched.append("browser/app/winlauncher/LauncherProcessWin.cpp")

    uc = firefox_dir / "browser/components/shell/WindowsUserChoice.cpp"
    if uc.is_file():
        text = uc.read_text(encoding="utf-8")
        if "[Könfox Win7]" not in text and "GetCurrentPackageFullName(" in text:
            old_block = """\
  UINT32 pfnLen = 0;
  LONG rv = GetCurrentPackageFullName(&pfnLen, nullptr);
  NS_ENSURE_TRUE(rv != APPMODEL_ERROR_NO_PACKAGE, NS_ERROR_FAILURE);

  auto pfn = std::make_unique<wchar_t[]>(pfnLen);
  rv = GetCurrentPackageFullName(&pfnLen, pfn.get());"""
            new_block = """\
  // [Könfox Win7] GetCurrentPackageFullName requires Windows 8+.
  using GetCurrentPackageFullNameFn = LONG(WINAPI*)(UINT32*, PWSTR);
  static const auto pGetCurrentPackageFullName =
      reinterpret_cast<GetCurrentPackageFullNameFn>(
            reinterpret_cast<void*>(::GetProcAddress(
          ::GetModuleHandleW(L"kernel32.dll"), "GetCurrentPackageFullName")));
  if (!pGetCurrentPackageFullName) {
    return NS_ERROR_FAILURE;
  }
  UINT32 pfnLen = 0;
  LONG rv = pGetCurrentPackageFullName(&pfnLen, nullptr);
  NS_ENSURE_TRUE(rv != APPMODEL_ERROR_NO_PACKAGE, NS_ERROR_FAILURE);

  auto pfn = std::make_unique<wchar_t[]>(pfnLen);
  rv = pGetCurrentPackageFullName(&pfnLen, pfn.get());"""
            if old_block in text:
                if not dry_run:
                    uc.write_text(text.replace(old_block, new_block, 1), encoding="utf-8")
                touched.append("browser/components/shell/WindowsUserChoice.cpp")

    da = firefox_dir / "toolkit/mozapps/defaultagent/SetDefaultBrowser.cpp"
    if da.is_file():
        text = da.read_text(encoding="utf-8")
        if "[Könfox Win7]" not in text and "GetCurrentPackageFullName(" in text:
            old_da = """\
  UINT32 pfnLen = 0;
  bool inMsix =
      GetCurrentPackageFullName(&pfnLen, nullptr) != APPMODEL_ERROR_NO_PACKAGE;"""
            new_da = """\
  // [Könfox Win7] GetCurrentPackageFullName requires Windows 8+.
  using GetCurrentPackageFullNameFn = LONG(WINAPI*)(UINT32*, PWSTR);
  static const auto pGetCurrentPackageFullName =
      reinterpret_cast<GetCurrentPackageFullNameFn>(
            reinterpret_cast<void*>(::GetProcAddress(
          ::GetModuleHandleW(L"kernel32.dll"), "GetCurrentPackageFullName")));
  UINT32 pfnLen = 0;
  bool inMsix = pGetCurrentPackageFullName &&
                pGetCurrentPackageFullName(&pfnLen, nullptr) !=
                    APPMODEL_ERROR_NO_PACKAGE;"""
            if old_da in text:
                if not dry_run:
                    da.write_text(text.replace(old_da, new_da, 1), encoding="utf-8")
                touched.append("toolkit/mozapps/defaultagent/SetDefaultBrowser.cpp")

    return touched


# ---------------------------------------------------------------------------
# Transform 6: Chromium sandbox dynamic kernel32 Win8+ lookups
#              Fixes konfox.exe (4), plugin-container.exe (2), xul.dll (1)
# ---------------------------------------------------------------------------
def patch_chromium_sandbox_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    touched: list[str] = []

    pm = firefox_dir / "security/sandbox/chromium/sandbox/win/src/process_mitigations.cc"
    if pm.is_file():
        text = pm.read_text(encoding="utf-8")
        if "[Könfox Win7]" not in text:
            new_text = text

            # 1. GetSupportedMitigations(): avoid static GetProcessMitigationPolicy
            #    AND avoid NOTREACHED() crash on Win7 where API is absent.
            old_get = """\
    if (!::GetProcessMitigationPolicy(::GetCurrentProcess(),
                                      ProcessMitigationOptionsMask,
                                      &mitigations, mits_size)) {
      NOTREACHED();
    }"""
            new_get = """\
    // [Könfox Win7] GetProcessMitigationPolicy requires Windows 8+.
    static const auto pGetProcessMitigationPolicy =
        reinterpret_cast<decltype(&::GetProcessMitigationPolicy)>(
            reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"),
                             "GetProcessMitigationPolicy")));
    if (pGetProcessMitigationPolicy &&
        !pGetProcessMitigationPolicy(::GetCurrentProcess(),
                                     ProcessMitigationOptionsMask,
                                     &mitigations, mits_size)) {
      NOTREACHED();
    }"""
            if old_get in new_text:
                new_text = new_text.replace(old_get, new_get, 1)

            # 2. SetProcessMitigationPolicyInternal(): return false cleanly on Win7
            #    before PCHECK so process startup does not abort.
            old_set = """\
  PCHECK(::SetProcessMitigationPolicy(policy, lpBuffer, dwLength))
      << "SetProcessMitigationPolicy failed with Policy: " << policy;"""
            new_set = """\
  // [Könfox Win7] SetProcessMitigationPolicy requires Windows 8+.
  static const auto pSetProcessMitigationPolicy =
      reinterpret_cast<decltype(&::SetProcessMitigationPolicy)>(
            reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"),
                           "SetProcessMitigationPolicy")));
  if (!pSetProcessMitigationPolicy) {
    return false;
  }
  PCHECK(pSetProcessMitigationPolicy(policy, lpBuffer, dwLength))
      << "SetProcessMitigationPolicy failed with Policy: " << policy;"""
            if old_set in new_text:
                new_text = new_text.replace(old_set, new_set, 1)

            # 3. SetDefaultDllDirectories(): available on Win7 w/ KB2533623 and Win8+,
            #    absent on unpatched Win7 SP1 -> dynamically resolve & skip if missing.
            old_dll = """\
  if (flags & MITIGATION_DLL_SEARCH_ORDER) {
    if (!::SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)) {
      return false;
    }

    applied_flags |= MITIGATION_DLL_SEARCH_ORDER;
  }"""
            new_dll = """\
  if (flags & MITIGATION_DLL_SEARCH_ORDER) {
    // [Könfox Win7] SetDefaultDllDirectories requires KB2533623 on Win7 or Win8+.
    static const auto pSetDefaultDllDirectories =
        reinterpret_cast<decltype(&::SetDefaultDllDirectories)>(
            reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"),
                             "SetDefaultDllDirectories")));
    if (pSetDefaultDllDirectories) {
      if (!pSetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)) {
        return false;
      }
      applied_flags |= MITIGATION_DLL_SEARCH_ORDER;
    }
  }"""
            if old_dll in new_text:
                new_text = new_text.replace(old_dll, new_dll, 1)

            # 4. SetThreadInformation(): requires Win8+ (already guarded by WIN10_RS1).
            old_thr = """\
    if (!::SetThreadInformation(::GetCurrentThread(), ThreadDynamicCodePolicy,
                                &thread_policy, sizeof(thread_policy))) {
      return false;
    }"""
            new_thr = """\
    // [Könfox Win7] SetThreadInformation requires Windows 8+.
    static const auto pSetThreadInformation =
        reinterpret_cast<decltype(&::SetThreadInformation)>(
            reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"),
                             "SetThreadInformation")));
    if (!pSetThreadInformation ||
        !pSetThreadInformation(::GetCurrentThread(), ThreadDynamicCodePolicy,
                               &thread_policy, sizeof(thread_policy))) {
      return false;
    }"""
            if old_thr in new_text:
                new_text = new_text.replace(old_thr, new_thr, 1)

            if new_text != text:
                if not dry_run:
                    pm.write_text(new_text, encoding="utf-8")
                touched.append("security/sandbox/chromium/sandbox/win/src/process_mitigations.cc")

    wu = firefox_dir / "security/sandbox/chromium/base/win/win_util.cc"
    if wu.is_file():
        text = wu.read_text(encoding="utf-8")
        if "[Könfox Win7]" not in text:
            new_text = text
            old_u32 = """\
    if (::GetProcessMitigationPolicy(GetCurrentProcess(),
                                     ProcessSystemCallDisablePolicy, &policy,
                                     sizeof(policy))) {"""
            new_u32 = """\
    // [Könfox Win7] GetProcessMitigationPolicy requires Windows 8+.
    static const auto pGetProcessMitigationPolicy =
        reinterpret_cast<decltype(&::GetProcessMitigationPolicy)>(
            reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"),
                             "GetProcessMitigationPolicy")));
    if (pGetProcessMitigationPolicy &&
        pGetProcessMitigationPolicy(GetCurrentProcess(),
                                    ProcessSystemCallDisablePolicy, &policy,
                                    sizeof(policy))) {"""
            if old_u32 in new_text:
                new_text = new_text.replace(old_u32, new_u32, 1)

            if new_text != text:
                if not dry_run:
                    wu.write_text(new_text, encoding="utf-8")
                touched.append("security/sandbox/chromium/base/win/win_util.cc")

    tw = firefox_dir / "security/sandbox/chromium/base/time/time_win.cc"
    if tw.is_file():
        text = tw.read_text(encoding="utf-8")
        if "[Könfox Win7]" not in text:
            old_tw = "  ::GetSystemTimePreciseAsFileTime(&ft);"
            new_tw = """\
  // [Könfox Win7] GetSystemTimePreciseAsFileTime requires Windows 8+.
  static const auto pGetSystemTimePreciseAsFileTime = []() {
    auto fn = reinterpret_cast<decltype(&::GetSystemTimeAsFileTime)>(
            reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"),
                         "GetSystemTimePreciseAsFileTime")));
    return fn ? fn : &::GetSystemTimeAsFileTime;
  }();
  pGetSystemTimePreciseAsFileTime(&ft);"""
            if old_tw in text:
                if not dry_run:
                    tw.write_text(text.replace(old_tw, new_tw, 1), encoding="utf-8")
                touched.append("security/sandbox/chromium/base/time/time_win.cc")

    return touched


# ---------------------------------------------------------------------------
# Transform 7: mozglue.dll Win7 Futex fallback + remove Win8+ "mincore" lib
# ---------------------------------------------------------------------------
FUTEX_WINDOWS_WIN7 = """\
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// [Könfox Win7] Dynamic WaitOnAddress/WakeByAddress* on Windows 8+ with a
// deadlock-free 256-bucket SRWLOCK + CONDITION_VARIABLE fallback on Windows 7.

#include "mozilla/Futex.h"

#include <windows.h>

namespace mozilla {

namespace {

using WaitOnAddressFn = BOOL(WINAPI*)(volatile VOID*, PVOID, SIZE_T, DWORD);
using WakeByAddressSingleFn = VOID(WINAPI*)(PVOID);
using WakeByAddressAllFn = VOID(WINAPI*)(PVOID);

static INIT_ONCE sFutexApiOnce = INIT_ONCE_STATIC_INIT;
static WaitOnAddressFn sWaitOnAddress = nullptr;
static WakeByAddressSingleFn sWakeSingle = nullptr;
static WakeByAddressAllFn sWakeAll = nullptr;

static BOOL CALLBACK InitWin8FutexApi(PINIT_ONCE, PVOID, PVOID*) {
  HMODULE mod = ::LoadLibraryW(L"api-ms-win-core-synch-l1-2-0.dll");
  if (mod) {
    auto w = reinterpret_cast<WaitOnAddressFn>(
            reinterpret_cast<void*>(::GetProcAddress(mod, "WaitOnAddress")));
    auto s = reinterpret_cast<WakeByAddressSingleFn>(
            reinterpret_cast<void*>(::GetProcAddress(mod, "WakeByAddressSingle")));
    auto a = reinterpret_cast<WakeByAddressAllFn>(
            reinterpret_cast<void*>(::GetProcAddress(mod, "WakeByAddressAll")));
    if (w && s && a) {
      sWaitOnAddress = w;
      sWakeSingle = s;
      sWakeAll = a;
    }
  }
  return TRUE;
}

static inline void EnsureFutexApiInit() {
  ::InitOnceExecuteOnce(&sFutexApiOnce, InitWin8FutexApi, nullptr, nullptr);
}

constexpr size_t kNumFutexBuckets = 256;

struct FutexBucket {
  SRWLOCK lock;
  CONDITION_VARIABLE cond;
};

// Zero-initialized SRWLOCK_INIT / CONDITION_VARIABLE_INIT in .bss (safe during
// early DllMain / pre-main static initialization).
static FutexBucket sFutexBuckets[kNumFutexBuckets] = {};

static inline FutexBucket& BucketFor(const volatile void* aAddr) {
  uintptr_t h = reinterpret_cast<uintptr_t>(aAddr);
  h ^= (h >> 16);
  h *= 0x45d9f3bu;
  h ^= (h >> 16);
  return sFutexBuckets[h & (kNumFutexBuckets - 1)];
}

}  // namespace

static DWORD ConvertTimeout(const TimeDuration* aTimeout) {
  if (!aTimeout || *aTimeout == TimeDuration::Forever()) {
    return INFINITE;
  }
  double msecd = aTimeout->ToMilliseconds();
  if (msecd < 0.0) {
    return 0;
  }
  if (msecd > UINT32_MAX) {
    return INFINITE;
  }
  DWORD msec = static_cast<DWORD>(msecd);
  // Round sub-millisecond waits up to 1ms (bug 1437167 comment 6).
  if (msec == 0 && !aTimeout->IsZero()) {
    msec = 1;
  }
  return msec;
}

template <typename T>
bool FutexImpl<T>::wait(T aExpected, const TimeDuration* aTimeout) {
  EnsureFutexApiInit();
  DWORD timeout = ConvertTimeout(aTimeout);
  if (sWaitOnAddress) {
    return sWaitOnAddress(reinterpret_cast<volatile void*>(&mValue),
                          &aExpected, sizeof(aExpected), timeout) != FALSE;
  }
  FutexBucket& bucket = BucketFor(&mValue);
  ::AcquireSRWLockExclusive(&bucket.lock);
  if (mValue.load(std::memory_order_seq_cst) != aExpected) {
    ::ReleaseSRWLockExclusive(&bucket.lock);
    return true;
  }
  BOOL ok =
      ::SleepConditionVariableSRW(&bucket.cond, &bucket.lock, timeout, 0);
  ::ReleaseSRWLockExclusive(&bucket.lock);
  return ok != FALSE;
}

template <typename T>
void FutexImpl<T>::wake() {
  EnsureFutexApiInit();
  if (sWakeSingle) {
    sWakeSingle(reinterpret_cast<void*>(&mValue));
    return;
  }
  // Wake all waiters on the hash bucket so hash collisions never starve a
  // distinct futex word; FutexImpl::wait callers always re-check on wakeup.
  FutexBucket& bucket = BucketFor(&mValue);
  ::AcquireSRWLockExclusive(&bucket.lock);
  ::WakeAllConditionVariable(&bucket.cond);
  ::ReleaseSRWLockExclusive(&bucket.lock);
}

template <typename T>
void FutexImpl<T>::wakeAll() {
  EnsureFutexApiInit();
  if (sWakeAll) {
    sWakeAll(reinterpret_cast<void*>(&mValue));
    return;
  }
  FutexBucket& bucket = BucketFor(&mValue);
  ::AcquireSRWLockExclusive(&bucket.lock);
  ::WakeAllConditionVariable(&bucket.cond);
  ::ReleaseSRWLockExclusive(&bucket.lock);
}

template struct FutexImpl<uint32_t>;
template struct FutexImpl<uint8_t>;

}  // namespace mozilla
"""


AWAKE_TIMESTAMP_OLD = """\
AwakeTimeStamp AwakeTimeStamp::Now() {
  ULONGLONG interrupt_time;
  QueryUnbiasedInterruptTimePrecise(&interrupt_time);

  return AwakeTimeStamp(interrupt_time / kHNSperUS);
}"""

AWAKE_TIMESTAMP_NEW = """\
AwakeTimeStamp AwakeTimeStamp::Now() {
  // [Könfox Win7] QueryUnbiasedInterruptTimePrecise requires Windows 10+
  // (mincore / api-ms-win-core-realtime-l1-1-1.dll); resolve dynamically from
  // kernelbase.dll and fall back to Win7-native QueryUnbiasedInterruptTime.
  using QueryUnbiasedInterruptTimePreciseFn = VOID(WINAPI*)(PULONGLONG);
  static const auto pQueryUnbiasedInterruptTimePrecise = []() {
    HMODULE kb = ::GetModuleHandleW(L"kernelbase.dll");
    return kb ? reinterpret_cast<QueryUnbiasedInterruptTimePreciseFn>(
                    reinterpret_cast<void*>(::GetProcAddress(
                        kb, "QueryUnbiasedInterruptTimePrecise")))
              : nullptr;
  }();
  ULONGLONG interrupt_time = 0;
  if (pQueryUnbiasedInterruptTimePrecise) {
    pQueryUnbiasedInterruptTimePrecise(&interrupt_time);
  } else {
    DebugOnly<bool> rv = QueryUnbiasedInterruptTime(&interrupt_time);
    MOZ_ASSERT(rv);
  }

  return AwakeTimeStamp(interrupt_time / kHNSperUS);
}"""


def patch_mozglue_futex_and_mincore(firefox_dir: Path, dry_run: bool) -> list[str]:
    touched: list[str] = []

    if _remove_mozbuild_lib(firefox_dir / "mozglue/misc/moz.build", "mincore", dry_run):
        touched.append("mozglue/misc/moz.build")

    futex_cpp = firefox_dir / "mozglue/misc/Futex_windows.cpp"
    if futex_cpp.is_file():
        text = futex_cpp.read_text(encoding="utf-8")
        if "[Könfox Win7]" not in text:
            if not dry_run:
                futex_cpp.write_text(FUTEX_WINDOWS_WIN7, encoding="utf-8")
            touched.append("mozglue/misc/Futex_windows.cpp")

    awake_cpp = firefox_dir / "mozglue/misc/AwakeTimeStamp.cpp"
    if awake_cpp.is_file():
        text = awake_cpp.read_text(encoding="utf-8")
        if "[Könfox Win7]" not in text and AWAKE_TIMESTAMP_OLD in text:
            if not dry_run:
                awake_cpp.write_text(
                    text.replace(AWAKE_TIMESTAMP_OLD, AWAKE_TIMESTAMP_NEW, 1),
                    encoding="utf-8",
                )
            touched.append("mozglue/misc/AwakeTimeStamp.cpp")

    return touched


# ---------------------------------------------------------------------------
# Transform 8: Disable Win8+ futex in ANGLE SimpleMutex (uses built-in std::mutex)
#              Eliminates api-ms-win-core-synch-l1-2-0.dll in libGLESv2.dll & xul.dll
# ---------------------------------------------------------------------------
def patch_angle_futex(firefox_dir: Path, dry_run: bool) -> list[str]:
    p = firefox_dir / "third_party/angle/src/common/SimpleMutex.h"
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8")
    if "[Könfox Win7]" in text:
        return []
    old_block = """\
#    elif defined(ANGLE_PLATFORM_WINDOWS) && !defined(ANGLE_ENABLE_WINDOWS_UWP) && \\
        !defined(ANGLE_WINDOWS_NO_FUTEX)
// Windows has futexes since version 8, which is already end of life (let alone older versions).
// Assume support.
#        define ANGLE_USE_FUTEX 1"""
    new_block = """\
#    elif defined(ANGLE_PLATFORM_WINDOWS)
// [Könfox Win7] Disable Win8+ WaitOnAddress futex; use ANGLE MutexOnStd fallback.
#        define ANGLE_USE_FUTEX 0"""
    if old_block in text:
        if not dry_run:
            p.write_text(text.replace(old_block, new_block, 1), encoding="utf-8")
        return ["third_party/angle/src/common/SimpleMutex.h"]
    return []


# ---------------------------------------------------------------------------
# Transform 9: Dynamic shcore.dll (GetDpiForMonitor / GetScaleFactorForMonitor)
#              and api-ms-win-core-path-l1-1-0.dll (PathCchCanonicalize)
# ---------------------------------------------------------------------------
def patch_shcore_and_pathcch(firefox_dir: Path, dry_run: bool) -> list[str]:
    touched: list[str] = []

    for mozbuild, lib in (
        ("widget/windows/moz.build", "pathcch"),
        ("widget/windows/moz.build", "shcore"),
        ("toolkit/mozapps/update/common/moz.build", "pathcch"),
        ("third_party/libwebrtc/modules/desktop_capture/desktop_capture_gn/moz.build", "shcore"),
        ("third_party/libwebrtc/webrtc_gn/moz.build", "shcore"),
    ):
        if _remove_mozbuild_lib(firefox_dir / mozbuild, lib, dry_run):
            if mozbuild not in touched:
                touched.append(mozbuild)

    # 1. widget/windows/WinUtils.cpp: MonitorDPI + CanonicalizePath
    wu = firefox_dir / "widget/windows/WinUtils.cpp"
    if wu.is_file():
        text = wu.read_text(encoding="utf-8")
        new_text = text

        old_dpi = """\
float WinUtils::MonitorDPI(HMONITOR aMonitor) {
  UINT dpiX, dpiY = 96;
  GetDpiForMonitor(aMonitor ? aMonitor : GetPrimaryMonitor(), MDT_EFFECTIVE_DPI,
                   &dpiX, &dpiY);
  return dpiY;
}"""
        new_dpi = """\
float WinUtils::MonitorDPI(HMONITOR aMonitor) {
  // [Könfox Win7] GetDpiForMonitor (shcore.dll) requires Windows 8.1+.
  static const auto pGetDpiForMonitor = []() -> decltype(&::GetDpiForMonitor) {
    HMODULE mod = ::LoadLibraryW(L"shcore.dll");
    return mod ? reinterpret_cast<decltype(&::GetDpiForMonitor)>(
            reinterpret_cast<void*>(::GetProcAddress(mod, "GetDpiForMonitor")))
               : nullptr;
  }();
  if (pGetDpiForMonitor) {
    UINT dpiX = 96, dpiY = 96;
    if (SUCCEEDED(pGetDpiForMonitor(aMonitor ? aMonitor : GetPrimaryMonitor(),
                                    MDT_EFFECTIVE_DPI, &dpiX, &dpiY))) {
      return dpiY;
    }
  }
  return static_cast<float>(SystemDPI());
}"""
        if old_dpi in new_text:
            new_text = new_text.replace(old_dpi, new_dpi, 1)

        old_canon = """\
bool WinUtils::CanonicalizePath(nsAString& aPath) {
  wchar_t tempPath[MAX_PATH + 1];
  HRESULT hr = PathCchCanonicalize(tempPath, std::size(tempPath),
                                   (char16ptr_t)PromiseFlatString(aPath).get());
  if (FAILED(hr)) {
    return false;
  }"""
        new_canon = """\
bool WinUtils::CanonicalizePath(nsAString& aPath) {
  wchar_t tempPath[MAX_PATH + 1];
  // [Könfox Win7] PathCchCanonicalize (api-ms-win-core-path-l1-1-0.dll)
  // requires Windows 8+; fall back to dynamic shlwapi!PathCanonicalizeW.
  using PathCchCanonicalizeFn = HRESULT(WINAPI*)(PWSTR, size_t, PCWSTR);
  static const auto pPathCchCanonicalize = []() -> PathCchCanonicalizeFn {
    HMODULE mod = ::LoadLibraryW(L"api-ms-win-core-path-l1-1-0.dll");
    return mod ? reinterpret_cast<PathCchCanonicalizeFn>(
            reinterpret_cast<void*>(::GetProcAddress(mod, "PathCchCanonicalize")))
               : nullptr;
  }();
  if (pPathCchCanonicalize) {
    HRESULT hr = pPathCchCanonicalize(
        tempPath, std::size(tempPath),
        (char16ptr_t)PromiseFlatString(aPath).get());
    if (FAILED(hr)) {
      return false;
    }
  } else {
    using PathCanonicalizeWFn = BOOL(WINAPI*)(LPWSTR, LPCWSTR);
    static const auto pPathCanonicalizeW = []() -> PathCanonicalizeWFn {
      HMODULE mod = ::LoadLibraryW(L"shlwapi.dll");
      return mod ? reinterpret_cast<PathCanonicalizeWFn>(
                       reinterpret_cast<void*>(
                           ::GetProcAddress(mod, "PathCanonicalizeW")))
                 : nullptr;
    }();
    if (!pPathCanonicalizeW ||
        !pPathCanonicalizeW(tempPath,
                            (char16ptr_t)PromiseFlatString(aPath).get())) {
      return false;
    }
  }"""
        if old_canon in new_text:
            new_text = new_text.replace(old_canon, new_canon, 1)

        if new_text != text:
            if not dry_run:
                wu.write_text(new_text, encoding="utf-8")
            touched.append("widget/windows/WinUtils.cpp")

    # 2. toolkit/mozapps/update/common/updatecommon.cpp: PathCchCanonicalize
    uc = firefox_dir / "toolkit/mozapps/update/common/updatecommon.cpp"
    if uc.is_file():
        text = uc.read_text(encoding="utf-8")
        old_uc = "  if (FAILED(PathCchCanonicalize(canonicalPath, MAXPATHLEN, testPath))) {"
        new_uc = """\
  // [Könfox Win7] PathCchCanonicalize requires Windows 8+; fall back to
  // dynamic shlwapi!PathCanonicalizeW (no <shlwapi.h> or shlwapi.lib needed).
  using PathCchCanonicalizeFn = HRESULT(WINAPI*)(PWSTR, size_t, PCWSTR);
  static const auto pPathCchCanonicalize = []() -> PathCchCanonicalizeFn {
    HMODULE mod = ::LoadLibraryW(L"api-ms-win-core-path-l1-1-0.dll");
    return mod ? reinterpret_cast<PathCchCanonicalizeFn>(
            reinterpret_cast<void*>(::GetProcAddress(mod, "PathCchCanonicalize")))
               : nullptr;
  }();
  bool canonOk = false;
  if (pPathCchCanonicalize) {
    canonOk = SUCCEEDED(
        pPathCchCanonicalize(canonicalPath, MAXPATHLEN, testPath));
  } else {
    using PathCanonicalizeWFn = BOOL(WINAPI*)(LPWSTR, LPCWSTR);
    static const auto pPathCanonicalizeW = []() -> PathCanonicalizeWFn {
      HMODULE mod = ::LoadLibraryW(L"shlwapi.dll");
      return mod ? reinterpret_cast<PathCanonicalizeWFn>(
                       reinterpret_cast<void*>(
                           ::GetProcAddress(mod, "PathCanonicalizeW")))
                 : nullptr;
    }();
    canonOk = pPathCanonicalizeW &&
              pPathCanonicalizeW(canonicalPath, testPath) != FALSE;
  }
  if (!canonOk) {"""
        if old_uc in text:
            if not dry_run:
                uc.write_text(text.replace(old_uc, new_uc, 1), encoding="utf-8")
            touched.append("toolkit/mozapps/update/common/updatecommon.cpp")

    # 3. libwebrtc screen_capture_utils.cc: GetDpiForMonitor
    scu = firefox_dir / "third_party/libwebrtc/modules/desktop_capture/win/screen_capture_utils.cc"
    if scu.is_file():
        text = scu.read_text(encoding="utf-8")
        old_scu = "  HRESULT hr = ::GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &dpi_x, &dpi_y);"
        new_scu = """\
  // [Könfox Win7] GetDpiForMonitor (shcore.dll) requires Windows 8.1+.
  static const auto pGetDpiForMonitor = []() -> decltype(&::GetDpiForMonitor) {
    HMODULE mod = ::LoadLibraryW(L"shcore.dll");
    return mod ? reinterpret_cast<decltype(&::GetDpiForMonitor)>(
            reinterpret_cast<void*>(::GetProcAddress(mod, "GetDpiForMonitor")))
               : nullptr;
  }();
  HRESULT hr = pGetDpiForMonitor
                   ? pGetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &dpi_x, &dpi_y)
                   : E_NOTIMPL;"""
        if old_scu in text:
            if not dry_run:
                scu.write_text(text.replace(old_scu, new_scu, 1), encoding="utf-8")
            touched.append("third_party/libwebrtc/modules/desktop_capture/win/screen_capture_utils.cc")

    # 4. libwebrtc dxgi_output_duplicator.cc: GetScaleFactorForMonitor
    dod = firefox_dir / "third_party/libwebrtc/modules/desktop_capture/win/dxgi_output_duplicator.cc"
    if dod.is_file():
        text = dod.read_text(encoding="utf-8")
        old_dod = "  HRESULT hr = GetScaleFactorForMonitor(monitor_, &device_scale_factor);"
        new_dod = """\
  // [Könfox Win7] GetScaleFactorForMonitor (shcore.dll) requires Windows 8.1+.
  static const auto pGetScaleFactorForMonitor =
      []() -> decltype(&::GetScaleFactorForMonitor) {
    HMODULE mod = ::LoadLibraryW(L"shcore.dll");
    return mod ? reinterpret_cast<decltype(&::GetScaleFactorForMonitor)>(
            reinterpret_cast<void*>(::GetProcAddress(mod, "GetScaleFactorForMonitor")))
               : nullptr;
  }();
  HRESULT hr = pGetScaleFactorForMonitor
                   ? pGetScaleFactorForMonitor(monitor_, &device_scale_factor)
                   : E_NOTIMPL;"""
        if old_dod in text:
            if not dry_run:
                dod.write_text(text.replace(old_dod, new_dod, 1), encoding="utf-8")
            touched.append("third_party/libwebrtc/modules/desktop_capture/win/dxgi_output_duplicator.cc")

    # 5. libwebrtc wgc_capture_session.cc: GetScaleFactorForMonitor (2 call sites)
    wgc = firefox_dir / "third_party/libwebrtc/modules/desktop_capture/win/wgc_capture_session.cc"
    if wgc.is_file():
        text = wgc.read_text(encoding="utf-8")
        if "[Könfox Win7]" not in text and "GetScaleFactorForMonitor(" in text:
            new_text = text
            old_wgc_1 = """\
  HRESULT scale_factor_hr =
      GetScaleFactorForMonitor(monitor_.value(), &device_scale_factor);"""
            new_wgc_1 = """\
  // [Könfox Win7] GetScaleFactorForMonitor (shcore.dll) requires Windows 8.1+.
  static const auto pGetScaleFactorForMonitor1 =
      []() -> decltype(&::GetScaleFactorForMonitor) {
    HMODULE mod = ::LoadLibraryW(L"shcore.dll");
    return mod ? reinterpret_cast<decltype(&::GetScaleFactorForMonitor)>(
            reinterpret_cast<void*>(::GetProcAddress(mod, "GetScaleFactorForMonitor")))
               : nullptr;
  }();
  HRESULT scale_factor_hr =
      pGetScaleFactorForMonitor1
          ? pGetScaleFactorForMonitor1(monitor_.value(), &device_scale_factor)
          : E_NOTIMPL;"""
            if old_wgc_1 in new_text:
                new_text = new_text.replace(old_wgc_1, new_wgc_1, 1)

            old_wgc_2 = """\
    HRESULT hr =
        GetScaleFactorForMonitor(monitor_.value(), &device_scale_factor);"""
            new_wgc_2 = """\
    static const auto pGetScaleFactorForMonitor2 =
        []() -> decltype(&::GetScaleFactorForMonitor) {
      HMODULE mod = ::LoadLibraryW(L"shcore.dll");
      return mod ? reinterpret_cast<decltype(&::GetScaleFactorForMonitor)>(
            reinterpret_cast<void*>(::GetProcAddress(mod, "GetScaleFactorForMonitor")))
                 : nullptr;
    }();
    HRESULT hr =
        pGetScaleFactorForMonitor2
            ? pGetScaleFactorForMonitor2(monitor_.value(), &device_scale_factor)
            : E_NOTIMPL;"""
            if old_wgc_2 in new_text:
                new_text = new_text.replace(old_wgc_2, new_wgc_2, 1)

            if new_text != text:
                if not dry_run:
                    wgc.write_text(new_text, encoding="utf-8")
                touched.append("third_party/libwebrtc/modules/desktop_capture/win/wgc_capture_session.cc")

    return touched


# ---------------------------------------------------------------------------
# Transform 10: Dynamic GetSystemCpuSetInformation in hal/windows
# ---------------------------------------------------------------------------
def patch_cpu_sets_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    p = firefox_dir / "hal/windows/WindowsHeterogeneousCpuInfo.cpp"
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8")
    if "[Könfox Win7]" in text:
        return []
    old_block = """\
  ULONG returnedLength;
  GetSystemCpuSetInformation(NULL, 0, &returnedLength, NULL, 0);

  if (!returnedLength) {
    return Nothing();
  }

  AutoTArray<uint8_t, 1024> cpuSets;

  cpuSets.SetLength(returnedLength);

  if (!GetSystemCpuSetInformation(
          reinterpret_cast<SYSTEM_CPU_SET_INFORMATION*>(cpuSets.Elements()),
          returnedLength, &returnedLength, NULL, 0)) {"""
    new_block = """\
  // [Könfox Win7] GetSystemCpuSetInformation requires Windows 10+.
  static const auto pGetSystemCpuSetInformation =
      reinterpret_cast<decltype(&::GetSystemCpuSetInformation)>(
            reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"),
                           "GetSystemCpuSetInformation")));
  if (!pGetSystemCpuSetInformation) {
    return Nothing();
  }

  ULONG returnedLength = 0;
  pGetSystemCpuSetInformation(NULL, 0, &returnedLength, NULL, 0);

  if (!returnedLength) {
    return Nothing();
  }

  AutoTArray<uint8_t, 1024> cpuSets;

  cpuSets.SetLength(returnedLength);

  if (!pGetSystemCpuSetInformation(
          reinterpret_cast<SYSTEM_CPU_SET_INFORMATION*>(cpuSets.Elements()),
          returnedLength, &returnedLength, NULL, 0)) {"""
    if old_block in text:
        if not dry_run:
            p.write_text(text.replace(old_block, new_block, 1), encoding="utf-8")
        return ["hal/windows/WindowsHeterogeneousCpuInfo.cpp"]
    return []


# ---------------------------------------------------------------------------
# Transform 11: Dynamic GetSystemTimePreciseAsFileTime in SpiderMonkey Time.cpp
# ---------------------------------------------------------------------------
def patch_precise_time_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    p = firefox_dir / "js/src/vm/Time.cpp"
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8")
    if "[Könfox Win7]" in text:
        return []
    old_call = "  GetSystemTimePreciseAsFileTime(&ft);"
    new_call = """\
  // [Könfox Win7] GetSystemTimePreciseAsFileTime requires Windows 8+.
  static const auto pGetSystemTimePreciseAsFileTime = []() {
    auto fn = reinterpret_cast<decltype(&::GetSystemTimeAsFileTime)>(
            reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"),
                         "GetSystemTimePreciseAsFileTime")));
    return fn ? fn : &::GetSystemTimeAsFileTime;
  }();
  pGetSystemTimePreciseAsFileTime(&ft);"""
    if old_call in text:
        if not dry_run:
            p.write_text(text.replace(old_call, new_call, 1), encoding="utf-8")
        return ["js/src/vm/Time.cpp"]
    return []


# ---------------------------------------------------------------------------
# Transform 12: Dynamic EventSetInformation in TraceLoggingProvider.h (ETW)
# ---------------------------------------------------------------------------
def patch_etw_tracelogging_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    p = firefox_dir / "tools/profiler/public/ETWTools.h"
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8")
    if "TLG_HAVE_EVENT_SET_INFORMATION" in text:
        return []
    old_inc = "#  include <TraceLoggingProvider.h>"
    new_inc = (
        "// [Könfox Win7] Mode 2 resolves advapi32!EventSetInformation dynamically.\n"
        "#  ifndef TLG_HAVE_EVENT_SET_INFORMATION\n"
        "#    define TLG_HAVE_EVENT_SET_INFORMATION 2\n"
        "#  endif\n"
        "#  include <TraceLoggingProvider.h>"
    )
    if old_inc in text:
        if not dry_run:
            p.write_text(text.replace(old_inc, new_inc, 1), encoding="utf-8")
        return ["tools/profiler/public/ETWTools.h"]
    return []


# ---------------------------------------------------------------------------
# Transform 13: Dynamic SetThreadInformation in llama.cpp (mozinference.dll)
# ---------------------------------------------------------------------------
def patch_llama_cpp_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    p = firefox_dir / "third_party/llama.cpp/ggml/src/ggml-cpu/ggml-cpu-c.c"
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8")
    if "[Könfox Win7]" in text:
        return []
    old_call = """\
        if (!SetThreadInformation(GetCurrentThread(), ThreadPowerThrottling, &t, sizeof(t))) {
            GGML_LOG_DEBUG("failed to disable thread power throttling %d : (%d)\\n", prio, (int) GetLastError());
            return false;
        }"""
    new_call = """\
        {
            // [Könfox Win7] SetThreadInformation requires Windows 8+ (pure C).
            typedef BOOL(WINAPI* SetThreadInformationFn)(HANDLE, THREAD_INFORMATION_CLASS, LPVOID, DWORD);
            SetThreadInformationFn pSetThreadInformation =
                (SetThreadInformationFn)(void*) GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetThreadInformation");
            if (pSetThreadInformation &&
                !pSetThreadInformation(GetCurrentThread(), ThreadPowerThrottling, &t, sizeof(t))) {
                GGML_LOG_DEBUG("failed to disable thread power throttling %d : (%d)\\n", prio, (int) GetLastError());
                return false;
            }
        }"""
    if old_call in text:
        if not dry_run:
            p.write_text(text.replace(old_call, new_call, 1), encoding="utf-8")
        return ["third_party/llama.cpp/ggml/src/ggml-cpu/ggml-cpu-c.c"]
    return []


# ---------------------------------------------------------------------------
# Transform 14: Guard Win8+/10+ APIs in vendored Rust crates + refresh checksums
# ---------------------------------------------------------------------------
def patch_vendored_rust_crates(firefox_dir: Path, dry_run: bool) -> list[str]:
    touched: list[str] = []
    vendor_root = firefox_dir / "third_party/rust"
    if not vendor_root.is_dir():
        return touched

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
# Transform 15: Apply optional ordered git patches from patches/series
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


# ---------------------------------------------------------------------------
# 16. browser/app/konfox.exe.manifest — Win32 RT_MANIFEST with Win7 GUID
# ---------------------------------------------------------------------------
def patch_konfox_app_manifest(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    config/rules.mk looks for $(srcdir)/$(notdir $1).manifest when linking an
    executable. Because Könfox sets MOZ_APP_NAME=konfox, the build looks for
    browser/app/konfox.exe.manifest instead of firefox.exe.manifest. Without it,
    konfox.exe ships with NO embedded RT_MANIFEST and Windows 7 runs it in
    Vista compatibility mode without Common-Controls v6 or mozglue assembly.
    """
    touched: list[str] = []
    src_manifest = firefox_dir / "browser/app/firefox.exe.manifest"
    dst_manifest = firefox_dir / "browser/app/konfox.exe.manifest"
    if not src_manifest.is_file():
        return touched

    src_text = src_manifest.read_text(encoding="utf-8", errors="replace")
    win7_guid = "{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"
    new_text = src_text.replace('name="Firefox"', 'name="Konfox"').replace(
        "<description>Firefox</description>",
        "<description>Konfox</description>",
    )
    if win7_guid not in new_text.lower():
        new_text = new_text.replace(
            "</application>",
            f'      <supportedOS Id="{win7_guid}"/>\n    </application>',
            1,
        )

    existing = dst_manifest.read_text(encoding="utf-8", errors="replace") if dst_manifest.is_file() else None
    if existing != new_text:
        if not dry_run:
            dst_manifest.write_text(new_text, encoding="utf-8")
        touched.append(str(dst_manifest.relative_to(firefox_dir)))
    return touched


# ---------------------------------------------------------------------------
# 17. Eliminate static combase.dll imports (windows-core/sys + AgileReference)
# ---------------------------------------------------------------------------
def _refresh_cargo_checksum(crate_dir: Path, rel_paths: list[str], dry_run: bool) -> bool:
    checksum_file = crate_dir / ".cargo-checksum.json"
    if not checksum_file.is_file():
        return False
    data = json.loads(checksum_file.read_text(encoding="utf-8"))
    files_map = data.get("files")
    if not isinstance(files_map, dict):
        return False
    updated = False
    for rel in rel_paths:
        target = crate_dir / rel
        if not target.is_file():
            continue
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if files_map.get(rel) != digest:
            files_map[rel] = digest
            updated = True
    if updated and not dry_run:
        checksum_file.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    return updated


def patch_combase_and_agile_reference(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    Windows 7 SP1 has no combase.dll (introduced in Windows 8).
      1) Vendored Rust crates windows-core & windows-sys statically link
         CoTaskMemAlloc, CoTaskMemFree, CoCreateFreeThreadedMarshaler, and
         CoIncrementMTAUsage from combase.dll. The first three live in
         ole32.dll since Windows 2000; CoIncrementMTAUsage is Win8+ and is
         loaded dynamically with E_NOTIMPL fallback on Win7.
      2) ipc/mscom/AgileReference.cpp statically calls ::RoGetAgileReference
         (combase.dll). Load it dynamically and fall back to an in-file
         IGlobalInterfaceTable-backed IAgileReference (ole32.dll) on Win7.
    """
    touched: list[str] = []

    # --- 17a. third_party/rust/windows-core ---
    wc_dir = firefox_dir / "third_party/rust/windows-core"
    wc_changed: list[str] = []

    bindings_rs = wc_dir / "src/imp/bindings.rs"
    if bindings_rs.is_file():
        orig = bindings_rs.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            patched = patched.replace(
                'windows_link::link!("combase.dll" "system" fn CoIncrementMTAUsage(pcookie : *mut CO_MTA_USAGE_COOKIE) -> HRESULT);',
                (
                    "// [Könfox Win7] Dynamically resolve CoIncrementMTAUsage from combase.dll\n"
                    "// so xul.dll has zero static combase.dll imports on Windows 7 SP1.\n"
                    "#[allow(non_snake_case)]\n"
                    "pub unsafe fn CoIncrementMTAUsage(pcookie: *mut CO_MTA_USAGE_COOKIE) -> HRESULT {\n"
                    "    unsafe {\n"
                    "        let module = LoadLibraryExA(b\"combase.dll\\0\".as_ptr(), core::ptr::null_mut(), 0);\n"
                    "        if module.is_null() {\n"
                    "            return -2147467263i32; // E_NOTIMPL\n"
                    "        }\n"
                    "        if let Some(addr) = GetProcAddress(module, b\"CoIncrementMTAUsage\\0\".as_ptr()) {\n"
                    "            let f: unsafe extern \"system\" fn(*mut CO_MTA_USAGE_COOKIE) -> HRESULT =\n"
                    "                core::mem::transmute(addr);\n"
                    "            return f(pcookie);\n"
                    "        }\n"
                    "        -2147467263i32 // E_NOTIMPL\n"
                    "    }\n"
                    "}"
                ),
            )
            patched = patched.replace(
                'windows_link::link!("combase.dll" "system" fn CoTaskMemAlloc(',
                'windows_link::link!("ole32.dll" "system" fn CoTaskMemAlloc(',
            )
            patched = patched.replace(
                'windows_link::link!("combase.dll" "system" fn CoTaskMemFree(',
                'windows_link::link!("ole32.dll" "system" fn CoTaskMemFree(',
            )
        if patched != orig:
            if not dry_run:
                bindings_rs.write_text(patched, encoding="utf-8")
            wc_changed.append("src/imp/bindings.rs")
            touched.append(str(bindings_rs.relative_to(firefox_dir)))

    marshaler_rs = wc_dir / "src/imp/marshaler.rs"
    if marshaler_rs.is_file():
        orig = marshaler_rs.read_text(encoding="utf-8", errors="replace")
        patched = orig.replace(
            'windows_link::link!("combase.dll" "system" fn CoCreateFreeThreadedMarshaler(',
            'windows_link::link!("ole32.dll" "system" fn CoCreateFreeThreadedMarshaler(',
        )
        if patched != orig:
            if not dry_run:
                marshaler_rs.write_text(patched, encoding="utf-8")
            wc_changed.append("src/imp/marshaler.rs")
            touched.append(str(marshaler_rs.relative_to(firefox_dir)))

    if wc_changed and _refresh_cargo_checksum(wc_dir, wc_changed, dry_run):
        touched.append(str((wc_dir / ".cargo-checksum.json").relative_to(firefox_dir)))

    # --- 17b. third_party/rust/windows-sys ---
    ws_dir = firefox_dir / "third_party/rust/windows-sys"
    com_mod_rs = ws_dir / "src/Windows/Win32/System/Com/mod.rs"
    if com_mod_rs.is_file():
        orig = com_mod_rs.read_text(encoding="utf-8", errors="replace")
        patched = orig
        for sym in ("CoCreateFreeThreadedMarshaler", "CoTaskMemAlloc", "CoTaskMemFree"):
            patched = patched.replace(
                f'windows_link::link!("combase.dll" "system" fn {sym}(',
                f'windows_link::link!("ole32.dll" "system" fn {sym}(',
            )
        if patched != orig:
            if not dry_run:
                com_mod_rs.write_text(patched, encoding="utf-8")
            touched.append(str(com_mod_rs.relative_to(firefox_dir)))
            if _refresh_cargo_checksum(ws_dir, ["src/Windows/Win32/System/Com/mod.rs"], dry_run):
                touched.append(str((ws_dir / ".cargo-checksum.json").relative_to(firefox_dir)))

    # --- 17c. ipc/mscom/AgileReference.cpp ---
    agile_cpp = firefox_dir / "ipc/mscom/AgileReference.cpp"
    if agile_cpp.is_file():
        orig = agile_cpp.read_text(encoding="utf-8", errors="replace")
        if "[Könfox Win7]" not in orig and "::RoGetAgileReference(" in orig:
            patched = orig
            if '#include "mozilla/DynamicallyLinkedFunctionPtr.h"' not in patched:
                patched = patched.replace(
                    '#include "mozilla/Assertions.h"',
                    (
                        '#include <atomic>\n'
                        '#include <objidl.h>\n'
                        '#include "mozilla/Assertions.h"\n'
                        '#include "mozilla/DynamicallyLinkedFunctionPtr.h"'
                    ),
                    1,
                )
            old_create = (
                "HRESULT AgileReference_CreateImpl(RefPtr<IAgileReference>& aRefPtr, REFIID riid,\n"
                "                                  IUnknown* aObject) {\n"
                "  MOZ_ASSERT(aObject);\n"
                "  MOZ_ASSERT(IsCOMInitializedOnCurrentThread());\n"
                "  return ::RoGetAgileReference(AGILEREFERENCE_DEFAULT, riid, aObject,\n"
                "                               getter_AddRefs(aRefPtr));\n"
                "}"
            )
            new_create = """// [Könfox Win7] Fallback IAgileReference backed by COM's Global Interface Table
// (CLSID_StdGlobalInterfaceTable in ole32.dll) when combase.dll!RoGetAgileReference
// is unavailable on Windows 7 SP1.
namespace {

class GitAgileReference final : public IAgileReference {
 public:
  GitAgileReference(IGlobalInterfaceTable* aGit, DWORD aCookie)
      : mRefCnt(0), mGit(aGit), mCookie(aCookie) {
    if (mGit) {
      mGit->AddRef();
    }
  }

  ~GitAgileReference() {
    if (mGit) {
      if (mCookie) {
        mGit->RevokeInterfaceFromGlobal(mCookie);
      }
      mGit->Release();
    }
  }

  STDMETHODIMP QueryInterface(REFIID aIid, void** aOut) override {
    if (!aOut) {
      return E_POINTER;
    }
    if (aIid == IID_IUnknown || aIid == IID_IAgileReference) {
      *aOut = static_cast<IAgileReference*>(this);
      AddRef();
      return S_OK;
    }
    *aOut = nullptr;
    return E_NOINTERFACE;
  }

  STDMETHODIMP_(ULONG) AddRef() override {
    return mRefCnt.fetch_add(1, std::memory_order_relaxed) + 1;
  }

  STDMETHODIMP_(ULONG) Release() override {
    ULONG count = mRefCnt.fetch_sub(1, std::memory_order_acq_rel) - 1;
    if (count == 0) {
      delete this;
    }
    return count;
  }

  STDMETHODIMP Resolve(REFIID aIid, void** aOutInterface) override {
    if (!aOutInterface) {
      return E_POINTER;
    }
    *aOutInterface = nullptr;
    if (!mGit || !mCookie) {
      return E_UNEXPECTED;
    }
    return mGit->GetInterfaceFromGlobal(mCookie, aIid, aOutInterface);
  }

 private:
  std::atomic<ULONG> mRefCnt;
  IGlobalInterfaceTable* mGit;
  DWORD mCookie;
};

}  // namespace

HRESULT AgileReference_CreateImpl(RefPtr<IAgileReference>& aRefPtr, REFIID riid,
                                  IUnknown* aObject) {
  MOZ_ASSERT(aObject);
  MOZ_ASSERT(IsCOMInitializedOnCurrentThread());

  using RoGetAgileReferenceFn = HRESULT(WINAPI*)(
      AgileReferenceOptions, REFIID, IUnknown*, IAgileReference**);
  static const mozilla::StaticDynamicallyLinkedFunctionPtr<RoGetAgileReferenceFn>
      pRoGetAgileReference(L"combase.dll", "RoGetAgileReference");
  if (pRoGetAgileReference) {
    return pRoGetAgileReference(AGILEREFERENCE_DEFAULT, riid, aObject,
                                getter_AddRefs(aRefPtr));
  }

  RefPtr<IGlobalInterfaceTable> git;
  HRESULT hr = ::CoCreateInstance(CLSID_StdGlobalInterfaceTable, nullptr,
                                  CLSCTX_INPROC_SERVER, IID_IGlobalInterfaceTable,
                                  getter_AddRefs(git));
  if (FAILED(hr) || !git) {
    return FAILED(hr) ? hr : E_FAIL;
  }

  DWORD cookie = 0;
  hr = git->RegisterInterfaceInGlobal(aObject, riid, &cookie);
  if (FAILED(hr)) {
    return hr;
  }

  aRefPtr = new GitAgileReference(git.get(), cookie);
  return S_OK;
}"""
            if old_create in patched:
                patched = patched.replace(old_create, new_create, 1)
                if not dry_run:
                    agile_cpp.write_text(patched, encoding="utf-8")
                touched.append(str(agile_cpp.relative_to(firefox_dir)))

    return touched


# ---------------------------------------------------------------------------
# 18. SpiderMonkey JIT unwind: dynamic RtlAddGrowableFunctionTable + Win7 callback
# ---------------------------------------------------------------------------
def patch_jit_unwind_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    js/src/jit/ProcessExecutableMemory.cpp statically imports Win8+
    ntdll.dll!RtlAddGrowableFunctionTable. Resolve it dynamically via
    GetProcAddress on ntdll.dll and fall back to Win7-native
    RtlInstallFunctionTableCallback on Windows 7 SP1 x64.
    """
    touched: list[str] = []
    pem_cpp = firefox_dir / "js/src/jit/ProcessExecutableMemory.cpp"
    if not pem_cpp.is_file():
        return touched

    orig = pem_cpp.read_text(encoding="utf-8", errors="replace")
    if "[Könfox Win7]" in orig or "RtlAddGrowableFunctionTable" not in orig:
        return touched

    patched = orig
    old_decl = (
        'extern "C" NTSYSAPI DWORD NTAPI RtlAddGrowableFunctionTable(\n'
        "    PVOID* DynamicTable, PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount,\n"
        "    DWORD MaximumEntryCount, ULONG_PTR RangeBase, ULONG_PTR RangeEnd);"
    )
    new_decl = (
        "// [Könfox Win7] Dynamically resolve Win8+ ntdll!RtlAddGrowableFunctionTable\n"
        "// and fall back to RtlInstallFunctionTableCallback on Windows 7 SP1 x64.\n"
        "using KonfoxRtlAddGrowableFunctionTableFn = DWORD(NTAPI*)(\n"
        "    PVOID* DynamicTable, PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount,\n"
        "    DWORD MaximumEntryCount, ULONG_PTR RangeBase, ULONG_PTR RangeEnd);\n"
        "static PRUNTIME_FUNCTION KonfoxWin7RuntimeFunctionCallback(DWORD64 /*ControlPc*/,\n"
        "                                                           PVOID Context) {\n"
        "  return reinterpret_cast<PRUNTIME_FUNCTION>(Context);\n"
        "}"
    )
    old_call = (
        "    DWORD result = RtlAddGrowableFunctionTable(\n"
        "        &r->dynamicTable, &r->runtimeFunction, 1, 1, (ULONG_PTR)p,\n"
        "        (ULONG_PTR)p + bytes - pageSize);\n"
        "    if (result != S_OK) {\n"
        "      return false;\n"
        "    }"
    )
    new_call = (
        '    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");\n'
        "    auto addGrowable = ntdll\n"
        "        ? reinterpret_cast<KonfoxRtlAddGrowableFunctionTableFn>(\n"
        "              reinterpret_cast<void*>(\n"
        '                  ::GetProcAddress(ntdll, "RtlAddGrowableFunctionTable")))\n'
        "        : nullptr;\n"
        "    if (addGrowable) {\n"
        "      DWORD result = addGrowable(\n"
        "          &r->dynamicTable, &r->runtimeFunction, 1, 1, (ULONG_PTR)p,\n"
        "          (ULONG_PTR)p + bytes - pageSize);\n"
        "      if (result != S_OK) {\n"
        "        return false;\n"
        "      }\n"
        "    } else if (!::RtlInstallFunctionTableCallback(\n"
        "                   reinterpret_cast<DWORD64>(p) | 0x3,\n"
        "                   reinterpret_cast<DWORD64>(p),\n"
        "                   static_cast<DWORD>(bytes),\n"
        "                   &KonfoxWin7RuntimeFunctionCallback,\n"
        "                   &r->runtimeFunction, nullptr)) {\n"
        "      return false;\n"
        "    }"
    )
    if old_decl in patched and old_call in patched:
        patched = patched.replace(old_decl, new_decl, 1).replace(old_call, new_call, 1)
        if not dry_run:
            pem_cpp.write_text(patched, encoding="utf-8")
        touched.append(str(pem_cpp.relative_to(firefox_dir)))
    return touched


# ---------------------------------------------------------------------------
# 19. Dynamic kernel32!GetCurrentApplicationUserModelId + nsWindow/Toast guards
# ---------------------------------------------------------------------------
def patch_aumid_dynamic_load(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    kernel32.dll!GetCurrentApplicationUserModelId is Windows 8+ only and was
    statically imported by xul.dll from ToastNotification.cpp and nsWindow.cpp.
    Resolve it dynamically via GetProcAddress and guard Win10+ window/toast hooks.
    """
    touched: list[str] = []

    # --- 19a. widget/windows/ToastNotification.cpp ---
    toast_cpp = firefox_dir / "widget/windows/ToastNotification.cpp"
    if toast_cpp.is_file():
        orig = toast_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "ToastNotification.h"',
                    '#include "ToastNotification.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            patched = patched.replace(
                "nsresult ToastNotification::Init() {\n",
                (
                    "nsresult ToastNotification::Init() {\n"
                    "  // [Könfox Win7] Windows Toast Notifications require Windows 10+.\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return NS_ERROR_NOT_IMPLEMENTED;\n"
                    "  }\n"
                ),
                1,
            )
            old_msix = (
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
                "  LONG success = GetCurrentApplicationUserModelId(&len, buffer.Elements());"
            )
            new_msix = (
                "bool ToastNotification::AssignIfMsixAumid(Maybe<nsAutoString>& aAumid) {\n"
                "  using GetCurrentAumidFn = LONG(WINAPI*)(UINT32*, PWSTR);\n"
                '  HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");\n'
                "  auto getAumid = k32\n"
                "      ? reinterpret_cast<GetCurrentAumidFn>(\n"
                "            reinterpret_cast<void*>(\n"
                '                ::GetProcAddress(k32, "GetCurrentApplicationUserModelId")))\n'
                "      : nullptr;\n"
                "  if (!getAumid) {\n"
                "    return false;\n"
                "  }\n"
                "  UINT32 len = 0;\n"
                "  // ERROR_INSUFFICIENT_BUFFER signals that we're in an MSIX package, and\n"
                "  // therefore should use the package's AUMID.\n"
                "  if (getAumid(&len, nullptr) != ERROR_INSUFFICIENT_BUFFER) {\n"
                '    MOZ_LOG(sWASLog, LogLevel::Debug, ("Not an MSIX package"));\n'
                "    return false;\n"
                "  }\n"
                "  mozilla::Buffer<wchar_t> buffer(len);\n"
                "  LONG success = getAumid(&len, buffer.Elements());"
            )
            if old_msix in patched:
                patched = patched.replace(old_msix, new_msix, 1)
        if patched != orig:
            if not dry_run:
                toast_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(toast_cpp.relative_to(firefox_dir)))

    # --- 19b. widget/windows/nsWindow.cpp ---
    nswin_cpp = firefox_dir / "widget/windows/nsWindow.cpp"
    if nswin_cpp.is_file():
        orig = nswin_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_aumid = (
                "        (void)NS_WARN_IF(\n"
                "            GetCurrentApplicationUserModelId(&maxLength, aumid.get()));"
            )
            new_aumid = (
                "        // [Könfox Win7] Dynamically load Win8+ GetCurrentApplicationUserModelId.\n"
                "        using GetCurrentAumidFn = LONG(WINAPI*)(UINT32*, PWSTR);\n"
                '        HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");\n'
                "        auto getAumid = k32\n"
                "            ? reinterpret_cast<GetCurrentAumidFn>(\n"
                "                  reinterpret_cast<void*>(\n"
                '                      ::GetProcAddress(k32, "GetCurrentApplicationUserModelId")))\n'
                "            : nullptr;\n"
                "        if (getAumid) {\n"
                "          (void)NS_WARN_IF(getAumid(&maxLength, aumid.get()));\n"
                "        }"
            )
            if old_aumid in patched:
                patched = patched.replace(old_aumid, new_aumid, 1)
            # Also guard Win10+ window cloaking hook (EVENT_OBJECT_CLOAKED is Win8+/10+)
            patched = patched.replace(
                "  if (!sWinCloakEventHook) {",
                "  if (mozilla::IsWin10OrLater() && !sWinCloakEventHook) {",
                1,
            )
        if patched != orig:
            if not dry_run:
                nswin_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(nswin_cpp.relative_to(firefox_dir)))

    return touched


# ---------------------------------------------------------------------------
# 20. Win7 PRNG fallback (mfbt/RandomNum.cpp + Chromium rand_util_win.cc)
# ---------------------------------------------------------------------------
def patch_win7_prng_fallbacks(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    bcryptprimitives.dll!ProcessPrng was added in Windows 10. On Windows 7 SP1,
    both mfbt/RandomNum.cpp (MOZ_RELEASE_ASSERT in RandomUint64OrDie) and
    security/sandbox/chromium/base/rand_util_win.cc (CHECK(process_prng_fn))
    crash immediately on startup unless they fall back to advapi32!SystemFunction036
    (RtlGenRandom), which is natively available on Windows XP through Windows 11.
    """
    touched: list[str] = []

    # --- 20a. mfbt/RandomNum.cpp ---
    rand_cpp = firefox_dir / "mfbt/RandomNum.cpp"
    if rand_cpp.is_file():
        orig = rand_cpp.read_text(encoding="utf-8", errors="replace")
        if "[Könfox Win7]" not in orig:
            old_block = (
                "  static const mozilla::StaticDynamicallyLinkedFunctionPtr<BOOL(WINAPI*)(\n"
                "      PBYTE, SIZE_T)>\n"
                '      pProcessPrng(L"bcryptprimitives.dll", "ProcessPrng");\n'
                "  return pProcessPrng && !!pProcessPrng(static_cast<PBYTE>(aBuffer), aLength);"
            )
            new_block = (
                "  static const mozilla::StaticDynamicallyLinkedFunctionPtr<BOOL(WINAPI*)(\n"
                "      PBYTE, SIZE_T)>\n"
                '      pProcessPrng(L"bcryptprimitives.dll", "ProcessPrng");\n'
                "  if (pProcessPrng) {\n"
                "    return !!pProcessPrng(static_cast<PBYTE>(aBuffer), aLength);\n"
                "  }\n"
                "  // [Könfox Win7] Fallback to advapi32!SystemFunction036 (RtlGenRandom)\n"
                "  // when bcryptprimitives!ProcessPrng (Win10+) is unavailable.\n"
                "  static const mozilla::StaticDynamicallyLinkedFunctionPtr<BOOLEAN(WINAPI*)(\n"
                "      PVOID, ULONG)>\n"
                '      pRtlGenRandom(L"advapi32.dll", "SystemFunction036");\n'
                "  if (!pRtlGenRandom) {\n"
                "    return false;\n"
                "  }\n"
                "  uint8_t* ptr = static_cast<uint8_t*>(aBuffer);\n"
                "  size_t remaining = aLength;\n"
                "  while (remaining > 0) {\n"
                "    ULONG chunk = remaining > 0xFFFFFFFFUL\n"
                "                      ? 0xFFFFFFFFUL\n"
                "                      : static_cast<ULONG>(remaining);\n"
                "    if (!pRtlGenRandom(ptr, chunk)) {\n"
                "      return false;\n"
                "    }\n"
                "    ptr += chunk;\n"
                "    remaining -= chunk;\n"
                "  }\n"
                "  return true;"
            )
            if old_block in orig:
                patched = orig.replace(old_block, new_block, 1)
                if not dry_run:
                    rand_cpp.write_text(patched, encoding="utf-8")
                touched.append(str(rand_cpp.relative_to(firefox_dir)))

    # --- 20b. security/sandbox/chromium/base/rand_util_win.cc ---
    rand_cc = firefox_dir / "security/sandbox/chromium/base/rand_util_win.cc"
    if rand_cc.is_file():
        orig = rand_cc.read_text(encoding="utf-8", errors="replace")
        if "[Könfox Win7]" not in orig:
            old_fn = (
                "decltype(&ProcessPrng) GetProcessPrng() {\n"
                '  HMODULE hmod = LoadLibraryW(L"bcryptprimitives.dll");\n'
                "  CHECK(hmod);\n"
                "  decltype(&ProcessPrng) process_prng_fn =\n"
                "      reinterpret_cast<decltype(&ProcessPrng)>(\n"
                '          GetProcAddress(hmod, "ProcessPrng"));\n'
                "  CHECK(process_prng_fn);\n"
                "  return process_prng_fn;\n"
                "}"
            )
            new_fn = (
                "// [Könfox Win7] Fallback to advapi32!SystemFunction036 (RtlGenRandom)\n"
                "// when bcryptprimitives!ProcessPrng (Win10+) is unavailable.\n"
                "BOOL WINAPI KonfoxWin7RtlGenRandom(PBYTE pbData, SIZE_T cbData) {\n"
                "  static auto sRtlGenRandom = []() -> BOOLEAN(WINAPI*)(PVOID, ULONG) {\n"
                '    HMODULE hAdvapi = LoadLibraryW(L"advapi32.dll");\n'
                "    if (!hAdvapi) {\n"
                "      return nullptr;\n"
                "    }\n"
                "    return reinterpret_cast<BOOLEAN(WINAPI*)(PVOID, ULONG)>(\n"
                "        reinterpret_cast<void*>(\n"
                '            GetProcAddress(hAdvapi, "SystemFunction036")));\n'
                "  }();\n"
                "  if (!sRtlGenRandom) {\n"
                "    return FALSE;\n"
                "  }\n"
                "  while (cbData > 0) {\n"
                "    ULONG chunk = cbData > std::numeric_limits<ULONG>::max()\n"
                "                      ? std::numeric_limits<ULONG>::max()\n"
                "                      : static_cast<ULONG>(cbData);\n"
                "    if (!sRtlGenRandom(pbData, chunk)) {\n"
                "      return FALSE;\n"
                "    }\n"
                "    pbData += chunk;\n"
                "    cbData -= chunk;\n"
                "  }\n"
                "  return TRUE;\n"
                "}\n\n"
                "decltype(&ProcessPrng) GetProcessPrng() {\n"
                '  HMODULE hmod = LoadLibraryW(L"bcryptprimitives.dll");\n'
                "  if (hmod) {\n"
                "    decltype(&ProcessPrng) process_prng_fn =\n"
                "        reinterpret_cast<decltype(&ProcessPrng)>(\n"
                "            reinterpret_cast<void*>(\n"
                '                GetProcAddress(hmod, "ProcessPrng")));\n'
                "    if (process_prng_fn) {\n"
                "      return process_prng_fn;\n"
                "    }\n"
                "  }\n"
                "  return &KonfoxWin7RtlGenRandom;\n"
                "}"
            )
            if old_fn in orig:
                patched = orig.replace(old_fn, new_fn, 1)
                if not dry_run:
                    rand_cc.write_text(patched, encoding="utf-8")
                touched.append(str(rand_cc.relative_to(firefox_dir)))

    return touched


# ---------------------------------------------------------------------------
# 21. Chromium Sandbox + Mozilla SandboxBroker Win7 SP1 runtime fixes
# ---------------------------------------------------------------------------
def patch_chromium_sandbox_runtime_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    Fixes all post-load Windows 7 SP1 x64 runtime failures in Chromium sandbox
    and Mozilla SandboxBroker:
      - process_mitigations.cc: skip Win8+ mitigation policies on < WIN8
      - broker_services.cc: skip PROC_THREAD_ATTRIBUTE_JOB_LIST (Win10+) and
        assign the suspended child process to the job via AssignProcessToJobObject
      - handle_closer_agent.cc: brute-force handle scan on < WIN8 because
        ProcessHandleTable (58) requires Windows 8+
      - sandbox_policy_base.cc: skip SetDisconnectCsrss (< WIN10) & SetFakeGdiInit (< WIN8)
      - heap_helper.cc: skip FindCsrPortHeap on < WIN10
      - window.cc: guard kAllApplicationPackages SID on >= WIN8
      - app_container_base.cc: dynamically load userenv!DeriveAppContainerSidFromAppContainerName
      - sandboxBroker.cpp: skip Win32k lockdown (< WIN8) and CIG (< WIN10)
    """
    touched: list[str] = []

    # --- 21a. process_mitigations.cc ---
    pm_cc = firefox_dir / "security/sandbox/chromium/sandbox/win/src/process_mitigations.cc"
    if pm_cc.is_file():
        orig = pm_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7 mitigations]" not in patched:
            dep_anchor = (
                "    applied_flags |=\n"
                "        combined_flags & (MITIGATION_DEP | MITIGATION_DEP_NO_ATL_THUNK);\n"
                "  }\n"
                "#endif"
            )
            if dep_anchor in patched:
                patched = patched.replace(
                    dep_anchor,
                    dep_anchor
                    + "\n\n  // [Könfox Win7 mitigations] Remaining mitigations require Windows 8+.\n"
                    "  if (version < base::win::Version::WIN8) {\n"
                    "    return true;\n"
                    "  }",
                    1,
                )
            sehop_anchor = (
                "  if (flags & MITIGATION_SEHOP)\n"
                "    *policy_value_1 |= PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE;\n"
                "#endif"
            )
            if sehop_anchor in patched:
                patched = patched.replace(
                    sehop_anchor,
                    sehop_anchor
                    + "\n\n  // [Könfox Win7 mitigations] Process creation mitigation policies require Windows 8+.\n"
                    "  if (version < base::win::Version::WIN8) {\n"
                    "    return;\n"
                    "  }",
                    1,
                )
        if patched != orig:
            if not dry_run:
                pm_cc.write_text(patched, encoding="utf-8")
            touched.append(str(pm_cc.relative_to(firefox_dir)))

    # --- 21b. broker_services.cc ---
    bs_cc = firefox_dir / "security/sandbox/chromium/sandbox/win/src/broker_services.cc"
    if bs_cc.is_file():
        orig = bs_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_job_attr = "  startup_info->AddJobToAssociate(policy_base->GetJobHandle());"
            new_job_attr = (
                "  // [Könfox Win7] PROC_THREAD_ATTRIBUTE_JOB_LIST requires Windows 10+.\n"
                "  // On Windows 7/8, assign the suspended process in FinishSpawnTargetImpl.\n"
                "  if (base::win::GetVersion() >= base::win::Version::WIN10) {\n"
                "    startup_info->AddJobToAssociate(policy_base->GetJobHandle());\n"
                "  }"
            )
            old_finish = (
                "  ConfigBase* config_base = static_cast<ConfigBase*>(policy_base->GetConfig());\n\n"
                "  if (config_base->GetJobLevel() <= JobLevel::kLimitedUser) {"
            )
            new_finish = (
                "  ConfigBase* config_base = static_cast<ConfigBase*>(policy_base->GetConfig());\n\n"
                "  if (base::win::GetVersion() < base::win::Version::WIN10) {\n"
                "    HANDLE job_handle = policy_base->GetJobHandle();\n"
                "    if (job_handle &&\n"
                "        !::AssignProcessToJobObject(job_handle, process_info->process_handle())) {\n"
                "      DWORD err = ::GetLastError();\n"
                "      // On Win7, nested jobs are unsupported if the parent is already in a\n"
                "      // non-breakaway job (ERROR_ACCESS_DENIED); allow launch to continue.\n"
                "      if (err != ERROR_ACCESS_DENIED) {\n"
                "        *last_error = err;\n"
                "        target->Terminate();\n"
                "        return SBOX_ERROR_CANNOT_INIT_JOB;\n"
                "      }\n"
                "    }\n"
                "  }\n\n"
                "  if (config_base->GetJobLevel() <= JobLevel::kLimitedUser) {"
            )
            if old_job_attr in patched and old_finish in patched:
                patched = patched.replace(old_job_attr, new_job_attr, 1).replace(
                    old_finish, new_finish, 1
                )
        if patched != orig:
            if not dry_run:
                bs_cc.write_text(patched, encoding="utf-8")
            touched.append(str(bs_cc.relative_to(firefox_dir)))

    # --- 21c. handle_closer_agent.cc ---
    hc_cc = firefox_dir / "security/sandbox/chromium/sandbox/win/src/handle_closer_agent.cc"
    if hc_cc.is_file():
        orig = hc_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "base/win/windows_version.h"' not in patched:
                patched = patched.replace(
                    '#include "base/check.h"',
                    '#include "base/check.h"\n#include "base/win/windows_version.h"',
                    1,
                )
            old_scan = (
                "  DWORD handle_count;\n"
                "  if (!::GetProcessHandleCount(::GetCurrentProcess(), &handle_count)) {\n"
                "    return false;\n"
                "  }"
            )
            new_scan = (
                "  DWORD handle_count;\n"
                "  if (!::GetProcessHandleCount(::GetCurrentProcess(), &handle_count)) {\n"
                "    return false;\n"
                "  }\n\n"
                "  // [Könfox Win7] ProcessHandleTable (58) requires Windows 8+.\n"
                "  // Enumerate open handles step-by-4 on Windows 7 SP1.\n"
                "  if (base::win::GetVersion() < base::win::Version::WIN8) {\n"
                "    constexpr int kInvalidHandleThreshold = 100;\n"
                "    constexpr uint32_t kHandleOffset = 4;\n"
                "    uint32_t handle_value = 0;\n"
                "    int invalid_count = 0;\n"
                "    DWORD remaining = handle_count;\n"
                "    while (remaining && invalid_count < kInvalidHandleThreshold) {\n"
                "      handle_value += kHandleOffset;\n"
                "      HANDLE handle = base::win::Uint32ToHandle(handle_value);\n"
                "      auto type_name = GetTypeNameFromHandle(handle);\n"
                "      if (!type_name) {\n"
                "        ++invalid_count;\n"
                "        continue;\n"
                "      }\n"
                "      --remaining;\n"
                "      MaybeCloseHandle(type_name.value(), handle);\n"
                "    }\n"
                "    return true;\n"
                "  }"
            )
            if old_scan in patched:
                patched = patched.replace(old_scan, new_scan, 1)
        if patched != orig:
            if not dry_run:
                hc_cc.write_text(patched, encoding="utf-8")
            touched.append(str(hc_cc.relative_to(firefox_dir)))

    # --- 21d. sandbox_policy_base.cc ---
    spb_cc = firefox_dir / "security/sandbox/chromium/sandbox/win/src/sandbox_policy_base.cc"
    if spb_cc.is_file():
        orig = spb_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            patched = patched.replace(
                "ResultCode ConfigBase::SetDisconnectCsrss() {\n",
                (
                    "ResultCode ConfigBase::SetDisconnectCsrss() {\n"
                    "  // [Könfox Win7] CSRSS disconnect requires Windows 10+.\n"
                    "  if (base::win::GetVersion() < base::win::Version::WIN10) {\n"
                    "    return SBOX_ALL_OK;\n"
                    "  }\n"
                ),
                1,
            )
            patched = patched.replace(
                "ResultCode ConfigBase::SetFakeGdiInit() {\n",
                (
                    "ResultCode ConfigBase::SetFakeGdiInit() {\n"
                    "  // [Könfox Win7] Win32k lockdown fake GDI init requires Windows 8+.\n"
                    "  if (base::win::GetVersion() < base::win::Version::WIN8) {\n"
                    "    return SBOX_ALL_OK;\n"
                    "  }\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                spb_cc.write_text(patched, encoding="utf-8")
            touched.append(str(spb_cc.relative_to(firefox_dir)))

    # --- 21e. heap_helper.cc ---
    hh_cc = firefox_dir / "security/sandbox/chromium/sandbox/win/src/heap_helper.cc"
    if hh_cc.is_file():
        orig = hh_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "base/win/windows_version.h"' not in patched:
                patched = patched.replace(
                    '#include "base/logging.h"',
                    '#include "base/logging.h"\n#include "base/win/windows_version.h"',
                    1,
                )
            patched = patched.replace(
                "HANDLE FindCsrPortHeap() {\n",
                (
                    "HANDLE FindCsrPortHeap() {\n"
                    "  // [Könfox Win7] CSRSS port heap inspection requires Windows 10+.\n"
                    "  if (base::win::GetVersion() < base::win::Version::WIN10) {\n"
                    "    return nullptr;\n"
                    "  }\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                hh_cc.write_text(patched, encoding="utf-8")
            touched.append(str(hh_cc.relative_to(firefox_dir)))

    # --- 21f. window.cc ---
    win_cc = firefox_dir / "security/sandbox/chromium/sandbox/win/src/window.cc"
    if win_cc.is_file():
        orig = win_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "base/win/windows_version.h"' not in patched:
                patched = patched.replace(
                    '#include "base/win/security_descriptor.h"',
                    '#include "base/win/security_descriptor.h"\n#include "base/win/windows_version.h"',
                    1,
                )
            old_ace = (
                "  if (!sd->SetDaclEntry(base::win::WellKnownSid::kAllApplicationPackages,\n"
                "                        base::win::SecurityAccessMode::kGrant,\n"
                "                        DESKTOP_GENERIC_READ | DESKTOP_GENERIC_WRITE |\n"
                "                            DESKTOP_GENERIC_EXECUTE,\n"
                "                        0)) {\n"
                "    return false;\n"
                "  }"
            )
            new_ace = (
                "  // [Könfox Win7] ALL APPLICATION PACKAGES SID (S-1-15-2-1) is Windows 8+.\n"
                "  if (base::win::GetVersion() >= base::win::Version::WIN8) {\n"
                "    if (!sd->SetDaclEntry(base::win::WellKnownSid::kAllApplicationPackages,\n"
                "                          base::win::SecurityAccessMode::kGrant,\n"
                "                          DESKTOP_GENERIC_READ | DESKTOP_GENERIC_WRITE |\n"
                "                              DESKTOP_GENERIC_EXECUTE,\n"
                "                          0)) {\n"
                "      return false;\n"
                "    }\n"
                "  }"
            )
            if old_ace in patched:
                patched = patched.replace(old_ace, new_ace, 1)
        if patched != orig:
            if not dry_run:
                win_cc.write_text(patched, encoding="utf-8")
            touched.append(str(win_cc.relative_to(firefox_dir)))

    # --- 21g. app_container_base.cc ---
    ac_cc = firefox_dir / "security/sandbox/chromium/sandbox/win/src/app_container_base.cc"
    if ac_cc.is_file():
        orig = ac_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_derive = (
                "  HRESULT hr = ::DeriveAppContainerSidFromAppContainerName(package_name,\n"
                "                                                           &package_sid_ptr);"
            )
            new_derive = (
                "  // [Könfox Win7] Dynamically load Win8+ userenv!DeriveAppContainerSidFromAppContainerName.\n"
                "  using DeriveSidFn = HRESULT(WINAPI*)(PCWSTR, PSID*);\n"
                "  static auto sDeriveSid = []() -> DeriveSidFn {\n"
                '    HMODULE hUserenv = ::LoadLibraryW(L"userenv.dll");\n'
                "    if (!hUserenv) {\n"
                "      return nullptr;\n"
                "    }\n"
                "    return reinterpret_cast<DeriveSidFn>(reinterpret_cast<void*>(\n"
                '        ::GetProcAddress(hUserenv, "DeriveAppContainerSidFromAppContainerName")));\n'
                "  }();\n"
                "  if (!sDeriveSid) {\n"
                "    return std::nullopt;\n"
                "  }\n"
                "  HRESULT hr = sDeriveSid(package_name, &package_sid_ptr);"
            )
            if old_derive in patched:
                patched = patched.replace(old_derive, new_derive, 1)
        if patched != orig:
            if not dry_run:
                ac_cc.write_text(patched, encoding="utf-8")
            touched.append(str(ac_cc.relative_to(firefox_dir)))

    # --- 21h. security/sandbox/win/src/sandboxbroker/sandboxBroker.cpp ---
    sb_cpp = firefox_dir / "security/sandbox/win/src/sandboxbroker/sandboxBroker.cpp"
    if sb_cpp.is_file():
        orig = sb_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            patched = patched.replace(
                "static sandbox::ResultCode AddWin32kLockdownConfig(\n"
                "    sandbox::TargetConfig* aConfig) {\n",
                (
                    "static sandbox::ResultCode AddWin32kLockdownConfig(\n"
                    "    sandbox::TargetConfig* aConfig) {\n"
                    "  // [Könfox Win7] Win32k lockdown requires Windows 8+.\n"
                    "  if (!mozilla::IsWin8OrLater()) {\n"
                    "    return sandbox::SBOX_ALL_OK;\n"
                    "  }\n"
                ),
                1,
            )
            patched = patched.replace(
                "static sandbox::ResultCode AddCigToConfig(\n"
                "    sandbox::TargetConfig* aConfig, bool aAlwaysProxyBinDirLoading = false) {\n",
                (
                    "static sandbox::ResultCode AddCigToConfig(\n"
                    "    sandbox::TargetConfig* aConfig, bool aAlwaysProxyBinDirLoading = false) {\n"
                    "  // [Könfox Win7] Code Integrity Guard requires Windows 10+.\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return sandbox::SBOX_ALL_OK;\n"
                    "  }\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                sb_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(sb_cpp.relative_to(firefox_dir)))

    return touched


# ---------------------------------------------------------------------------
# 22. Graphics / WebRender Win7 SP1 fixes (DirectComposition & D3D 11.1)
# ---------------------------------------------------------------------------
def patch_graphics_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    - gfx/config/gfxConfigManager.cpp: disable WebRender DirectComposition on
      < Windows 10 (dcomp.dll does not exist on Windows 7 SP1).
    - gfx/thebes/DeviceManagerDx.cpp: only request D3D_FEATURE_LEVEL_11_1 on
      Windows 8+ (Win7 SP1 without Platform Update rejects 11_1).
    """
    touched: list[str] = []

    gcm_cpp = firefox_dir / "gfx/config/gfxConfigManager.cpp"
    if gcm_cpp.is_file():
        orig = gcm_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#  include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#  include "mozilla/gfx/DeviceManagerDx.h"',
                    '#  include "mozilla/WindowsVersion.h"\n#  include "mozilla/gfx/DeviceManagerDx.h"',
                    1,
                )
            patched = patched.replace(
                "  mFeatureWrDComp->EnableByDefault();\n",
                (
                    "  mFeatureWrDComp->EnableByDefault();\n"
                    "#ifdef XP_WIN\n"
                    "  // [Könfox Win7] DirectComposition requires Windows 10+.\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    mFeatureWrDComp->Disable(FeatureStatus::Unavailable,\n"
                    '                             "DirectComposition requires Windows 10+",\n'
                    '                             "FEATURE_FAILURE_WIN7_NO_DCOMP"_ns);\n'
                    "  }\n"
                    "#endif\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                gcm_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(gcm_cpp.relative_to(firefox_dir)))

    dm_cpp = firefox_dir / "gfx/thebes/DeviceManagerDx.cpp"
    if dm_cpp.is_file():
        orig = dm_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "DeviceManagerDx.h"',
                    '#include "DeviceManagerDx.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            patched = patched.replace(
                "  mFeatureLevels.AppendElement(D3D_FEATURE_LEVEL_11_1);",
                (
                    "  // [Könfox Win7] D3D_FEATURE_LEVEL_11_1 requires Windows 8+ (or Platform Update).\n"
                    "  if (mozilla::IsWin8OrLater()) {\n"
                    "    mFeatureLevels.AppendElement(D3D_FEATURE_LEVEL_11_1);\n"
                    "  }"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                dm_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(dm_cpp.relative_to(firefox_dir)))

    return touched


# ---------------------------------------------------------------------------
# 23. WinRT / Startup / DPI / Widget / Geolocation Win7 guards
# ---------------------------------------------------------------------------
def patch_winrt_and_widget_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    Guards all unguarded WinRT delay-load callers and Win8+/10+ widget/startup
    code paths so Windows 7 SP1 never triggers 0xC06D007E delay-load crashes
    on api-ms-win-core-winrt-*.dll, shcore.dll, or Microsoft.UI.*.dll.
    """
    touched: list[str] = []

    # --- 23a. mozglue/misc/WindowsDpiInitialization.cpp ---
    dpi_cpp = firefox_dir / "mozglue/misc/WindowsDpiInitialization.cpp"
    if dpi_cpp.is_file():
        orig = dpi_cpp.read_text(encoding="utf-8", errors="replace")
        if "[Könfox Win7]" not in orig:
            old_else = (
                "  } else {\n"
                "    DynamicallyLinkedFunctionPtr<SetProcessDpiAwarenessType>"
            )
            new_else = (
                "  } else if (mozilla::IsWin8Point1OrLater()) {\n"
                "    DynamicallyLinkedFunctionPtr<SetProcessDpiAwarenessType>"
            )
            old_end = (
                "    return WindowsDpiInitializationResult::Success;\n"
                "  }\n"
                "}"
            )
            new_end = (
                "    return WindowsDpiInitializationResult::Success;\n"
                "  } else {\n"
                "    // [Könfox Win7] Fallback to Vista/Win7 SetProcessDPIAware.\n"
                "    ::SetProcessDPIAware();\n"
                "    return WindowsDpiInitializationResult::Success;\n"
                "  }\n"
                "}"
            )
            if old_else in orig and old_end in orig:
                patched = orig.replace(old_else, new_else, 1).replace(old_end, new_end, 1)
                if not dry_run:
                    dpi_cpp.write_text(patched, encoding="utf-8")
                touched.append(str(dpi_cpp.relative_to(firefox_dir)))

    # --- 23b. mozglue/misc/PreXULSkeletonUI.cpp ---
    skel_cpp = firefox_dir / "mozglue/misc/PreXULSkeletonUI.cpp"
    if skel_cpp.is_file():
        orig = skel_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "PreXULSkeletonUI.h"',
                    '#include "PreXULSkeletonUI.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            patched = patched.replace(
                "static Result<Ok, PreXULSkeletonUIError> CreateAndStorePreXULSkeletonUIImpl(\n"
                "    HINSTANCE hInstance, int argc, char** argv) {\n",
                (
                    "static Result<Ok, PreXULSkeletonUIError> CreateAndStorePreXULSkeletonUIImpl(\n"
                    "    HINSTANCE hInstance, int argc, char** argv) {\n"
                    "  // [Könfox Win7] Pre-XUL skeleton UI relies on Win10+ DWM/DPI APIs.\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return Err(PreXULSkeletonUIError::Disabled);\n"
                    "  }\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                skel_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(skel_cpp.relative_to(firefox_dir)))

    # --- 23c. widget/windows/WindowsUIUtils.cpp ---
    ui_cpp = firefox_dir / "widget/windows/WindowsUIUtils.cpp"
    if ui_cpp.is_file():
        orig = ui_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            patched = patched.replace(
                "static IInspectable* GetUISettings() {\n",
                (
                    "static IInspectable* GetUISettings() {\n"
                    "  // [Könfox Win7] WinRT UISettings requires Windows 10+.\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return nullptr;\n"
                    "  }\n"
                ),
                1,
            )
            patched = patched.replace(
                "void WindowsUIUtils::UpdateInWin10TabletMode() {\n"
                "  if (IsWin11OrLater()) {",
                (
                    "void WindowsUIUtils::UpdateInWin10TabletMode() {\n"
                    "  if (!mozilla::IsWin10OrLater() || mozilla::IsWin11OrLater()) {"
                ),
                1,
            )
            patched = patched.replace(
                "Result<HStringUniquePtr, HRESULT> ConvertToWindowsString(\n"
                "    const nsAString& aStr) {\n",
                (
                    "Result<HStringUniquePtr, HRESULT> ConvertToWindowsString(\n"
                    "    const nsAString& aStr) {\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return Err(E_NOTIMPL);\n"
                    "  }\n"
                ),
                1,
            )
            patched = patched.replace(
                "static Result<Ok, nsresult> RequestShare(\n"
                "    std::function<HRESULT(IDataRequestedEventArgs* pArgs)>&& aCallback) {\n",
                (
                    "static Result<Ok, nsresult> RequestShare(\n"
                    "    std::function<HRESULT(IDataRequestedEventArgs* pArgs)>&& aCallback) {\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return Err(NS_ERROR_NOT_IMPLEMENTED);\n"
                    "  }\n"
                ),
                1,
            )
            patched = patched.replace(
                "  if (!StaticPrefs::widget_windows_windowsappsdk_enabled()) {",
                (
                    "  if (!mozilla::IsWin10OrLater() || !StaticPrefs::widget_windows_windowsappsdk_enabled()) {"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                ui_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(ui_cpp.relative_to(firefox_dir)))

    # --- 23d. widget/windows/OSKInputPaneManager.cpp ---
    osk_cpp = firefox_dir / "widget/windows/OSKInputPaneManager.cpp"
    if osk_cpp.is_file():
        orig = osk_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "OSKInputPaneManager.h"',
                    '#include "OSKInputPaneManager.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            patched = patched.replace(
                "static ComPtr<IInputPane2> GetInputPane(HWND aHwnd) {\n",
                (
                    "static ComPtr<IInputPane2> GetInputPane(HWND aHwnd) {\n"
                    "  // [Könfox Win7] WinRT InputPane requires Windows 10+.\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return nullptr;\n"
                    "  }\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                osk_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(osk_cpp.relative_to(firefox_dir)))

    # --- 23e. widget/windows/WindowsSMTCProvider.cpp ---
    smtc_cpp = firefox_dir / "widget/windows/WindowsSMTCProvider.cpp"
    if smtc_cpp.is_file():
        orig = smtc_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#  include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#  include "WindowsSMTCProvider.h"',
                    '#  include "WindowsSMTCProvider.h"\n#  include "mozilla/WindowsVersion.h"',
                    1,
                )
            patched = patched.replace(
                "bool WindowsSMTCProvider::Open() {\n",
                (
                    "bool WindowsSMTCProvider::Open() {\n"
                    "  // [Könfox Win7] WinRT SystemMediaTransportControls requires Windows 10+.\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return false;\n"
                    "  }\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                smtc_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(smtc_cpp.relative_to(firefox_dir)))

    # --- 23f. widget/windows/WinPointerEvents.cpp ---
    ptr_cpp = firefox_dir / "widget/windows/WinPointerEvents.cpp"
    if ptr_cpp.is_file():
        orig = ptr_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "WinPointerEvents.h"',
                    '#include "WinPointerEvents.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            patched = patched.replace(
                "void WinPointerEvents::InitLibrary() {\n",
                (
                    "void WinPointerEvents::InitLibrary() {\n"
                    "  // [Könfox Win7] WM_POINTER APIs require Windows 8+.\n"
                    "  if (!mozilla::IsWin8OrLater()) {\n"
                    "    return;\n"
                    "  }\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                ptr_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(ptr_cpp.relative_to(firefox_dir)))

    # --- 23g. widget/windows/WinWindowOcclusionTracker.cpp ---
    occ_cpp = firefox_dir / "widget/windows/WinWindowOcclusionTracker.cpp"
    if occ_cpp.is_file():
        orig = occ_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "WinWindowOcclusionTracker.h"',
                    '#include "WinWindowOcclusionTracker.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            patched = patched.replace(
                "void WinWindowOcclusionTracker::WindowOcclusionCalculator::Initialize() {\n",
                (
                    "void WinWindowOcclusionTracker::WindowOcclusionCalculator::Initialize() {\n"
                    "  // [Könfox Win7] IVirtualDesktopManager requires Windows 10+.\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return;\n"
                    "  }\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                occ_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(occ_cpp.relative_to(firefox_dir)))

    # --- 23h. widget/windows/nsWindowTaskbarConcealer.cpp ---
    tb_cpp = firefox_dir / "widget/windows/nsWindowTaskbarConcealer.cpp"
    if tb_cpp.is_file():
        orig = tb_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "nsWindowTaskbarConcealer.h"',
                    '#include "nsWindowTaskbarConcealer.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            patched = patched.replace(
                "void nsWindow::TaskbarConcealer::OnAsyncStateUpdateRequest(HWND hwnd) {\n",
                (
                    "void nsWindow::TaskbarConcealer::OnAsyncStateUpdateRequest(HWND hwnd) {\n"
                    "  // [Könfox Win7] Explorer rudeness workaround targets Win10/11.\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return;\n"
                    "  }\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                tb_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(tb_cpp.relative_to(firefox_dir)))

    # --- 23i. toolkit/system/windowsPackageManager/nsWindowsPackageManager.cpp ---
    wpm_cpp = firefox_dir / "toolkit/system/windowsPackageManager/nsWindowsPackageManager.cpp"
    if wpm_cpp.is_file():
        orig = wpm_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "nsWindowsPackageManager.h"',
                    '#include "nsWindowsPackageManager.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            patched = patched.replace(
                "nsWindowsPackageManager::FindUserInstalledPackages(\n"
                "    const nsTArray<nsString>& aNamePrefixes, nsTArray<nsString>& aPackages) {\n",
                (
                    "nsWindowsPackageManager::FindUserInstalledPackages(\n"
                    "    const nsTArray<nsString>& aNamePrefixes, nsTArray<nsString>& aPackages) {\n"
                    "  // [Könfox Win7] WinRT PackageManager requires Windows 10+.\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return NS_ERROR_NOT_IMPLEMENTED;\n"
                    "  }\n"
                ),
                1,
            )
            patched = patched.replace(
                "nsWindowsPackageManager::GetInstalledDate(uint64_t* ts) {\n",
                (
                    "nsWindowsPackageManager::GetInstalledDate(uint64_t* ts) {\n"
                    "  if (!mozilla::IsWin10OrLater()) {\n"
                    "    return NS_ERROR_NOT_IMPLEMENTED;\n"
                    "  }\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                wpm_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(wpm_cpp.relative_to(firefox_dir)))

    # --- 23j. toolkit/components/geolocation/GeolocationService.cpp ---
    geo_cpp = firefox_dir / "toolkit/components/geolocation/GeolocationService.cpp"
    if geo_cpp.is_file():
        orig = geo_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#  include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#  include "WindowsLocationProvider.h"',
                    '#  include "WindowsLocationProvider.h"\n#  include "mozilla/WindowsVersion.h"',
                    1,
                )
            patched = patched.replace(
                '  if (Preferences::GetBool("geo.provider.ms-windows-location", false)) {',
                (
                    "  // [Könfox Win7] WinRT WindowsLocationProvider requires Windows 10+.\n"
                    '  if (mozilla::IsWin10OrLater() && Preferences::GetBool("geo.provider.ms-windows-location", false)) {'
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                geo_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(geo_cpp.relative_to(firefox_dir)))

    return touched


# ---------------------------------------------------------------------------
# 24. XPCOM AvailableMemoryTracker Win8.1+ HeapOptimizeResources guard
# ---------------------------------------------------------------------------
def patch_memory_tracker_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    xpcom/base/AvailableMemoryTracker.cpp calls HeapSetInformation(...,
    HeapOptimizeResources, ...) which was introduced in Windows 8.1.
    """
    touched: list[str] = []
    amt_cpp = firefox_dir / "xpcom/base/AvailableMemoryTracker.cpp"
    if not amt_cpp.is_file():
        return touched

    orig = amt_cpp.read_text(encoding="utf-8", errors="replace")
    patched = orig
    if "[Könfox Win7]" not in patched:
        if '#  include "mozilla/WindowsVersion.h"' not in patched:
            patched = patched.replace(
                "#if defined(XP_WIN)\n",
                '#if defined(XP_WIN)\n#  include "mozilla/WindowsVersion.h"\n',
                1,
            )
        patched = patched.replace(
            "void nsJemallocFreeDirtyPagesRunnable::OptimizeSystemHeap() {\n",
            (
                "void nsJemallocFreeDirtyPagesRunnable::OptimizeSystemHeap() {\n"
                "  // [Könfox Win7] HeapOptimizeResources requires Windows 8.1+.\n"
                "  if (!mozilla::IsWin8Point1OrLater()) {\n"
                "    return;\n"
                "  }\n"
            ),
            1,
        )
    if patched != orig:
        if not dry_run:
            amt_cpp.write_text(patched, encoding="utf-8")
        touched.append(str(amt_cpp.relative_to(firefox_dir)))
    return touched


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
        ("WinLauncher WinRT & AppModel dynamic load", lambda: patch_winlauncher_and_appmodel(args.firefox_dir, args.dry_run)),
        ("Chromium sandbox Win8+ dynamic load", lambda: patch_chromium_sandbox_win7(args.firefox_dir, args.dry_run)),
        ("mozglue Futex Win7 fallback & mincore removal", lambda: patch_mozglue_futex_and_mincore(args.firefox_dir, args.dry_run)),
        ("ANGLE SimpleMutex Win7 std::mutex fallback", lambda: patch_angle_futex(args.firefox_dir, args.dry_run)),
        ("shcore & PathCch dynamic load (WinUtils/WebRTC/updater)", lambda: patch_shcore_and_pathcch(args.firefox_dir, args.dry_run)),
        ("HAL GetSystemCpuSetInformation dynamic load", lambda: patch_cpu_sets_win7(args.firefox_dir, args.dry_run)),
        ("SpiderMonkey GetSystemTimePreciseAsFileTime dynamic load", lambda: patch_precise_time_win7(args.firefox_dir, args.dry_run)),
        ("Profiler ETW dynamic EventSetInformation", lambda: patch_etw_tracelogging_win7(args.firefox_dir, args.dry_run)),
        ("llama.cpp SetThreadInformation dynamic load", lambda: patch_llama_cpp_win7(args.firefox_dir, args.dry_run)),
        ("Vendored Rust crate scan", lambda: patch_vendored_rust_crates(args.firefox_dir, args.dry_run)),
        ("konfox.exe Win7 RT_MANIFEST", lambda: patch_konfox_app_manifest(args.firefox_dir, args.dry_run)),
        ("combase.dll removal (windows-core/sys + AgileReference)", lambda: patch_combase_and_agile_reference(args.firefox_dir, args.dry_run)),
        ("SpiderMonkey JIT RtlAddGrowableFunctionTable Win7 fallback", lambda: patch_jit_unwind_win7(args.firefox_dir, args.dry_run)),
        ("Dynamic GetCurrentApplicationUserModelId & nsWindow guards", lambda: patch_aumid_dynamic_load(args.firefox_dir, args.dry_run)),
        ("Win7 PRNG fallback (RandomNum + Chromium rand_util_win)", lambda: patch_win7_prng_fallbacks(args.firefox_dir, args.dry_run)),
        ("Chromium Sandbox & SandboxBroker Win7 runtime fixes", lambda: patch_chromium_sandbox_runtime_win7(args.firefox_dir, args.dry_run)),
        ("Graphics Win7 fixes (DirectComposition & D3D 11.1)", lambda: patch_graphics_win7(args.firefox_dir, args.dry_run)),
        ("WinRT, DPI, SkeletonUI & Widget Win7 guards", lambda: patch_winrt_and_widget_win7(args.firefox_dir, args.dry_run)),
        ("AvailableMemoryTracker HeapOptimizeResources Win7 guard", lambda: patch_memory_tracker_win7(args.firefox_dir, args.dry_run)),
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
