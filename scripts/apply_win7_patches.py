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
// IMPORTANT: Never call LoadLibraryW or InitOnceExecuteOnce here! FutexImpl
// backs jemalloc arena locks and mozilla::Mutex/CondVar, so touching the
// Windows loader lock causes AB-BA deadlocks with DLL delay-loading,
// FreeLibrary shutdown, and post-lockdown sandboxes. kernelbase.dll is always
// mapped before main() and directly exports WaitOnAddress on Windows 8+.

#include "mozilla/Futex.h"

#include <atomic>
#include <windows.h>

namespace mozilla {

namespace {

using WaitOnAddressFn = BOOL(WINAPI*)(volatile VOID*, PVOID, SIZE_T, DWORD);
using WakeByAddressSingleFn = VOID(WINAPI*)(PVOID);
using WakeByAddressAllFn = VOID(WINAPI*)(PVOID);

// 0 = uninitialized, 1 = Win7 SRWLOCK/CV fallback, 2 = Win8+ WaitOnAddress
static std::atomic<int> sFutexApiState{0};
static std::atomic<WaitOnAddressFn> sWaitOnAddress{nullptr};
static std::atomic<WakeByAddressSingleFn> sWakeSingle{nullptr};
static std::atomic<WakeByAddressAllFn> sWakeAll{nullptr};

static inline int EnsureFutexApiInit() {
  int state = sFutexApiState.load(std::memory_order_acquire);
  if (state != 0) {
    return state;
  }
  HMODULE mod = ::GetModuleHandleW(L"kernelbase.dll");
  if (mod) {
    auto w = reinterpret_cast<WaitOnAddressFn>(
        reinterpret_cast<void*>(::GetProcAddress(mod, "WaitOnAddress")));
    auto s = reinterpret_cast<WakeByAddressSingleFn>(
        reinterpret_cast<void*>(::GetProcAddress(mod, "WakeByAddressSingle")));
    auto a = reinterpret_cast<WakeByAddressAllFn>(
        reinterpret_cast<void*>(::GetProcAddress(mod, "WakeByAddressAll")));
    if (w && s && a) {
      sWaitOnAddress.store(w, std::memory_order_relaxed);
      sWakeSingle.store(s, std::memory_order_relaxed);
      sWakeAll.store(a, std::memory_order_relaxed);
      sFutexApiState.store(2, std::memory_order_release);
      return 2;
    }
  }
  sFutexApiState.store(1, std::memory_order_release);
  return 1;
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
  DWORD timeout = ConvertTimeout(aTimeout);
  if (EnsureFutexApiInit() == 2) {
    return sWaitOnAddress.load(std::memory_order_relaxed)(
               reinterpret_cast<volatile void*>(&mValue), &aExpected,
               sizeof(aExpected), timeout) != FALSE;
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
  if (EnsureFutexApiInit() == 2) {
    sWakeSingle.load(std::memory_order_relaxed)(
        reinterpret_cast<void*>(&mValue));
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
  if (EnsureFutexApiInit() == 2) {
    sWakeAll.load(std::memory_order_relaxed)(
        reinterpret_cast<void*>(&mValue));
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
            patched = patched.replace(
                'windows_link::link!("api-ms-win-core-winrt-l1-1-0.dll" "system" fn RoGetActivationFactory(activatableclassid : HSTRING, iid : *const GUID, factory : *mut *mut core::ffi::c_void) -> HRESULT);',
                (
                    "// [Könfox Win7] Dynamically resolve RoGetActivationFactory from combase.dll\n"
                    "// so Rust WinRT calls never trigger a fatal delay-load exception for\n"
                    "// api-ms-win-core-winrt-l1-1-0.dll (missing on Windows 7 SP1).\n"
                    "#[allow(non_snake_case)]\n"
                    "pub unsafe fn RoGetActivationFactory(\n"
                    "    activatableclassid: HSTRING,\n"
                    "    iid: *const GUID,\n"
                    "    factory: *mut *mut core::ffi::c_void,\n"
                    ") -> HRESULT {\n"
                    "    unsafe {\n"
                    "        if !factory.is_null() {\n"
                    "            *factory = core::ptr::null_mut();\n"
                    "        }\n"
                    "        let module = LoadLibraryExA(b\"combase.dll\\0\".as_ptr(), core::ptr::null_mut(), 0);\n"
                    "        if module.is_null() {\n"
                    "            return -2147467263i32; // E_NOTIMPL\n"
                    "        }\n"
                    "        if let Some(addr) = GetProcAddress(module, b\"RoGetActivationFactory\\0\".as_ptr()) {\n"
                    "            let f: unsafe extern \"system\" fn(\n"
                    "                HSTRING,\n"
                    "                *const GUID,\n"
                    "                *mut *mut core::ffi::c_void,\n"
                    "            ) -> HRESULT = core::mem::transmute(addr);\n"
                    "            return f(activatableclassid, iid, factory);\n"
                    "        }\n"
                    "        -2147467263i32 // E_NOTIMPL\n"
                    "    }\n"
                    "}"
                ),
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

    com_bindings_rs = wc_dir / "src/imp/com_bindings.rs"
    if com_bindings_rs.is_file():
        orig = com_bindings_rs.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched and 'link!("combase.dll"' in patched:
            old_agile_rs = (
                '    windows_core::link!("combase.dll" "system" fn RoGetAgileReference(options : AgileReferenceOptions, riid : *const windows_core::GUID, punk : * mut core::ffi::c_void, ppagilereference : *mut * mut core::ffi::c_void) -> windows_core::HRESULT);\n'
                "    unsafe {\n"
                "        let mut result__ = core::mem::zeroed();\n"
                "        RoGetAgileReference(options, riid, punk.param().abi(), &mut result__)\n"
                "            .and_then(|| windows_core::Type::from_abi(result__))\n"
                "    }"
            )
            new_agile_rs = (
                "    // [Könfox Win7] Dynamically resolve combase.dll!RoGetAgileReference (Win8.1+)\n"
                "    // so windows-core never emits a static combase.dll import on Windows 7 SP1.\n"
                "    unsafe {\n"
                '        let module = super::LoadLibraryExA(b"combase.dll\\0".as_ptr(), core::ptr::null_mut(), 0);\n'
                "        if module.is_null() {\n"
                "            return Err(windows_core::HRESULT(-2147467263i32).into());\n"
                "        }\n"
                '        if let Some(addr) = super::GetProcAddress(module, b"RoGetAgileReference\\0".as_ptr()) {\n'
                '            let f: unsafe extern "system" fn(\n'
                "                AgileReferenceOptions,\n"
                "                *const windows_core::GUID,\n"
                "                *mut core::ffi::c_void,\n"
                "                *mut *mut core::ffi::c_void,\n"
                "            ) -> windows_core::HRESULT = core::mem::transmute(addr);\n"
                "            let mut result__ = core::mem::zeroed();\n"
                "            return f(options, riid, punk.param().abi(), &mut result__)\n"
                "                .and_then(|| windows_core::Type::from_abi(result__));\n"
                "        }\n"
                "        Err(windows_core::HRESULT(-2147467263i32).into())\n"
                "    }"
            )
            if old_agile_rs in patched:
                patched = patched.replace(old_agile_rs, new_agile_rs, 1)
        if patched != orig:
            if not dry_run:
                com_bindings_rs.write_text(patched, encoding="utf-8")
            wc_changed.append("src/imp/com_bindings.rs")
            touched.append(str(com_bindings_rs.relative_to(firefox_dir)))

    if wc_changed and _refresh_cargo_checksum(wc_dir, wc_changed, dry_run):
        touched.append(str((wc_dir / ".cargo-checksum.json").relative_to(firefox_dir)))

    # --- 17a2. third_party/rust/windows-link ---
    # windows-core re-exports `windows_link::link!`, which is also invoked by the
    # bootstrapped `~/.mozbuild/windows-rs` (`windows 0.62.2`) crate via
    # `build/rust/windows/src/lib.rs` (`mozbuild::windows_rs_lib!{}`).
    # Redirecting `"combase.dll"` -> `"ole32.dll"` inside `windows_link::link!`
    # guarantees ZERO Rust crates (vendored OR bootstrapped) ever emit raw-dylib
    # `combase.dll` import stubs into `gkrust.lib` / `xul.dll`.
    wl_dir = firefox_dir / "third_party/rust/windows-link"
    wl_lib_rs = wl_dir / "src/lib.rs"
    if wl_lib_rs.is_file():
        orig = wl_lib_rs.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_x86 = (
                "#[cfg(all(windows, target_arch = \"x86\"))]\n"
                "#[macro_export]\n"
                "macro_rules! link {\n"
                "    ($library:literal $abi:literal $($link_name:literal)? fn $($function:tt)*) => (\n"
                '        #[link(name = $library, kind = "raw-dylib", modifiers = "+verbatim", import_name_type = "undecorated")]\n'
                "        extern $abi {\n"
                "            $(#[link_name=$link_name])?\n"
                "            pub fn $($function)*;\n"
                "        }\n"
                "    )\n"
                "}"
            )
            new_x86 = (
                "#[cfg(all(windows, target_arch = \"x86\"))]\n"
                "#[macro_export]\n"
                "macro_rules! link {\n"
                "    // [Könfox Win7] Redirect combase.dll (Win8+) raw-dylib links to ole32.dll (Win7-native).\n"
                '    ("combase.dll" $abi:literal $($link_name:literal)? fn $($function:tt)*) => (\n'
                '        #[link(name = "ole32.dll", kind = "raw-dylib", modifiers = "+verbatim", import_name_type = "undecorated")]\n'
                "        extern $abi {\n"
                "            $(#[link_name=$link_name])?\n"
                "            pub fn $($function)*;\n"
                "        }\n"
                "    );\n"
                "    ($library:literal $abi:literal $($link_name:literal)? fn $($function:tt)*) => (\n"
                '        #[link(name = $library, kind = "raw-dylib", modifiers = "+verbatim", import_name_type = "undecorated")]\n'
                "        extern $abi {\n"
                "            $(#[link_name=$link_name])?\n"
                "            pub fn $($function)*;\n"
                "        }\n"
                "    );\n"
                "}"
            )
            old_x64 = (
                "#[cfg(all(windows, not(target_arch = \"x86\")))]\n"
                "#[macro_export]\n"
                "macro_rules! link {\n"
                "    ($library:literal $abi:literal $($link_name:literal)? fn $($function:tt)*) => (\n"
                '        #[link(name = $library, kind = "raw-dylib", modifiers = "+verbatim")]\n'
                "        extern $abi {\n"
                "            $(#[link_name=$link_name])?\n"
                "            pub fn $($function)*;\n"
                "        }\n"
                "    )\n"
                "}"
            )
            new_x64 = (
                "#[cfg(all(windows, not(target_arch = \"x86\")))]\n"
                "#[macro_export]\n"
                "macro_rules! link {\n"
                "    // [Könfox Win7] Redirect combase.dll (Win8+) raw-dylib links to ole32.dll (Win7-native).\n"
                '    ("combase.dll" $abi:literal $($link_name:literal)? fn $($function:tt)*) => (\n'
                '        #[link(name = "ole32.dll", kind = "raw-dylib", modifiers = "+verbatim")]\n'
                "        extern $abi {\n"
                "            $(#[link_name=$link_name])?\n"
                "            pub fn $($function)*;\n"
                "        }\n"
                "    );\n"
                "    ($library:literal $abi:literal $($link_name:literal)? fn $($function:tt)*) => (\n"
                '        #[link(name = $library, kind = "raw-dylib", modifiers = "+verbatim")]\n'
                "        extern $abi {\n"
                "            $(#[link_name=$link_name])?\n"
                "            pub fn $($function)*;\n"
                "        }\n"
                "    );\n"
                "}"
            )
            if old_x86 in patched:
                patched = patched.replace(old_x86, new_x86, 1)
            if old_x64 in patched:
                patched = patched.replace(old_x64, new_x64, 1)
        if patched != orig:
            if not dry_run:
                wl_lib_rs.write_text(patched, encoding="utf-8")
            touched.append(str(wl_lib_rs.relative_to(firefox_dir)))
            if _refresh_cargo_checksum(wl_dir, ["src/lib.rs"], dry_run):
                touched.append(str((wl_dir / ".cargo-checksum.json").relative_to(firefox_dir)))

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
        # [Könfox Win7 component filter] PROC_THREAD_ATTRIBUTE_COMPONENT_FILTER
        # (COMPONENT_KTM) requires Windows 10 20H1+. On Windows 7 SP1,
        # UpdateProcThreadAttribute fails with ERROR_INVALID_PARAMETER (not
        # ERROR_NOT_SUPPORTED), which aborts EVERY child-process launch!
        if "[Könfox Win7 component filter]" not in patched:
            ktm_anchor = (
                "void ConvertProcessMitigationsToComponentFilter(MitigationFlags flags,\n"
                "                                                COMPONENT_FILTER* filter) {\n"
                "  filter->ComponentFlags = 0;\n"
                "  if (flags & MITIGATION_KTM_COMPONENT) {"
            )
            if ktm_anchor in patched:
                patched = patched.replace(
                    ktm_anchor,
                    (
                        "void ConvertProcessMitigationsToComponentFilter(MitigationFlags flags,\n"
                        "                                                COMPONENT_FILTER* filter) {\n"
                        "  filter->ComponentFlags = 0;\n"
                        "  // [Könfox Win7 component filter] PROC_THREAD_ATTRIBUTE_COMPONENT_FILTER requires Win10 20H1+.\n"
                        "  if (base::win::GetVersion() < base::win::Version::WIN10_20H1) {\n"
                        "    return;\n"
                        "  }\n"
                        "  if (flags & MITIGATION_KTM_COMPONENT) {"
                    ),
                    1,
                )
        # [Könfox Win7 dll search] On unpatched Windows 7 SP1 without KB2533623,
        # SetDefaultDllDirectories does not exist (shim returns FALSE with
        # ERROR_PROC_NOT_FOUND). Do not abort child startup in that case.
        if "[Könfox Win7 dll search]" not in patched:
            dll_dir_anchor = (
                "  if (flags & MITIGATION_DLL_SEARCH_ORDER) {\n"
                "    if (!::SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)) {\n"
                "      return false;\n"
                "    }"
            )
            if dll_dir_anchor in patched:
                patched = patched.replace(
                    dll_dir_anchor,
                    (
                        "  if (flags & MITIGATION_DLL_SEARCH_ORDER) {\n"
                        "    // [Könfox Win7 dll search] Tolerate missing SetDefaultDllDirectories on Win7 without KB2533623.\n"
                        "    if (!::SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) &&\n"
                        "        ::GetLastError() != ERROR_PROC_NOT_FOUND) {\n"
                        "      return false;\n"
                        "    }"
                    ),
                    1,
                )
        if "[Könfox Win7 mitigation apis]" not in patched:
            old_get_supp = (
                "    if (!::GetProcessMitigationPolicy(::GetCurrentProcess(),\n"
                "                                      ProcessMitigationOptionsMask,\n"
                "                                      &mitigations, mits_size)) {\n"
                "      NOTREACHED();\n"
                "    }"
            )
            new_get_supp = (
                "    // [Könfox Win7 mitigation apis] Dynamically resolve Win8+ GetProcessMitigationPolicy.\n"
                "    using GetMitigationFn = decltype(&::GetProcessMitigationPolicy);\n"
                "    static auto sGetMitigation = reinterpret_cast<GetMitigationFn>(\n"
                "        reinterpret_cast<void*>(::GetProcAddress(\n"
                '            ::GetModuleHandleW(L"kernel32.dll"), "GetProcessMitigationPolicy")));\n'
                "    if (sGetMitigation && base::win::GetVersion() >= base::win::Version::WIN8) {\n"
                "      if (!sGetMitigation(::GetCurrentProcess(), ProcessMitigationOptionsMask,\n"
                "                          &mitigations, mits_size)) {\n"
                "        mitigations[0] = 0;\n"
                "        mitigations[1] = 0;\n"
                "      }\n"
                "    }"
            )
            old_set_mit = (
                "bool SetProcessMitigationPolicyInternal(PROCESS_MITIGATION_POLICY policy,\n"
                "                                        PVOID lpBuffer,\n"
                "                                        SIZE_T dwLength) {\n"
                "  PCHECK(::SetProcessMitigationPolicy(policy, lpBuffer, dwLength))\n"
                '      << "SetProcessMitigationPolicy failed with Policy: " << policy;\n\n'
                "  return true;\n"
                "}"
            )
            new_set_mit = (
                "bool SetProcessMitigationPolicyInternal(PROCESS_MITIGATION_POLICY policy,\n"
                "                                        PVOID lpBuffer,\n"
                "                                        SIZE_T dwLength) {\n"
                "  if (base::win::GetVersion() < base::win::Version::WIN8) {\n"
                "    return true;\n"
                "  }\n"
                "  using SetMitigationFn = decltype(&::SetProcessMitigationPolicy);\n"
                "  static auto sSetMitigation = reinterpret_cast<SetMitigationFn>(\n"
                "      reinterpret_cast<void*>(::GetProcAddress(\n"
                '          ::GetModuleHandleW(L"kernel32.dll"), "SetProcessMitigationPolicy")));\n'
                "  if (!sSetMitigation) {\n"
                "    return true;\n"
                "  }\n"
                "  PCHECK(sSetMitigation(policy, lpBuffer, dwLength))\n"
                '      << "SetProcessMitigationPolicy failed with Policy: " << policy;\n\n'
                "  return true;\n"
                "}"
            )
            old_filter = (
                "MitigationFlags FilterPostStartupProcessMitigations(MitigationFlags flags) {\n"
                "  return flags & (MITIGATION_BOTTOM_UP_ASLR | MITIGATION_DLL_SEARCH_ORDER);\n"
                "}"
            )
            new_filter = (
                "MitigationFlags FilterPostStartupProcessMitigations(MitigationFlags flags) {\n"
                "  if (base::win::GetVersion() < base::win::Version::WIN8) {\n"
                "    return flags & (MITIGATION_HEAP_TERMINATE | MITIGATION_BOTTOM_UP_ASLR |\n"
                "                    MITIGATION_DLL_SEARCH_ORDER);\n"
                "  }\n"
                "  return flags & (MITIGATION_BOTTOM_UP_ASLR | MITIGATION_DLL_SEARCH_ORDER);\n"
                "}"
            )
            if old_get_supp in patched:
                patched = patched.replace(old_get_supp, new_get_supp, 1)
            if old_set_mit in patched:
                patched = patched.replace(old_set_mit, new_set_mit, 1)
            if old_filter in patched:
                patched = patched.replace(old_filter, new_filter, 1)
        if patched != orig:
            if not dry_run:
                pm_cc.write_text(patched, encoding="utf-8")
            touched.append(str(pm_cc.relative_to(firefox_dir)))

    # --- 21a2. startup_information_helper.cc (belt-and-suspenders for COMPONENT_FILTER) ---
    sih_cc = firefox_dir / "security/sandbox/chromium/sandbox/win/src/startup_information_helper.cc"
    if sih_cc.is_file():
        orig = sih_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7 component filter]" not in patched:
            cf_anchor = (
                "    if (!startup_info_.UpdateProcThreadAttribute(\n"
                "            PROC_THREAD_ATTRIBUTE_COMPONENT_FILTER, &component_filter_,\n"
                "            sizeof(component_filter_)) &&\n"
                "        ::GetLastError() != ERROR_NOT_SUPPORTED) {\n"
                "      return false;\n"
                "    }"
            )
            if cf_anchor in patched:
                patched = patched.replace(
                    cf_anchor,
                    (
                        "    // [Könfox Win7 component filter] Win7 returns ERROR_INVALID_PARAMETER for unknown attributes.\n"
                        "    if (!startup_info_.UpdateProcThreadAttribute(\n"
                        "            PROC_THREAD_ATTRIBUTE_COMPONENT_FILTER, &component_filter_,\n"
                        "            sizeof(component_filter_)) &&\n"
                        "        ::GetLastError() != ERROR_NOT_SUPPORTED &&\n"
                        "        ::GetLastError() != ERROR_INVALID_PARAMETER) {\n"
                        "      return false;\n"
                        "    }"
                    ),
                    1,
                )
        if patched != orig:
            if not dry_run:
                sih_cc.write_text(patched, encoding="utf-8")
            touched.append(str(sih_cc.relative_to(firefox_dir)))

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
                "  bool assigned_to_job = true;\n"
                "  if (base::win::GetVersion() < base::win::Version::WIN10) {\n"
                "    HANDLE job_handle = policy_base->GetJobHandle();\n"
                "    if (job_handle &&\n"
                "        !::AssignProcessToJobObject(job_handle, process_info->process_handle())) {\n"
                "      DWORD err = ::GetLastError();\n"
                "      // On Win7, nested jobs are unsupported if the parent is already in a\n"
                "      // non-breakaway job (ERROR_ACCESS_DENIED); allow launch to continue.\n"
                "      if (err == ERROR_ACCESS_DENIED) {\n"
                "        assigned_to_job = false;\n"
                "      } else {\n"
                "        *last_error = err;\n"
                "        target->Terminate();\n"
                "        return SBOX_ERROR_CANNOT_INIT_JOB;\n"
                "      }\n"
                "    }\n"
                "  }\n\n"
                "  if (assigned_to_job && config_base->GetJobLevel() <= JobLevel::kLimitedUser) {"
            )
            old_assoc = (
                "  // There is no obvious cleanup here.\n"
                "  CHECK(AssociateCompletionPort(job_handle, job_port_.get(), tracker));"
            )
            new_assoc = (
                "  // There is no obvious cleanup here.\n"
                "  if (assigned_to_job) {\n"
                "    CHECK(AssociateCompletionPort(job_handle, job_port_.get(), tracker));\n"
                "  }"
            )
            if old_job_attr in patched and old_finish in patched:
                patched = patched.replace(old_job_attr, new_job_attr, 1).replace(
                    old_finish, new_finish, 1
                )
                if old_assoc in patched:
                    patched = patched.replace(old_assoc, new_assoc, 1)
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
            old_ace_generic = (
                "    sd->SetDaclEntry(base::win::WellKnownSid::kAllApplicationPackages,\n"
                "                     base::win::SecurityAccessMode::kGrant, GENERIC_ALL, 0);"
            )
            new_ace_generic = (
                "    // [Könfox Win7] ALL APPLICATION PACKAGES SID (S-1-15-2-1) is Windows 8+.\n"
                "    if (base::win::GetVersion() >= base::win::Version::WIN8) {\n"
                "      sd->SetDaclEntry(base::win::WellKnownSid::kAllApplicationPackages,\n"
                "                       base::win::SecurityAccessMode::kGrant, GENERIC_ALL, 0);\n"
                "    }"
            )
            old_ace_legacy = (
                "  if (!sd->SetDaclEntry(base::win::WellKnownSid::kAllApplicationPackages,\n"
                "                        base::win::SecurityAccessMode::kGrant,\n"
                "                        DESKTOP_GENERIC_READ | DESKTOP_GENERIC_WRITE |\n"
                "                            DESKTOP_GENERIC_EXECUTE,\n"
                "                        0)) {\n"
                "    return false;\n"
                "  }"
            )
            new_ace_legacy = (
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
            if old_ace_generic in patched:
                patched = patched.replace(old_ace_generic, new_ace_generic, 1)
            elif old_ace_legacy in patched:
                patched = patched.replace(old_ace_legacy, new_ace_legacy, 1)
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
            # Cap Windows 7 content sandbox to Level 6 (Firefox 115 ESR's proven Win7
            # production level: kLockdown job, USER_LIMITED, INTEGRITY_LEVEL_LOW,
            # lockdown default DACL, random SID, alternate winstation) instead of
            # Win10-tuned Level 7/8/9 (INTEGRITY_LEVEL_UNTRUSTED / USER_LOCKDOWN_WITH_TRAVERSE
            # / SetForceKnownDllLoadingFallback), and grant \Device\KsecDD for RtlGenRandom.
            patched = patched.replace(
                "  MOZ_RELEASE_ASSERT(aSandboxLevel >= 1,\n"
                '                     "Should not be called with aSandboxLevel < 1");\n',
                (
                    "  MOZ_RELEASE_ASSERT(aSandboxLevel >= 1,\n"
                    '                     "Should not be called with aSandboxLevel < 1");\n'
                    "  // [Könfox Win7] Level 7+ (UNTRUSTED / USER_LOCKDOWN_WITH_TRAVERSE /\n"
                    "  // SetForceKnownDllLoadingFallback) requires Windows 8+; cap Win7 at\n"
                    "  // Level 6 (USER_LIMITED + LOW integrity + alternate winstation).\n"
                    "  if (!mozilla::IsWin8OrLater() && aSandboxLevel > 6) {\n"
                    "    aSandboxLevel = 6;\n"
                    "  }\n"
                ),
                1,
            )
            patched = patched.replace(
                "  // Add the policy for the client side of the crash server pipe.\n"
                "  result = config->AllowFileAccess(sandbox::FileSemantics::kAllowAny,\n"
                '                                   L"\\\\??\\\\pipe\\\\gecko-crash-server-pipe.*");\n',
                (
                    "  // [Könfox Win7] Win7 RtlGenRandom / cryptbase.dll may open \\Device\\KsecDD.\n"
                    "  if (!mozilla::IsWin8OrLater()) {\n"
                    "    (void)config->AllowFileAccess(sandbox::FileSemantics::kAllowAny,\n"
                    '                                  LR"(\\Device\\KsecDD)");\n'
                    "  }\n\n"
                    "  // Add the policy for the client side of the crash server pipe.\n"
                    "  result = config->AllowFileAccess(sandbox::FileSemantics::kAllowAny,\n"
                    '                                   L"\\\\??\\\\pipe\\\\gecko-crash-server-pipe.*");\n'
                ),
                1,
            )
            # GPU sandbox (aSandboxLevel >= 2): allow FOLDERID_Fonts on Win7 (Feodor2 7fbdf5cb77).
            patched = patched.replace(
                "  if (aSandboxLevel >= 2) {\n"
                "    if (UseFontFileRule()) {\n",
                (
                    "  if (aSandboxLevel >= 2) {\n"
                    "    // [Könfox Win7] Allow system Fonts directory in USER_LIMITED GPU sandbox.\n"
                    "    if (!mozilla::IsWin8OrLater()) {\n"
                    "      AddCachedWindowsDirRule(&trackingConfig,\n"
                    "                              sandbox::FileSemantics::kAllowReadonly,\n"
                    "                              FOLDERID_Fonts);\n"
                    "      AddCachedWindowsDirRule(&trackingConfig,\n"
                    "                              sandbox::FileSemantics::kAllowReadonly,\n"
                    '                              FOLDERID_Fonts, u"\\\\*"_ns);\n'
                    "    }\n"
                    "    if (UseFontFileRule()) {\n"
                ),
                1,
            )
            # GMP Win32k lockdown guard (Feodor2 2c10acccb6).
            patched = patched.replace(
                "  if (StaticPrefs::security_sandbox_gmp_win32k_disable() &&\n"
                "      aGMPSandboxKind != Widevine && aGMPSandboxKind != Clearkey &&\n"
                "      aGMPSandboxKind != Fake) {\n",
                (
                    "  // [Könfox Win7] GMP Win32k lockdown requires Windows 10+.\n"
                    "  if (mozilla::IsWin10OrLater() &&\n"
                    "      StaticPrefs::security_sandbox_gmp_win32k_disable() &&\n"
                    "      aGMPSandboxKind != Widevine && aGMPSandboxKind != Clearkey &&\n"
                    "      aGMPSandboxKind != Fake) {\n"
                ),
                1,
            )
        if patched != orig:
            if not dry_run:
                sb_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(sb_cpp.relative_to(firefox_dir)))

    # --- 21i. security/sandbox/chromium/sandbox/win/src/target_process.cc ---
    # On Windows 7 SP1, nested Job objects are unsupported. If the parent is
    # inside a Job that permits breakaway (e.g. Win7 PCA / Explorer), pass
    # CREATE_BREAKAWAY_FROM_JOB so AssignProcessToJobObject succeeds cleanly.
    tp_cc = firefox_dir / "security/sandbox/chromium/sandbox/win/src/target_process.cc"
    if tp_cc.is_file():
        orig = tp_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "base/win/windows_version.h"' not in patched:
                patched = patched.replace(
                    '#include "base/win/current_module.h"',
                    '#include "base/win/current_module.h"\n#include "base/win/windows_version.h"',
                    1,
                )
            old_flags = (
                "  if (startup_info->has_extended_startup_info())\n"
                "    flags |= EXTENDED_STARTUPINFO_PRESENT;"
            )
            new_flags = (
                "  if (startup_info->has_extended_startup_info())\n"
                "    flags |= EXTENDED_STARTUPINFO_PRESENT;\n\n"
                "  // [Könfox Win7] Nested Jobs require Win8+. Break away from a parent Job\n"
                "  // only when the parent Job explicitly permits JOB_OBJECT_LIMIT_BREAKAWAY_OK.\n"
                "  if (base::win::GetVersion() < base::win::Version::WIN8) {\n"
                "    BOOL in_job = FALSE;\n"
                "    if (::IsProcessInJob(::GetCurrentProcess(), nullptr, &in_job) && in_job) {\n"
                "      JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info = {};\n"
                "      if (::QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation,\n"
                "                                      &job_info, sizeof(job_info), nullptr) &&\n"
                "          (job_info.BasicLimitInformation.LimitFlags &\n"
                "           JOB_OBJECT_LIMIT_BREAKAWAY_OK)) {\n"
                "        flags |= CREATE_BREAKAWAY_FROM_JOB;\n"
                "      }\n"
                "    }\n"
                "  }"
            )
            if old_flags in patched:
                patched = patched.replace(old_flags, new_flags, 1)
        if patched != orig:
            if not dry_run:
                tp_cc.write_text(patched, encoding="utf-8")
            touched.append(str(tp_cc.relative_to(firefox_dir)))

    # --- 21j. security/sandbox/chromium/sandbox/win/src/win_utils.cc ---
    # Defensive RtlGenRandom fallback for GetProcessPrng() (Win10+ bcryptprimitives).
    wu_cc = firefox_dir / "security/sandbox/chromium/sandbox/win/src/win_utils.cc"
    if wu_cc.is_file():
        orig = wu_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_prng = (
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
            new_prng = (
                "// [Könfox Win7] Fall back to advapi32!SystemFunction036 (RtlGenRandom)\n"
                "// when bcryptprimitives!ProcessPrng (Win10+) is unavailable on Win7 SP1.\n"
                "BOOL WINAPI KonfoxRtlGenRandomAdapter(PBYTE pbData, SIZE_T cbData) {\n"
                "  using RtlGenRandomFn = BOOLEAN(WINAPI*)(PVOID, ULONG);\n"
                "  static const RtlGenRandomFn sRtlGenRandom = []() -> RtlGenRandomFn {\n"
                '    HMODULE hAdv = ::LoadLibraryW(L"advapi32.dll");\n'
                "    return hAdv ? reinterpret_cast<RtlGenRandomFn>(\n"
                '                      reinterpret_cast<void*>(::GetProcAddress(hAdv, "SystemFunction036")))\n'
                "                : nullptr;\n"
                "  }();\n"
                "  if (!sRtlGenRandom) {\n"
                "    return FALSE;\n"
                "  }\n"
                "  return sRtlGenRandom(pbData, static_cast<ULONG>(cbData)) ? TRUE : FALSE;\n"
                "}\n\n"
                "decltype(&ProcessPrng) GetProcessPrng() {\n"
                '  HMODULE hmod = LoadLibraryW(L"bcryptprimitives.dll");\n'
                "  if (hmod) {\n"
                "    decltype(&ProcessPrng) process_prng_fn =\n"
                "        reinterpret_cast<decltype(&ProcessPrng)>(\n"
                '            reinterpret_cast<void*>(GetProcAddress(hmod, "ProcessPrng")));\n'
                "    if (process_prng_fn) {\n"
                "      return process_prng_fn;\n"
                "    }\n"
                "  }\n"
                "  return reinterpret_cast<decltype(&ProcessPrng)>(&KonfoxRtlGenRandomAdapter);\n"
                "}"
            )
            if old_prng in patched:
                patched = patched.replace(old_prng, new_prng, 1)
        if patched != orig:
            if not dry_run:
                wu_cc.write_text(patched, encoding="utf-8")
            touched.append(str(wu_cc.relative_to(firefox_dir)))

    # --- 21k. security/sandbox/chromium/base/win/win_util.cc ---
    # Dynamically resolve Win8+ GetProcessMitigationPolicy in IsUser32AndGdi32Available().
    bwu_cc = firefox_dir / "security/sandbox/chromium/base/win/win_util.cc"
    if bwu_cc.is_file():
        orig = bwu_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_u32 = (
                "    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY policy = {};\n"
                "    if (::GetProcessMitigationPolicy(GetCurrentProcess(),\n"
                "                                     ProcessSystemCallDisablePolicy, &policy,\n"
                "                                     sizeof(policy))) {\n"
                "      return policy.DisallowWin32kSystemCalls == 0;\n"
                "    }"
            )
            new_u32 = (
                "    // [Könfox Win7] GetProcessMitigationPolicy requires Windows 8+.\n"
                "    static const auto pGetProcessMitigationPolicy =\n"
                "        reinterpret_cast<decltype(&::GetProcessMitigationPolicy)>(\n"
                "            reinterpret_cast<void*>(::GetProcAddress(\n"
                '                ::GetModuleHandleW(L"kernel32.dll"),\n'
                '                "GetProcessMitigationPolicy")));\n'
                "    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY policy = {};\n"
                "    if (pGetProcessMitigationPolicy &&\n"
                "        pGetProcessMitigationPolicy(GetCurrentProcess(),\n"
                "                                    ProcessSystemCallDisablePolicy, &policy,\n"
                "                                    sizeof(policy))) {\n"
                "      return policy.DisallowWin32kSystemCalls == 0;\n"
                "    }"
            )
            if old_u32 in patched:
                patched = patched.replace(old_u32, new_u32, 1)
        if patched != orig:
            if not dry_run:
                bwu_cc.write_text(patched, encoding="utf-8")
            touched.append(str(bwu_cc.relative_to(firefox_dir)))

    # --- 21l. security/sandbox/chromium/base/threading/platform_thread_win.cc ---
    # Dynamically resolve Win8+ SetThreadInformation at both call sites.
    ptw_cc = firefox_dir / "security/sandbox/chromium/base/threading/platform_thread_win.cc"
    if ptw_cc.is_file():
        orig = ptw_cc.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_sti1 = (
                "    [[maybe_unused]] const BOOL memory_priority_success =\n"
                "        SetThreadInformation(platform_handle, ::ThreadMemoryPriority,\n"
                "                             &memory_priority, sizeof(memory_priority));"
            )
            new_sti1 = (
                "    // [Könfox Win7] SetThreadInformation requires Windows 8+.\n"
                "    static const auto pSetThreadInformation =\n"
                "        reinterpret_cast<decltype(&::SetThreadInformation)>(\n"
                "            reinterpret_cast<void*>(::GetProcAddress(\n"
                '                ::GetModuleHandleW(L"kernel32.dll"),\n'
                '                "SetThreadInformation")));\n'
                "    [[maybe_unused]] const BOOL memory_priority_success =\n"
                "        pSetThreadInformation\n"
                "            ? pSetThreadInformation(platform_handle, ::ThreadMemoryPriority,\n"
                "                                    &memory_priority, sizeof(memory_priority))\n"
                "            : FALSE;"
            )
            old_sti2 = (
                "  [[maybe_unused]] const BOOL success = ::SetThreadInformation(\n"
                "      thread_handle.platform_handle(), ::ThreadPowerThrottling,\n"
                "      &thread_power_throttling_state, sizeof(thread_power_throttling_state));"
            )
            new_sti2 = (
                "  // [Könfox Win7] SetThreadInformation requires Windows 8+.\n"
                "  static const auto pSetThreadInformation =\n"
                "      reinterpret_cast<decltype(&::SetThreadInformation)>(\n"
                "          reinterpret_cast<void*>(::GetProcAddress(\n"
                '              ::GetModuleHandleW(L"kernel32.dll"),\n'
                '              "SetThreadInformation")));\n'
                "  [[maybe_unused]] const BOOL success =\n"
                "      pSetThreadInformation\n"
                "          ? pSetThreadInformation(thread_handle.platform_handle(),\n"
                "                                  ::ThreadPowerThrottling,\n"
                "                                  &thread_power_throttling_state,\n"
                "                                  sizeof(thread_power_throttling_state))\n"
                "          : FALSE;"
            )
            if old_sti1 in patched:
                patched = patched.replace(old_sti1, new_sti1, 1)
            if old_sti2 in patched:
                patched = patched.replace(old_sti2, new_sti2, 1)
        if patched != orig:
            if not dry_run:
                ptw_cc.write_text(patched, encoding="utf-8")
            touched.append(str(ptw_cc.relative_to(firefox_dir)))

    return touched


# ---------------------------------------------------------------------------
# 22. Graphics / WebRender Win7 SP1 fixes (DirectComposition & D3D 11.1)
# ---------------------------------------------------------------------------
def patch_graphics_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    - gfx/config/gfxConfigManager.cpp: disable WebRender DirectComposition on
      < Windows 10 (dcomp.dll does not exist on Windows 7 SP1).
    - gfx/thebes/DeviceManagerDx.cpp: only request D3D_FEATURE_LEVEL_11_1 on
      Windows 8+, and skip DoesTextureSharingWork() on WARP < Windows 8.
    - gfx/thebes/gfxPlatform.cpp: guard D3D11 double buffering and WMF
      zero-copy NV12 textures behind IsWin10OrLater().
    - gfx/thebes/d3dkmtQueryStatistics.h & gfxWindowsPlatform.cpp: use the
      Windows 7 struct layout for D3DKMTQS_SEGMENT_INFO / ProcessSegmentInfo
      on < Windows 8 so GPU memory reporting does not read corrupt fields.
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
        if "[Könfox Win7 warp]" not in patched:
            old_warp = (
                '                    "FEATURE_FAILURE_D3D11_WARP_DEVICE2"_ns);\n'
                "    return;\n"
                "  }\n\n"
                "  bool textureSharingWorks = D3D11Checks::DoesTextureSharingWork(device);"
            )
            new_warp = (
                '                    "FEATURE_FAILURE_D3D11_WARP_DEVICE2"_ns);\n'
                "    return;\n"
                "  }\n\n"
                "  // [Könfox Win7 warp] DoesTextureSharingWork corrupts WARP D3D11 on Win7.\n"
                "  bool textureSharingWorks =\n"
                "      mozilla::IsWin8OrLater() && D3D11Checks::DoesTextureSharingWork(device);"
            )
            if old_warp in patched:
                patched = patched.replace(old_warp, new_warp, 1)
        if patched != orig:
            if not dry_run:
                dm_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(dm_cpp.relative_to(firefox_dir)))

    gp_cpp = firefox_dir / "gfx/thebes/gfxPlatform.cpp"
    if gp_cpp.is_file():
        orig = gp_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_db = (
                "    if (StaticPrefs::gfx_direct3d11_use_double_buffering()) {\n"
                "      gfxVars::SetUseDoubleBufferingWithCompositor(true);\n"
                "    }"
            )
            new_db = (
                "    // [Könfox Win7] Double buffering with compositor requires Windows 10+.\n"
                "    if (IsWin10OrLater() && StaticPrefs::gfx_direct3d11_use_double_buffering()) {\n"
                "      gfxVars::SetUseDoubleBufferingWithCompositor(true);\n"
                "    }"
            )
            old_zc = "  if (StaticPrefs::media_wmf_zero_copy_nv12_textures_AtStartup()) {"
            new_zc = (
                "  if (\n"
                "#ifdef XP_WIN\n"
                "      IsWin10OrLater() &&\n"
                "#endif\n"
                "      StaticPrefs::media_wmf_zero_copy_nv12_textures_AtStartup()) {"
            )
            if old_db in patched:
                patched = patched.replace(old_db, new_db, 1)
            if old_zc in patched:
                patched = patched.replace(old_zc, new_zc, 1)
        if patched != orig:
            if not dry_run:
                gp_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(gp_cpp.relative_to(firefox_dir)))

    d3d_h = firefox_dir / "gfx/thebes/d3dkmtQueryStatistics.h"
    if d3d_h.is_file():
        orig = d3d_h.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_seg = (
                "typedef struct _D3DKMTQS_SEGMENT_INFO {\n"
                "  ULONGLONG Filler[3];\n"
                "  struct {\n"
                "    ULONGLONG Filler;\n"
                "    ULONG Filler2[2];\n"
                "  } Filler_M;\n\n"
                "  ULONG Aperture;\n\n"
                "  ULONGLONG Filler3[5];\n"
                "  ULONG64 Filler4[8];\n"
                "} D3DKMTQS_SEGMENT_INFO;"
            )
            new_seg = (
                "// [Könfox Win7] Win7 uses ULONG fields for D3DKMTQS_SEGMENT_INFO.\n"
                "typedef struct _D3DKMTQS_SEGMENT_INFO_WIN7 {\n"
                "  ULONG Filler[3];\n"
                "  struct {\n"
                "    ULONGLONG Filler;\n"
                "    ULONG Filler2[2];\n"
                "  } Filler_M;\n"
                "  ULONG Aperture;\n"
                "  ULONGLONG Filler3[5];\n"
                "  ULONG64 Filler4[8];\n"
                "} D3DKMTQS_SEGMENT_INFO_WIN7;\n\n"
                "typedef struct _D3DKMTQS_SEGMENT_INFO {\n"
                "  ULONGLONG Filler[3];\n"
                "  struct {\n"
                "    ULONGLONG Filler;\n"
                "    ULONG Filler2[2];\n"
                "  } Filler_M;\n\n"
                "  ULONG Aperture;\n\n"
                "  ULONGLONG Filler3[5];\n"
                "  ULONG64 Filler4[8];\n"
                "} D3DKMTQS_SEGMENT_INFO;"
            )
            old_pseg = (
                "typedef struct _D3DKMTQS_PROCESS_SEGMENT_INFO {\n"
                "  ULONGLONG BytesCommitted;"
            )
            new_pseg = (
                "typedef struct _D3DKMTQS_PROCESS_SEGMENT_INFO {\n"
                "  union {\n"
                "    ULONGLONG BytesCommitted;\n"
                "    ULONG BytesCommittedWin7;\n"
                "  };"
            )
            old_res = "  D3DKMTQS_SEGMENT_INFO SegmentInfo;"
            new_res = (
                "  D3DKMTQS_SEGMENT_INFO SegmentInfo;\n"
                "  D3DKMTQS_SEGMENT_INFO_WIN7 SegmentInfoWin7;"
            )
            if old_seg in patched and old_pseg in patched and old_res in patched:
                patched = (
                    patched.replace(old_seg, new_seg, 1)
                    .replace(old_pseg, new_pseg, 1)
                    .replace(old_res, new_res, 1)
                )
        if patched != orig:
            if not dry_run:
                d3d_h.write_text(patched, encoding="utf-8")
            touched.append(str(d3d_h.relative_to(firefox_dir)))

    gwp_cpp = firefox_dir / "gfx/thebes/gfxWindowsPlatform.cpp"
    if gwp_cpp.is_file():
        orig = gwp_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_ap = "            bool aperture = queryStatistics.QueryResult.SegmentInfo.Aperture;"
            new_ap = (
                "            // [Könfox Win7] Read Win7 struct layout on < Windows 8.\n"
                "            bool aperture = mozilla::IsWin8OrLater()\n"
                "                                ? queryStatistics.QueryResult.SegmentInfo.Aperture\n"
                "                                : queryStatistics.QueryResult.SegmentInfoWin7.Aperture;"
            )
            old_bc = (
                "              ULONGLONG bytesCommitted =\n"
                "                  queryStatistics.QueryResult.ProcessSegmentInfo.BytesCommitted;"
            )
            new_bc = (
                "              ULONGLONG bytesCommitted =\n"
                "                  mozilla::IsWin8OrLater()\n"
                "                      ? queryStatistics.QueryResult.ProcessSegmentInfo.BytesCommitted\n"
                "                      : queryStatistics.QueryResult.ProcessSegmentInfo.BytesCommittedWin7;"
            )
            if old_ap in patched and old_bc in patched:
                patched = patched.replace(old_ap, new_ap, 1).replace(old_bc, new_bc, 1)
        if patched != orig:
            if not dry_run:
                gwp_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(gwp_cpp.relative_to(firefox_dir)))

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

    # --- 23k. intl/locale/windows/OSPreferences_win.cpp ---
    # Calls RoGetActivationFactory(HStringReference(...)) unguarded on startup,
    # triggering an SEH 0xC06D007E delay-load crash on Windows 7 SP1.
    osp_cpp = firefox_dir / "intl/locale/windows/OSPreferences_win.cpp"
    if osp_cpp.is_file():
        orig = osp_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "OSPreferences.h"',
                    '#include "OSPreferences.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            old_ro = (
                "  if (SUCCEEDED(RoGetActivationFactory(\n"
                "          HStringReference(\n"
                "              RuntimeClass_Windows_System_UserProfile_GlobalizationPreferences)\n"
                "              .Get(),"
            )
            new_ro = (
                "  // [Könfox Win7] WinRT GlobalizationPreferences requires Windows 8+;\n"
                "  // calling RoGetActivationFactory/HStringReference delay-loads WinRT DLLs.\n"
                "  if (mozilla::IsWin8OrLater() &&\n"
                "      SUCCEEDED(RoGetActivationFactory(\n"
                "          HStringReference(\n"
                "              RuntimeClass_Windows_System_UserProfile_GlobalizationPreferences)\n"
                "              .Get(),"
            )
            if old_ro in patched:
                patched = patched.replace(old_ro, new_ro, 1)
        if patched != orig:
            if not dry_run:
                osp_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(osp_cpp.relative_to(firefox_dir)))

    # --- 23l. browser/components/shell/nsWindowsShellService.cpp ---
    # Guard MSIX/WinRT StartupTask and Package3 activation factories on < Win10.
    wss_cpp = firefox_dir / "browser/components/shell/nsWindowsShellService.cpp"
    if wss_cpp.is_file():
        orig = wss_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            for fn_hdr in (
                "static void EnableLaunchOnLoginMSIXImpl(\n"
                "    const nsString& capturedTaskId,\n"
                "    const RefPtr<nsMainThreadPtrHolder<dom::Promise>> promiseHolder) {\n",
                "static void DisableLaunchOnLoginMSIXImpl(\n"
                "    const nsString& capturedTaskId,\n"
                "    const RefPtr<nsMainThreadPtrHolder<dom::Promise>> promiseHolder) {\n",
                "static void GetLaunchOnLoginEnabledMSIXImpl(\n"
                "    const nsString& capturedTaskId,\n"
                "    const RefPtr<nsMainThreadPtrHolder<dom::Promise>> promiseHolder) {\n",
            ):
                if fn_hdr in patched:
                    patched = patched.replace(
                        fn_hdr,
                        (
                            fn_hdr
                            + "  // [Könfox Win7] WinRT StartupTask requires Windows 10+.\n"
                            + "  if (!mozilla::IsWin10OrLater()) {\n"
                            + "    REJECT_AND_RETURN(promiseHolder, NS_ERROR_NOT_IMPLEMENTED, /* void */);\n"
                            + "  }\n"
                        ),
                        1,
                    )
            old_pkg3 = "static HRESULT GetPackage3(ComPtr<IPackage3>& package3) {\n"
            if old_pkg3 in patched:
                patched = patched.replace(
                    old_pkg3,
                    (
                        old_pkg3
                        + "  // [Könfox Win7] WinRT Package API requires Windows 10+.\n"
                        + "  if (!mozilla::IsWin10OrLater()) {\n"
                        + "    return E_NOTIMPL;\n"
                        + "  }\n"
                    ),
                    1,
                )
        if patched != orig:
            if not dry_run:
                wss_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(wss_cpp.relative_to(firefox_dir)))

    # --- 23m. dom/geolocation/GeolocationSystemWin.cpp ---
    gsw_cpp = firefox_dir / "dom/geolocation/GeolocationSystemWin.cpp"
    if gsw_cpp.is_file():
        orig = gsw_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "GeolocationSystem.h"',
                    '#include "GeolocationSystem.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            old_caf = (
                "ComPtr<TypeToCreate> CreateFromActivationFactory(const wchar_t* aNamespace) {\n"
                "  ComPtr<TypeToCreate> newObject;\n"
            )
            new_caf = (
                "ComPtr<TypeToCreate> CreateFromActivationFactory(const wchar_t* aNamespace) {\n"
                "  ComPtr<TypeToCreate> newObject;\n"
                "  // [Könfox Win7] WinRT AppCapability/Launcher requires Windows 10+.\n"
                "  if (!mozilla::IsWin10OrLater()) {\n"
                "    return newObject;\n"
                "  }\n"
            )
            if old_caf in patched:
                patched = patched.replace(old_caf, new_caf, 1)
        if patched != orig:
            if not dry_run:
                gsw_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(gsw_cpp.relative_to(firefox_dir)))

    # --- 23n. dom/system/windows/location/WindowsRuntimeLocationChild.cpp ---
    wrl_cpp = firefox_dir / "dom/system/windows/location/WindowsRuntimeLocationChild.cpp"
    if wrl_cpp.is_file():
        orig = wrl_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "WindowsRuntimeLocationChild.h"',
                    '#include "WindowsRuntimeLocationChild.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            old_start = (
                "  ComPtr<IInspectable> inspectable;\n"
                "  HRESULT hr = RoActivateInstance("
            )
            new_start = (
                "  // [Könfox Win7] WinRT Geolocator requires Windows 10+.\n"
                "  if (!mozilla::IsWin10OrLater()) {\n"
                "    return IPC_OK();\n"
                "  }\n\n"
                "  ComPtr<IInspectable> inspectable;\n"
                "  HRESULT hr = RoActivateInstance("
            )
            if old_start in patched:
                patched = patched.replace(old_start, new_start, 1)
        if patched != orig:
            if not dry_run:
                wrl_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(wrl_cpp.relative_to(firefox_dir)))

    # --- 23o. widget/windows/WinRegistry.cpp ---
    # REG_NOTIFY_THREAD_AGNOSTIC is Windows 8+; passing it to
    # RegNotifyChangeKeyValue on Win7 SP1 fails with ERROR_INVALID_PARAMETER,
    # breaking registry watching (including system proxy change detection).
    wreg_cpp = firefox_dir / "widget/windows/WinRegistry.cpp"
    if wreg_cpp.is_file():
        orig = wreg_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "WinRegistry.h"',
                    '#include "WinRegistry.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            old_flags = (
                "  DWORD flags = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES |\n"
                "                REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY |\n"
                "                REG_NOTIFY_THREAD_AGNOSTIC;"
            )
            new_flags = (
                "  DWORD flags = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES |\n"
                "                REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY;\n"
                "  // [Könfox Win7] REG_NOTIFY_THREAD_AGNOSTIC requires Windows 8+.\n"
                "  if (mozilla::IsWin8OrLater()) {\n"
                "    flags |= REG_NOTIFY_THREAD_AGNOSTIC;\n"
                "  }"
            )
            if old_flags in patched:
                patched = patched.replace(old_flags, new_flags, 1)
        if patched != orig:
            if not dry_run:
                wreg_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(wreg_cpp.relative_to(firefox_dir)))

    # --- 23p. widget/windows/WinUtils.cpp ---
    wu_cpp = firefox_dir / "widget/windows/WinUtils.cpp"
    if wu_cpp.is_file():
        orig = wu_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_pkg = "  sHasPackageIdentity = mozilla::HasPackageIdentity();"
            new_pkg = (
                "  // [Könfox Win7] Package identity requires Windows 8+.\n"
                "  sHasPackageIdentity = mozilla::IsWin8OrLater() && mozilla::HasPackageIdentity();"
            )
            if old_pkg in patched:
                patched = patched.replace(old_pkg, new_pkg, 1)
        if patched != orig:
            if not dry_run:
                wu_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(wu_cpp.relative_to(firefox_dir)))

    # --- 23q. widget/windows/nsWindow.cpp ---
    # EVENT_OBJECT_CLOAKED/UNCLOAKED and TIP UIA workaround hooks are Win8+.
    nw_cpp = firefox_dir / "widget/windows/nsWindow.cpp"
    if nw_cpp.is_file():
        orig = nw_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_tip = (
                "  static void Initialize() {\n"
                "    if (sInstance) {\n"
                "      return;\n"
                "    }"
            )
            new_tip = (
                "  static void Initialize() {\n"
                "    // [Könfox Win7] TIP UIA hook is only needed on Windows 8+.\n"
                "    if (!IsWin8OrLater() || sInstance) {\n"
                "      return;\n"
                "    }"
            )
            old_cloak = "  if (!sWinCloakEventHook) {"
            new_cloak = (
                "  // [Könfox Win7] DWM cloaking events require Windows 8+.\n"
                "  if (IsWin8OrLater() && !sWinCloakEventHook) {"
            )
            if old_tip in patched:
                patched = patched.replace(old_tip, new_tip, 1)
            if old_cloak in patched:
                patched = patched.replace(old_cloak, new_cloak, 1)
        if patched != orig:
            if not dry_run:
                nw_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(nw_cpp.relative_to(firefox_dir)))

    # --- 23r. toolkit/crashreporter/nsExceptionHandler.cpp ---
    # MiniDumpWithIndirectlyReferencedMemory triggers dbghelp.dll bugs on Win7.
    eh_cpp = firefox_dir / "toolkit/crashreporter/nsExceptionHandler.cpp"
    if eh_cpp.is_file():
        orig = eh_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#  include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#  include "mozilla/WindowsDllBlocklist.h"',
                    '#  include "mozilla/WindowsDllBlocklist.h"\n#  include "mozilla/WindowsVersion.h"',
                    1,
                )
            old_md = (
                "  minidump_type = static_cast<MINIDUMP_TYPE>(\n"
                "      minidump_type |\n"
                "      // This is Nightly only because this doubles the size of minidumps based\n"
                "      // on the experimental data.\n"
                "      MiniDumpWithProcessThreadData |\n"
                "      // This allows us to examine heap objects referenced from stack objects\n"
                "      // at the cost of further doubling the size of minidumps.\n"
                "      MiniDumpWithIndirectlyReferencedMemory);"
            )
            new_md = (
                "  // [Könfox Win7] MiniDumpWithIndirectlyReferencedMemory fails on Win7 dbghelp.\n"
                "  minidump_type = static_cast<MINIDUMP_TYPE>(\n"
                "      minidump_type | MiniDumpWithProcessThreadData |\n"
                "      (mozilla::IsWin8OrLater() ? MiniDumpWithIndirectlyReferencedMemory : 0));"
            )
            if old_md in patched:
                patched = patched.replace(old_md, new_md, 1)
        if patched != orig:
            if not dry_run:
                eh_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(eh_cpp.relative_to(firefox_dir)))

    # --- 23s. browser/components/shell/rust/shell_windows/src/taskbar/shortcut.rs ---
    # Replace Win10 1803+ WinRT UserDataPaths::GetDefault() and PropVariantToString
    # with Win7-native SHGetFolderPathW(CSIDL_APPDATA) + direct VT_LPWSTR extraction.
    # Fixes the new-profile browser crash when about:welcome checks taskbar pin status.
    sc_rs = firefox_dir / "browser/components/shell/rust/shell_windows/src/taskbar/shortcut.rs"
    if sc_rs.is_file():
        orig = sc_rs.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_imp = (
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
                "    },"
            )
            new_imp = (
                "    // [Könfox Win7] Use SHGetFolderPathW(CSIDL_APPDATA) & VT_LPWSTR instead of Win10 UserDataPaths.\n"
                "    Win32::{\n"
                "        Foundation::{E_FAIL, MAX_PATH},\n"
                "        Storage::{\n"
                "            EnhancedStorage::PKEY_AppUserModel_ID,\n"
                "            Packaging::Appx::APPLICATION_USER_MODEL_ID_MAX_LENGTH,\n"
                "        },\n"
                "        System::{\n"
                "            Com::{\n"
                "                CoCreateInstance, IPersistFile,\n"
                "                StructuredStorage::PropVariantClear,\n"
                "                CLSCTX_INPROC_SERVER, STGM,\n"
                "            },\n"
                "            Variant::VT_LPWSTR,\n"
                "        },\n"
                "        UI::Shell::{\n"
                "            CSIDL_APPDATA, IShellLinkW, PropertiesSystem::IPropertyStore, SHGetFolderPathW,\n"
                "            SHGFP_TYPE_CURRENT, ShellLink as ShellLinkClsid,\n"
                "        },\n"
                "    },"
            )
            old_appdata = (
                "    let appdata_folder = UserDataPaths::GetDefault()\n"
                "        .and_then(|paths| paths.RoamingAppData())\n"
                "        .map(|path| PathBuf::from(path.to_os_string()))\n"
                "        .map_err(IsPinnedError::GetAppData)?;"
            )
            new_appdata = (
                "    let mut appdata_folder = [0u16; MAX_PATH as usize];\n"
                "    // SAFETY: The buffer holds MAX_PATH characters; null handles select the current user.\n"
                "    unsafe {\n"
                "        SHGetFolderPathW(\n"
                "            None,\n"
                "            CSIDL_APPDATA as i32,\n"
                "            None,\n"
                "            SHGFP_TYPE_CURRENT.0 as u32,\n"
                "            &mut appdata_folder,\n"
                "        )\n"
                "    }\n"
                "    .map_err(IsPinnedError::GetAppData)?;\n"
                "    let appdata_folder = appdata_folder.split(|&c| c == 0).next().unwrap_or(&[]);\n"
                "    let appdata_folder = PathBuf::from(OsString::from_wide(appdata_folder));"
            )
            old_aumid = (
                "        let mut aumid = [0u16; APPLICATION_USER_MODEL_ID_MAX_LENGTH as usize];\n"
                "        // SAFETY: `propvar` pointer derived from a reference.\n"
                "        unsafe { PropVariantToString(&*pv, &mut aumid) }?;\n\n"
                "        // Strip the trailing nulls, including the null terminator.\n"
                "        let aumid = aumid.split(|&c| c == 0).next().unwrap_or(&[]);"
            )
            new_aumid = (
                "        // SAFETY: GetValue initialized the variant; check its type before reading the union.\n"
                "        let aumid = unsafe {\n"
                "            if pv.Anonymous.Anonymous.vt != VT_LPWSTR {\n"
                "                return Err(E_FAIL.into());\n"
                "            }\n"
                "            pv.Anonymous.Anonymous.Anonymous.pwszVal\n"
                "        };\n"
                "        if aumid.is_null() {\n"
                "            return Err(E_FAIL.into());\n"
                "        }\n"
                "        // SAFETY: VT_LPWSTR is null-terminated and remains owned by pv until after the copy.\n"
                "        let aumid = unsafe { aumid.as_wide() };\n"
                "        if aumid.len() >= APPLICATION_USER_MODEL_ID_MAX_LENGTH as usize {\n"
                "            return Err(E_FAIL.into());\n"
                "        }"
            )
            if old_imp in patched and old_appdata in patched and old_aumid in patched:
                patched = patched.replace(old_imp, new_imp, 1)
                patched = patched.replace(old_appdata, new_appdata, 1)
                patched = patched.replace(old_aumid, new_aumid, 1)
        if patched != orig:
            if not dry_run:
                sc_rs.write_text(patched, encoding="utf-8")
            touched.append(str(sc_rs.relative_to(firefox_dir)))

    # --- 23t. browser/components/migration/MSMigrationUtils.sys.mjs ---
    # Windows Vault password migration requires Windows 8+ (vaultcli.dll).
    msm_js = firefox_dir / "browser/components/migration/MSMigrationUtils.sys.mjs"
    if msm_js.is_file():
        orig = msm_js.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if "AppConstants" not in patched:
                patched = patched.replace(
                    'import { ctypes } from "resource://gre/modules/ctypes.sys.mjs";',
                    'import { AppConstants } from "resource://gre/modules/AppConstants.sys.mjs";\n'
                    'import { ctypes } from "resource://gre/modules/ctypes.sys.mjs";',
                    1,
                )
            old_vault = (
                "  get exists() {\n"
                "    // check if there are passwords available for migration.\n"
                "    return this.migrate(() => {}, true);\n"
                "  },"
            )
            new_vault = (
                "  get exists() {\n"
                "    // [Könfox Win7] Windows Vault migration requires Windows 8+.\n"
                '    if (AppConstants.isPlatformAndVersionAtLeast("win", "6.2")) {\n'
                "      return this.migrate(() => {}, true);\n"
                "    }\n"
                "    return false;\n"
                "  },"
            )
            if old_vault in patched:
                patched = patched.replace(old_vault, new_vault, 1)
        if patched != orig:
            if not dry_run:
                msm_js.write_text(patched, encoding="utf-8")
            touched.append(str(msm_js.relative_to(firefox_dir)))

    # --- 23u. xpcom/base/nsWindowsHelpers.h ---
    # LOAD_LIBRARY_SEARCH_SYSTEM32 requires KB2533623 on Win7 SP1; fall back to
    # ConstructSystem32Path + LOAD_WITH_ALTERED_SEARCH_PATH when absent.
    wh_h = firefox_dir / "xpcom/base/nsWindowsHelpers.h"
    if wh_h.is_file():
        orig = wh_h.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_ll = (
                "HMODULE inline LoadLibrarySystem32(LPCWSTR aModule) {\n"
                "  return LoadLibraryExW(aModule, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);\n"
                "}"
            )
            new_ll = (
                "HMODULE inline LoadLibrarySystem32(LPCWSTR aModule) {\n"
                "  // [Könfox Win7] LOAD_LIBRARY_SEARCH_SYSTEM32 requires KB2533623 on Win7.\n"
                "  static const auto setDefaultDllDirectories =\n"
                '      GetProcAddress(GetModuleHandleW(L"kernel32"), "SetDefaultDllDirectories");\n'
                "  if (setDefaultDllDirectories) {\n"
                "    return LoadLibraryExW(aModule, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);\n"
                "  }\n"
                "  WCHAR systemPath[MAX_PATH + 1];\n"
                "  if (!ConstructSystem32Path(aModule, systemPath, MAX_PATH + 1)) {\n"
                "    return NULL;\n"
                "  }\n"
                "  return LoadLibraryExW(systemPath, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);\n"
                "}"
            )
            if old_ll in patched:
                patched = patched.replace(old_ll, new_ll, 1)
        if patched != orig:
            if not dry_run:
                wh_h.write_text(patched, encoding="utf-8")
            touched.append(str(wh_h.relative_to(firefox_dir)))

    # --- 23v. browser/app/nsBrowserApp.cpp ---
    # Fall back to plain LoadLibraryW if LOAD_LIBRARY_SEARCH_SYSTEM32 fails on
    # Win7 SP1 without KB2533623.
    ba_cpp = firefox_dir / "browser/app/nsBrowserApp.cpp"
    if ba_cpp.is_file():
        orig = ba_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_cb = '  ::LoadLibraryExW(L"cryptbase.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);'
            new_cb = (
                "  // [Könfox Win7] Fall back if LOAD_LIBRARY_SEARCH_SYSTEM32 is unsupported (no KB2533623).\n"
                '  if (!::LoadLibraryExW(L"cryptbase.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {\n'
                '    ::LoadLibraryW(L"cryptbase.dll");\n'
                "  }"
            )
            if old_cb in patched:
                patched = patched.replace(old_cb, new_cb, 1)
        if patched != orig:
            if not dry_run:
                ba_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(ba_cpp.relative_to(firefox_dir)))

    # --- 23w. xpcom/threads/TimerThreadMonitor_windows.cpp ---
    # Use Win7-native CreateWaitableTimerW / SetWaitableTimer on < Windows 8
    # (Feodor2 01c7c012c9) while preserving high-res timers on Windows 10+.
    ttm_cpp = firefox_dir / "xpcom/threads/TimerThreadMonitor_windows.cpp"
    if ttm_cpp.is_file():
        orig = ttm_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "mozilla/Assertions.h"',
                    '#include "mozilla/Assertions.h"\n#include "mozilla/WindowsVersion.h"',
                    1,
                )
            old_ctor = (
                "      mHiResTimer(CreateWaitableTimerEx(nullptr, nullptr,\n"
                "                                        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,\n"
                "                                        TIMER_ALL_ACCESS)),\n"
                "      mLoResTimer(CreateWaitableTimerEx(nullptr, nullptr, 0, TIMER_ALL_ACCESS)),"
            )
            new_ctor = (
                "      // [Könfox Win7] Avoid CREATE_WAITABLE_TIMER_HIGH_RESOLUTION / Ex on Win7.\n"
                "      mHiResTimer(mozilla::IsWin10OrLater()\n"
                "                      ? CreateWaitableTimerEx(nullptr, nullptr,\n"
                "                                              CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,\n"
                "                                              TIMER_ALL_ACCESS)\n"
                "                      : nullptr),\n"
                "      mLoResTimer(mozilla::IsWin8OrLater()\n"
                "                      ? CreateWaitableTimerEx(nullptr, nullptr, 0, TIMER_ALL_ACCESS)\n"
                "                      : CreateWaitableTimerW(nullptr, FALSE, nullptr)),"
            )
            old_set = (
                "  [[maybe_unused]] const BOOL ok = SetWaitableTimerEx(\n"
                "      timer, &dueTime, 0, nullptr, nullptr, nullptr, timerTolerance);"
            )
            new_set = (
                "  [[maybe_unused]] const BOOL ok =\n"
                "      mozilla::IsWin8OrLater()\n"
                "          ? SetWaitableTimerEx(timer, &dueTime, 0, nullptr, nullptr, nullptr,\n"
                "                               timerTolerance)\n"
                "          : SetWaitableTimer(timer, &dueTime, 0, nullptr, nullptr, FALSE);"
            )
            if old_ctor in patched:
                patched = patched.replace(old_ctor, new_ctor, 1)
            if old_set in patched:
                patched = patched.replace(old_set, new_set, 1)
        if patched != orig:
            if not dry_run:
                ttm_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(ttm_cpp.relative_to(firefox_dir)))

    # --- 23x. toolkit/xre/nsAppRunner.cpp ---
    # Pre-warm CSPRNG (cryptbase.dll / RtlGenRandom) in parent startup too (Feodor2 24c3b1039f).
    ar_cpp = firefox_dir / "toolkit/xre/nsAppRunner.cpp"
    if ar_cpp.is_file():
        orig = ar_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#  include "mozilla/RandomNum.h"' not in patched:
                patched = patched.replace(
                    '#  include "mozilla/WindowsDllBlocklist.h"',
                    '#  include "mozilla/RandomNum.h"\n#  include "mozilla/WindowsDllBlocklist.h"',
                    1,
                )
            old_sbs = (
                "#  if defined(MOZ_SANDBOX)\n"
                "  mAppData->sandboxBrokerServices = aConfig.sandboxBrokerServices;\n"
                "#  endif  // defined(MOZ_SANDBOX)"
            )
            new_sbs = (
                "#  if defined(MOZ_SANDBOX)\n"
                "  mAppData->sandboxBrokerServices = aConfig.sandboxBrokerServices;\n"
                "#  endif  // defined(MOZ_SANDBOX)\n\n"
                "  // [Könfox Win7] Pre-warm CSPRNG (cryptbase.dll / RtlGenRandom).\n"
                "  (void)mozilla::RandomUint64OrDie();"
            )
            if old_sbs in patched:
                patched = patched.replace(old_sbs, new_sbs, 1)
        if patched != orig:
            if not dry_run:
                ar_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(ar_cpp.relative_to(firefox_dir)))

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


# ---------------------------------------------------------------------------
# 25. IPC (MSCOM AppContainer SID + Win7 Freezable ShMem) & Neqo HTTP/3 Win7
# ---------------------------------------------------------------------------
def patch_ipc_and_networking_win7(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    Fixes remaining Windows 7 SP1 x64 IPC / networking incompatibilities:
      - ipc/mscom/ProcessRuntime.cpp: guard WinBuiltinAnyPackageSid and
        TokenAppContainerSid behind IsWin8OrLater() so ProcessRuntime::
        InitializeSecurity() succeeds on Windows 7 SP1.
      - ipc/glue/SharedMemoryPlatform_windows.cpp: give freezable shared memory
        mappings a random name on < Win8.1 because Windows 7 ignores
        SECURITY_ATTRIBUTES on unnamed file mappings.
      - netwerk/socket/neqo_glue/src/lib.rs: disable pmtud_iface_mtu on Windows
        to avoid unsupported Win7 interface MTU queries in HTTP/3 QUIC.
    """
    touched: list[str] = []

    # 25a. ipc/mscom/ProcessRuntime.cpp
    pr_cpp = firefox_dir / "ipc/mscom/ProcessRuntime.cpp"
    if pr_cpp.is_file():
        orig = pr_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "mozilla/WindowsProcessMitigations.h"',
                    '#include "mozilla/WindowsVersion.h"\n#include "mozilla/WindowsProcessMitigations.h"',
                    1,
                )
            old_parent = "  if (aProcessCategory == ProcessCategory::GeckoBrowserParent) {"
            new_parent = (
                "  // [Könfox Win7] AppContainer SIDs (WinBuiltinAnyPackageSid) require Windows 8+.\n"
                "  const bool appContainersSupported = mozilla::IsWin8OrLater();\n"
                "  if (aProcessCategory == ProcessCategory::GeckoBrowserParent &&\n"
                "      appContainersSupported) {"
            )
            old_tok = (
                "  bool haveAppContainerSid =\n"
                "      ::GetTokenInformation(processToken, TokenAppContainerSid,"
            )
            new_tok = (
                "  bool haveAppContainerSid =\n"
                "      appContainersSupported &&\n"
                "      ::GetTokenInformation(processToken, TokenAppContainerSid,"
            )
            if old_parent in patched and old_tok in patched:
                patched = patched.replace(old_parent, new_parent, 1).replace(
                    old_tok, new_tok, 1
                )
        if patched != orig:
            if not dry_run:
                pr_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(pr_cpp.relative_to(firefox_dir)))

    # 25b. ipc/glue/SharedMemoryPlatform_windows.cpp
    shm_cpp = firefox_dir / "ipc/glue/SharedMemoryPlatform_windows.cpp"
    if shm_cpp.is_file():
        orig = shm_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "nsDebug.h"',
                    (
                        '#include "nsDebug.h"\n'
                        "#include <cwchar>\n"
                        "#include <iterator>\n"
                        '#include "mozilla/RandomNum.h"\n'
                        '#include "mozilla/WindowsVersion.h"'
                    ),
                    1,
                )
            old_dacl = "  ACL dacl;\n\n  if (aFreezable) {"
            new_dacl = (
                "  ACL dacl;\n"
                "  wchar_t name[80] = {};\n\n"
                "  if (aFreezable) {"
            )
            old_sd = (
                "        NS_WARN_IF(!::SetSecurityDescriptorDacl(&sd, TRUE, &dacl, FALSE))) {\n"
                "      return Nothing();\n"
                "    }\n"
                "  }\n\n"
                "  auto handle = MozCreateFileMappingW(psa, PAGE_READWRITE, 0,\n"
                "                                      static_cast<DWORD>(aSize), nullptr);"
            )
            new_sd = (
                "        NS_WARN_IF(!::SetSecurityDescriptorDacl(&sd, TRUE, &dacl, FALSE))) {\n"
                "      return Nothing();\n"
                "    }\n\n"
                "    // [Könfox Win7] Windows 7 ignores SECURITY_ATTRIBUTES on unnamed\n"
                "    // file mappings; assign a random name on < Windows 8.1.\n"
                "    if (!mozilla::IsWin8Point1OrLater()) {\n"
                "      mozilla::Maybe<uint64_t> r0 = mozilla::RandomUint64();\n"
                "      mozilla::Maybe<uint64_t> r1 = mozilla::RandomUint64();\n"
                "      mozilla::Maybe<uint64_t> r2 = mozilla::RandomUint64();\n"
                "      mozilla::Maybe<uint64_t> r3 = mozilla::RandomUint64();\n"
                "      if (NS_WARN_IF(r0.isNothing() || r1.isNothing() ||\n"
                "                     r2.isNothing() || r3.isNothing())) {\n"
                "        return Nothing();\n"
                "      }\n"
                "      swprintf_s(name, std::size(name),\n"
                '                 L"MozSharedMem_%016llx%016llx%016llx%016llx",\n'
                "                 static_cast<unsigned long long>(*r0),\n"
                "                 static_cast<unsigned long long>(*r1),\n"
                "                 static_cast<unsigned long long>(*r2),\n"
                "                 static_cast<unsigned long long>(*r3));\n"
                "    }\n"
                "  }\n\n"
                "  auto handle = MozCreateFileMappingW(\n"
                "      psa, PAGE_READWRITE, 0, static_cast<DWORD>(aSize),\n"
                "      name[0] ? name : nullptr);"
            )
            if old_dacl in patched and old_sd in patched:
                patched = patched.replace(old_dacl, new_dacl, 1).replace(
                    old_sd, new_sd, 1
                )
        if patched != orig:
            if not dry_run:
                shm_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(shm_cpp.relative_to(firefox_dir)))

    # 25c. netwerk/socket/neqo_glue/src/lib.rs
    neqo_rs = firefox_dir / "netwerk/socket/neqo_glue/src/lib.rs"
    if neqo_rs.is_file():
        orig = neqo_rs.read_text(encoding="utf-8", errors="replace")
        patched = orig
        old_pmtud = '.pmtud_iface_mtu(cfg!(not(target_os = "openbsd")))'
        new_pmtud = '.pmtud_iface_mtu(cfg!(not(any(target_os = "openbsd", target_os = "windows"))))'
        if old_pmtud in patched:
            patched = patched.replace(old_pmtud, new_pmtud, 1)
        if patched != orig:
            if not dry_run:
                neqo_rs.write_text(patched, encoding="utf-8")
            touched.append(str(neqo_rs.relative_to(firefox_dir)))

    # 25d. toolkit/xre/nsEmbedFunctions.cpp
    # Pre-warm ole32.dll, advapi32.dll, and the CSPRNG (\Device\KsecDD via
    # cryptbase.dll) BEFORE any sandboxed child process calls LowerToken().
    # Without this, post-lockdown calls to RandomUint64() (SharedMemory, JS,
    # Rust getrandom) fail with ERROR_ACCESS_DENIED on Windows 7 SP1.
    ef_cpp = firefox_dir / "toolkit/xre/nsEmbedFunctions.cpp"
    if ef_cpp.is_file():
        orig = ef_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#  include "mozilla/RandomNum.h"' not in patched:
                patched = patched.replace(
                    '#  include "WinUtils.h"',
                    '#  include "WinUtils.h"\n#  include "mozilla/RandomNum.h"',
                    1,
                )
            old_ts = (
                "  if (aChildData->sandboxTargetServices) {\n"
                "    SandboxTarget::Instance()->SetTargetServices(\n"
                "        aChildData->sandboxTargetServices);\n"
                "  }"
            )
            new_ts = (
                "  // [Könfox Win7] Warm up ole32, advapi32, and the Win7 CSPRNG\n"
                "  // (cryptbase.dll / \\Device\\KsecDD) before LowerToken() lockdown.\n"
                '  ::LoadLibraryW(L"ole32.dll");\n'
                '  ::LoadLibraryW(L"advapi32.dll");\n'
                "  (void)mozilla::RandomUint64OrDie();\n\n"
                "  if (aChildData->sandboxTargetServices) {\n"
                "    SandboxTarget::Instance()->SetTargetServices(\n"
                "        aChildData->sandboxTargetServices);\n"
                "  }"
            )
            if old_ts in patched:
                patched = patched.replace(old_ts, new_ts, 1)
        if patched != orig:
            if not dry_run:
                ef_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(ef_cpp.relative_to(firefox_dir)))

    # 25e. ipc/mscom/Utils.cpp
    # SHCreateMemStream is not thread-safe on Windows 7; use CreateStreamOnHGlobal.
    msu_cpp = firefox_dir / "ipc/mscom/Utils.cpp"
    if msu_cpp.is_file():
        orig = msu_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            if '#include "mozilla/WindowsVersion.h"' not in patched:
                patched = patched.replace(
                    '#include "mozilla/mscom/Utils.h"',
                    '#include "mozilla/mscom/Utils.h"\n#include "mozilla/WindowsVersion.h"\n#include <cstring>',
                    1,
                )
            old_stream = (
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
                "  }"
            )
            new_stream = (
                "  if (!mozilla::IsWin8OrLater()) {\n"
                "    // [Könfox Win7] SHCreateMemStream is not thread-safe on Windows 7;\n"
                "    // fall back to CreateStreamOnHGlobal.\n"
                "    HGLOBAL hMem = ::GlobalAlloc(GMEM_MOVEABLE, aInitBufSize);\n"
                "    if (!hMem) {\n"
                "      return E_OUTOFMEMORY;\n"
                "    }\n"
                "    if (aInitBuf) {\n"
                "      void* dest = ::GlobalLock(hMem);\n"
                "      if (!dest) {\n"
                "        ::GlobalFree(hMem);\n"
                "        return E_OUTOFMEMORY;\n"
                "      }\n"
                "      std::memcpy(dest, aInitBuf, aInitBufSize);\n"
                "      ::GlobalUnlock(hMem);\n"
                "    }\n"
                "    hr = ::CreateStreamOnHGlobal(hMem, TRUE, getter_AddRefs(stream));\n"
                "    if (FAILED(hr)) {\n"
                "      ::GlobalFree(hMem);\n"
                "      return hr;\n"
                "    }\n"
                "  } else {\n"
                "    // If aInitBuf is null then initSize must be 0.\n"
                "    UINT initSize = aInitBuf ? aInitBufSize : 0;\n"
                "    stream = already_AddRefed<IStream>(::SHCreateMemStream(aInitBuf, initSize));\n"
                "    if (!stream) {\n"
                "      return E_OUTOFMEMORY;\n"
                "    }\n\n"
                "    if (!aInitBuf) {\n"
                "      // Now we'll set the required size\n"
                "      ULARGE_INTEGER newSize;\n"
                "      newSize.QuadPart = aInitBufSize;\n"
                "      hr = stream->SetSize(newSize);\n"
                "      if (FAILED(hr)) {\n"
                "        return hr;\n"
                "      }\n"
                "    }\n"
                "  }"
            )
            if old_stream in patched:
                patched = patched.replace(old_stream, new_stream, 1)
        if patched != orig:
            if not dry_run:
                msu_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(msu_cpp.relative_to(firefox_dir)))

    # 25f. toolkit/system/windowsproxy/WindowsInternetFunctionsWrapper.cpp
    # Fall back from INTERNET_PER_CONN_FLAGS_UI (IE9+) to INTERNET_PER_CONN_FLAGS
    # on Windows 7 systems where the _UI option fails.
    wifw_cpp = (
        firefox_dir
        / "toolkit/system/windowsproxy/WindowsInternetFunctionsWrapper.cpp"
    )
    if wifw_cpp.is_file():
        orig = wifw_cpp.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_q = (
                "    if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION,\n"
                "                              &list, &size)) {\n"
                '      LOG(("ReadAllOptionsLocked: InternetQueryOptionW failed"));\n'
                "      return NS_ERROR_FAILURE;\n"
                "    }"
            )
            new_q = (
                "    if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION,\n"
                "                              &list, &size)) {\n"
                "      // [Könfox Win7] Retry with INTERNET_PER_CONN_FLAGS on Win7.\n"
                "      options[0].dwOption = INTERNET_PER_CONN_FLAGS;\n"
                "      list.dwOptionError = 0;\n"
                "      size = sizeof(INTERNET_PER_CONN_OPTION_LISTW);\n"
                "      if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION,\n"
                "                                &list, &size)) {\n"
                '        LOG(("ReadAllOptionsLocked: InternetQueryOptionW failed"));\n'
                "        return NS_ERROR_FAILURE;\n"
                "      }\n"
                "    }"
            )
            if old_q in patched:
                patched = patched.replace(old_q, new_q, 1)
        if patched != orig:
            if not dry_run:
                wifw_cpp.write_text(patched, encoding="utf-8")
            touched.append(str(wifw_cpp.relative_to(firefox_dir)))

    # 25g. third_party/rust/quinn-udp/src/windows.rs (+ .cargo-checksum.json)
    # Windows 7 does not support Win10+ UDP_SEND_MSG_SIZE / IP_ECN / IPV6_ECN
    # and may return WSAEINVAL on IP_RECVECN / WSASendMsg. Disable GSO and
    # fall back cleanly to socket.0.send_to() when no cmsgs are needed or
    # WSASendMsg rejects the options.
    quinn_dir = firefox_dir / "third_party/rust/quinn-udp"
    quinn_rs = quinn_dir / "src/windows.rs"
    if quinn_rs.is_file():
        orig = quinn_rs.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if "[Könfox Win7]" not in patched:
            old_v6only = (
                "        let v6only = unsafe {\n"
                "            get_socket_option::<u32>(&*socket.0, WinSock::IPPROTO_IPV6, WinSock::IPV6_V6ONLY as _)\n"
                "        }?;"
            )
            new_v6only = (
                "        // [Könfox Win7] Only query IPV6_V6ONLY on AF_INET6 sockets;\n"
                "        // Win7 returns WSAENOPROTOOPT when querying IPPROTO_IPV6 on AF_INET.\n"
                "        let v6only = if is_ipv6 {\n"
                "            unsafe {\n"
                "                get_socket_option::<u32>(\n"
                "                    &*socket.0,\n"
                "                    WinSock::IPPROTO_IPV6,\n"
                "                    WinSock::IPV6_V6ONLY as _,\n"
                "                )\n"
                "            }?\n"
                "        } else {\n"
                "            0\n"
                "        };"
            )
            old_ecn = (
                "                    if code == WinSock::WSAENOPROTOOPT\n"
                "                    || code == WinSock::WSAEOPNOTSUPP"
            )
            new_ecn = (
                "                    // [Könfox Win7] Win7 Winsock may return WSAEINVAL for IP_RECVECN.\n"
                "                    if code == WinSock::WSAENOPROTOOPT\n"
                "                    || code == WinSock::WSAEOPNOTSUPP\n"
                "                    || code == WinSock::WSAEINVAL"
            )
            old_v6_dontfrag = (
                "            set_socket_option(\n"
                "                &*socket.0,\n"
                "                WinSock::IPPROTO_IPV6,\n"
                "                WinSock::IPV6_DONTFRAG,\n"
                "                OPTION_ON,\n"
                "            )?;"
            )
            new_v6_dontfrag = (
                "            if let Err(e) = set_socket_option(\n"
                "                &*socket.0,\n"
                "                WinSock::IPPROTO_IPV6,\n"
                "                WinSock::IPV6_DONTFRAG,\n"
                "                OPTION_ON,\n"
                "            ) {\n"
                "                if !is_ecn_unsupported(&e) {\n"
                "                    return Err(e);\n"
                "                }\n"
                "            }"
            )
            old_gso = "            max_gso_segments: AtomicUsize::new(max_gso_segments(&*socket.0)),"
            new_gso = (
                "            // [Könfox Win7] Disable UDP GSO on Windows 7.\n"
                "            max_gso_segments: AtomicUsize::new(1),"
            )
            old_gro = (
                "    pub fn gro_segments(&self) -> usize {\n"
                "        // Arbitrary reasonable value inspired by Linux and msquic\n"
                "        64\n"
                "    }"
            )
            new_gro = (
                "    pub fn gro_segments(&self) -> usize {\n"
                "        // [Könfox Win7] Windows 7 does not support UDP GRO.\n"
                "        1\n"
                "    }"
            )
            old_send_call = (
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
                "    }"
            )
            new_send_call = (
                "    // [Könfox Win7] Use send_to directly when no control messages are\n"
                "    // attached, and fall back to send_to if WSASendMsg fails on Win7.\n"
                "    if wsa_msg.Control.len == 0 {\n"
                "        return socket.0.send_to(transmit.contents, &daddr).map(|_| ());\n"
                "    }\n\n"
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
                "        _ => {\n"
                "            let err = io::Error::last_os_error();\n"
                "            if matches!(\n"
                "                err.raw_os_error(),\n"
                "                Some(code)\n"
                "                    if code == WinSock::WSAEINVAL\n"
                "                    || code == WinSock::WSAENOPROTOOPT\n"
                "                    || code == WinSock::WSAEOPNOTSUPP\n"
                "            ) {\n"
                "                socket.0.send_to(transmit.contents, &daddr).map(|_| ())\n"
                "            } else {\n"
                "                Err(err)\n"
                "            }\n"
                "        }\n"
                "    }"
            )
            if old_v6only in patched:
                patched = patched.replace(old_v6only, new_v6only, 1)
            if old_ecn in patched:
                patched = patched.replace(old_ecn, new_ecn, 1)
            if old_v6_dontfrag in patched:
                patched = patched.replace(old_v6_dontfrag, new_v6_dontfrag, 1)
            if old_gso in patched:
                patched = patched.replace(old_gso, new_gso, 1)
            if old_gro in patched:
                patched = patched.replace(old_gro, new_gro, 1)
            if old_send_call in patched:
                patched = patched.replace(old_send_call, new_send_call, 1)
        if patched != orig:
            if not dry_run:
                quinn_rs.write_text(patched, encoding="utf-8")
                update_cargo_checksum(quinn_dir, "src/windows.rs")
            touched.append(f"{quinn_rs.relative_to(firefox_dir)} (+ .cargo-checksum.json)")

    return touched


# ---------------------------------------------------------------------------
# 26. Windows 7 SP1 Titlebar Caption Icons (Minimize / Maximize / Restore / Close)
# ---------------------------------------------------------------------------
def patch_win7_titlebar_icons(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    Firefox 163 draws Windows titlebar caption buttons using Private-Use-Area
    glyphs (\\e921/\\e922/\\e923/\\e8bb) from "Segoe Fluent Icons" (Win11) and
    "Segoe MDL2 Assets" (Win10). Neither font exists on Windows 7 SP1, so the
    buttons render as missing-glyph tofu boxes.

    Replace the font-glyph rendering with crisp 10x10 vector SVG CSS mask-images
    tinted by `background-color: currentColor` so Minimize, Maximize, Restore,
    and Close render sharply on Windows 7 SP1 (and 8/10/11) across Light mode,
    Dark mode, High Contrast, active/inactive states, and red Close hover.
    """
    touched: list[str] = []
    bcss = firefox_dir / "browser/themes/windows/browser.css"
    if not bcss.is_file():
        return touched

    orig = bcss.read_text(encoding="utf-8", errors="replace")
    patched = orig
    if "[Könfox Win7 titlebar icons]" not in patched:
        old_before = (
            "  &::before {\n"
            "    display: inline-block;\n"
            "    content: inherit;\n"
            "\n"
            "    &:-moz-locale-dir(rtl) {\n"
            "      transform: scaleX(-1);\n"
            "    }\n"
            "  }"
        )
        new_before = (
            "  /* [Könfox Win7 titlebar icons] Vector SVG mask icons instead of Win10/11-only Segoe MDL2/Fluent glyphs. */\n"
            "  &::before {\n"
            "    display: inline-block;\n"
            '    content: "";\n'
            "    width: 10px;\n"
            "    height: 10px;\n"
            "    background-color: currentColor;\n"
            "    forced-color-adjust: none;\n"
            "    mask-size: 10px 10px;\n"
            "    mask-repeat: no-repeat;\n"
            "    mask-position: center;\n"
            "    vertical-align: middle;\n"
            "\n"
            "    &:-moz-locale-dir(rtl) {\n"
            "      transform: scaleX(-1);\n"
            "    }\n"
            "  }"
        )

        old_buttons = (
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
            "}"
        )
        new_buttons = (
            ".titlebar-min {\n"
            "  /* Even though we use appearance: none, -moz-default-appearance is necessary\n"
            '   * for Windows 11\'s "snap layouts" feature, see\n'
            "   * DealWithWindowsAppearanceHacks */\n"
            "  -moz-default-appearance: -moz-window-button-minimize;\n"
            "  &::before {\n"
            '    mask-image: url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 10 10\'%3E%3Crect x=\'0\' y=\'5\' width=\'10\' height=\'1\' fill=\'%23000\'/%3E%3C/svg%3E");\n'
            "  }\n"
            "}\n"
            "\n"
            ".titlebar-max {\n"
            "  -moz-default-appearance: -moz-window-button-maximize;\n"
            "  &::before {\n"
            '    mask-image: url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 10 10\'%3E%3Cpath d=\'M0.5 0.5h9v9h-9z\' fill=\'none\' stroke=\'%23000\' stroke-width=\'1\'/%3E%3C/svg%3E");\n'
            "  }\n"
            "}\n"
            "\n"
            ".titlebar-restore {\n"
            "  -moz-default-appearance: -moz-window-button-restore;\n"
            "  &::before {\n"
            '    mask-image: url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 10 10\'%3E%3Cpath d=\'M2.5 2.5V0.5h7v7H7.5M0.5 2.5h7v7h-7z\' fill=\'none\' stroke=\'%23000\' stroke-width=\'1\'/%3E%3C/svg%3E");\n'
            "  }\n"
            "}\n"
            "\n"
            ".titlebar-close {\n"
            "  -moz-default-appearance: -moz-window-button-close;\n"
            "  &::before {\n"
            '    mask-image: url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 10 10\'%3E%3Cpath d=\'M0.5 0.5l9 9M9.5 0.5l-9 9\' fill=\'none\' stroke=\'%23000\' stroke-width=\'1.1\'/%3E%3C/svg%3E");\n'
            "  }\n"
            "}"
        )

        if old_before in patched and old_buttons in patched:
            patched = patched.replace(old_before, new_before, 1).replace(
                old_buttons, new_buttons, 1
            )

    if patched != orig:
        if not dry_run:
            bcss.write_text(patched, encoding="utf-8")
        touched.append(str(bcss.relative_to(firefox_dir)))
    return touched


# ---------------------------------------------------------------------------
# 27. Remove all AI / ML / GenAI features & "AI Controls" UI from Könfox
# ---------------------------------------------------------------------------
def patch_remove_ai_features(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    Completely removes "AI Controls" from Settings and disables all AI / ML /
    GenAI integrations (Sidebar AI Chatbot, Smart Window / AI Tab, Smart Tab
    Groups, Link Preview AI, PDF.js AI Alt Text, AI Translations, Extensions
    ML API, and on-device model downloads) at both UI and default-pref layers.
    """
    touched: list[str] = []

    def _replace_pairs(rel_path: str, pairs: list[tuple[str, str]]) -> None:
        fpath = firefox_dir / rel_path
        if not fpath.is_file():
            return
        orig = fpath.read_text(encoding="utf-8", errors="replace")
        patched = orig
        for old, new in pairs:
            if old in patched and new not in patched:
                patched = patched.replace(old, new)
        if patched != orig:
            if not dry_run:
                fpath.write_text(patched, encoding="utf-8")
            touched.append(rel_path)

    # 27a. Hide "AI Controls" navigation button in about:preferences
    _replace_pairs(
        "browser/components/preferences/preferences.xhtml",
        [
            (
                '<html:moz-page-nav-button id="category-ai-features"\n'
                '        view="paneAi"',
                '<html:moz-page-nav-button id="category-ai-features"\n'
                '        hidden="true"\n'
                '        view="paneAi"',
            ),
        ],
    )

    # 27b. Force AI Controls pane permanently invisible in about:preferences
    _replace_pairs(
        "browser/components/preferences/preferences.js",
        [
            (
                '    visible: () =>\n'
                '      Services.prefs.getBoolPref("browser.preferences.aiControls", false),',
                "    // [Könfox] AI Controls permanently removed.\n"
                "    visible: () => false,",
            ),
        ],
    )

    # 27c. Remove AI Chatbot ("aichat") from default sidebar launcher tools
    _replace_pairs(
        "browser/components/sidebar/SidebarManager.sys.mjs",
        [
            (
                '"opentabs,bookmarks,aichat,history,syncedtabs,passwords";',
                '"opentabs,bookmarks,history,syncedtabs,passwords";',
            ),
        ],
    )

    # 27d. Flip core AI/ML default preferences in modules/libpref/init/all.js
    _replace_pairs(
        "modules/libpref/init/all.js",
        [
            ('pref("extensions.ml.enabled", true);', 'pref("extensions.ml.enabled", false);'),
            ('pref("browser.ai.control.default", "available");', 'pref("browser.ai.control.default", "blocked");'),
            ('pref("browser.ai.control.translations", "default");', 'pref("browser.ai.control.translations", "blocked");'),
            ('pref("browser.ai.control.pdfjsAltText", "default");', 'pref("browser.ai.control.pdfjsAltText", "blocked");'),
            ('pref("browser.ai.control.smartTabGroups", "default");', 'pref("browser.ai.control.smartTabGroups", "blocked");'),
            ('pref("browser.ai.control.linkPreviewKeyPoints", "default");', 'pref("browser.ai.control.linkPreviewKeyPoints", "blocked");'),
            ('pref("browser.ai.control.sidebarChatbot", "default");', 'pref("browser.ai.control.sidebarChatbot", "blocked");'),
            ('pref("browser.ai.control.smartWindow", "default");', 'pref("browser.ai.control.smartWindow", "blocked");'),
            ('pref("browser.ai.control.speechRecognition", "default");', 'pref("browser.ai.control.speechRecognition", "blocked");'),
            ('pref("browser.ai.control.generatedWidgets", "default");', 'pref("browser.ai.control.generatedWidgets", "blocked");'),
            ('pref("browser.ml.enable", true);', 'pref("browser.ml.enable", false);'),
            ('pref("browser.ml.llama.hwInference", true);', 'pref("browser.ml.llama.hwInference", false);'),
        ],
    )

    # 27e. Flip browser AI/GenAI/SmartWindow/SmartTab/Translations defaults in firefox.js
    _replace_pairs(
        "browser/app/profile/firefox.js",
        [
            ('pref("browser.preferences.aiControls", true);', 'pref("browser.preferences.aiControls", false);'),
            ('pref("browser.tabs.groups.smart.enabled", true);', 'pref("browser.tabs.groups.smart.enabled", false);'),
            ('pref("browser.ml.chat.enabled", true);', 'pref("browser.ml.chat.enabled", false);'),
            ('pref("browser.ml.chat.menu", true);', 'pref("browser.ml.chat.menu", false);'),
            ('pref("browser.ml.chat.page", true);', 'pref("browser.ml.chat.page", false);'),
            ('pref("browser.ml.chat.page.footerBadge", true);', 'pref("browser.ml.chat.page.footerBadge", false);'),
            ('pref("browser.ml.chat.page.menuBadge", true);', 'pref("browser.ml.chat.page.menuBadge", false);'),
            ('pref("browser.ml.chat.shortcuts", true);', 'pref("browser.ml.chat.shortcuts", false);'),
            ('pref("browser.ml.chat.shortcuts.custom", true);', 'pref("browser.ml.chat.shortcuts.custom", false);'),
            ('pref("browser.ml.chat.shortcuts.smartwindow", true);', 'pref("browser.ml.chat.shortcuts.smartwindow", false);'),
            ('pref("browser.ml.chat.sidebar", true);', 'pref("browser.ml.chat.sidebar", false);'),
            ('pref("browser.ml.linkPreview.enabled", true);', 'pref("browser.ml.linkPreview.enabled", false);'),
            ('pref("browser.ml.linkPreview.longPress", true);', 'pref("browser.ml.linkPreview.longPress", false);'),
            ('pref("browser.smartwindow.autoTabGrouping.enabled", true);', 'pref("browser.smartwindow.autoTabGrouping.enabled", false);'),
            ('pref("browser.smartwindow.autoTabGrouping.preloadModels", true);', 'pref("browser.smartwindow.autoTabGrouping.preloadModels", false);'),
            ('pref("browser.smartwindow.smartformfill.enabled", true);', 'pref("browser.smartwindow.smartformfill.enabled", false);'),
            ('pref("browser.smartwindow.aitab.menus", true);', 'pref("browser.smartwindow.aitab.menus", false);'),
            ('pref("browser.smartwindow.agent.enabled", true);', 'pref("browser.smartwindow.agent.enabled", false);'),
            ('pref("browser.smartwindow.agent.toolbar.enabled", true);', 'pref("browser.smartwindow.agent.toolbar.enabled", false);'),
            ('pref("browser.smartwindow.agent.suggestions.enabled", true);', 'pref("browser.smartwindow.agent.suggestions.enabled", false);'),
            ('pref("browser.smartwindow.memories.generateFromHistory", true);', 'pref("browser.smartwindow.memories.generateFromHistory", false);'),
            ('pref("browser.smartwindow.memories.generateFromConversation", true);', 'pref("browser.smartwindow.memories.generateFromConversation", false);'),
            ('pref("browser.smartwindow.resumeActivity.enabled", true);', 'pref("browser.smartwindow.resumeActivity.enabled", false);'),
            ('pref("browser.smartwindow.sidebar.openByDefault", true);', 'pref("browser.smartwindow.sidebar.openByDefault", false);'),
            ('pref("browser.translations.enable", true);', 'pref("browser.translations.enable", false);'),
            ('pref("browser.translations.select.enable", true);', 'pref("browser.translations.select.enable", false);'),
            ('pref("browser.translations.quickAction.enabled", true);', 'pref("browser.translations.quickAction.enabled", false);'),
        ],
    )

    # 27f. Disable PDF.js AI Alt Text & model downloads
    _replace_pairs(
        "toolkit/components/pdfjs/PdfJsOverridePrefs.js",
        [
            ('pref("pdfjs.enableAltText", true);', 'pref("pdfjs.enableAltText", false);'),
        ],
    )
    _replace_pairs(
        "toolkit/components/pdfjs/PdfJsDefaultPrefs.js",
        [
            ('pref("pdfjs.enableAltTextModelDownload", true);', 'pref("pdfjs.enableAltTextModelDownload", false);'),
        ],
    )

    # 27g. Disable StaticPrefList browser.smartwindow.aitab.enabled on Nightly
    spl = firefox_dir / "modules/libpref/init/StaticPrefList.yaml"
    if spl.is_file():
        orig = spl.read_text(encoding="utf-8", errors="replace")
        patched = orig
        old_aitab = (
            "- name: browser.smartwindow.aitab.enabled\n"
            "  type: bool\n"
            "  value: @IS_NIGHTLY_BUILD@"
        )
        new_aitab = (
            "- name: browser.smartwindow.aitab.enabled\n"
            "  type: bool\n"
            "  value: false"
        )
        if old_aitab in patched:
            patched = patched.replace(old_aitab, new_aitab, 1)
        if patched != orig:
            if not dry_run:
                spl.write_text(patched, encoding="utf-8")
            touched.append("modules/libpref/init/StaticPrefList.yaml")

    return touched


def patch_konfox_profile_launcher_and_telemetry(firefox_dir: Path, dry_run: bool) -> list[str]:
    """
    Step 28 — Könfox profile directory, Win7 launcher guard, and complete telemetry removal:
      28a. browser/app/winlauncher/LauncherProcessWin.cpp:
           Skip the Windows 10+ out-of-process launcher on < Win8 (Windows 7 SP1)
           so DllBlocklistInit.cpp:58 never fails with INTERCEPTOR_MOD_INACCESSIBLE (EventID 2)
           or logs Windows Event Viewer errors even if invoked with -launcher / env var.
      28b. browser/moz.configure, mozglue/misc/PreXULSkeletonUI.cpp,
           toolkit/crashreporter/crash_helper_server/src/logging/env.rs:
           Place Könfox user data directly under %APPDATA%\\Konfox\\ and
           %LOCALAPPDATA%\\Konfox\\ (not nested under Mozilla\\) via
           MOZ_APP_PROFILE="Konfox" and MOZ_APP_VENDOR="Konfox".
      28c. xpcom/build/LateWriteChecks.cpp,
           toolkit/components/telemetry/core/Telemetry.cpp,
           toolkit/components/glean/xpcom/FOG.cpp:
           Completely disable on-disk and in-memory telemetry recording:
             - Never create Telemetry.LateWriteFinal-* files in the profile dir
             - Never record legacy Telemetry histograms/scalars/events or Telemetry.ShutdownTime.txt
             - Skip Glean/FOG initialization & datareporting/glean dir creation when upload is off
    """
    touched: list[str] = []

    def _patch_file(rel: str, replacements: list[tuple[str, str]], marker: str = "[Könfox]") -> None:
        p = firefox_dir / rel
        if not p.is_file():
            return
        orig = p.read_text(encoding="utf-8", errors="replace")
        patched = orig
        if marker not in patched:
            for old, new in replacements:
                if old in patched:
                    patched = patched.replace(old, new, 1)
        if patched != orig:
            if not dry_run:
                p.write_text(patched, encoding="utf-8")
            touched.append(rel)

    # --- 28a. browser/app/winlauncher/LauncherProcessWin.cpp ---
    _patch_file(
        "browser/app/winlauncher/LauncherProcessWin.cpp",
        [
            (
                "  // Called from the launcher process *and* the browser process.\n"
                "  EnablePreferLoadFromSystem32IfCompatible();\n",
                "  // Called from the launcher process *and* the browser process.\n"
                "  EnablePreferLoadFromSystem32IfCompatible();\n"
                "\n"
                "  // [Könfox] Skip Win10+ out-of-process launcher on Windows 7 SP1 so\n"
                "  // DllBlocklistInit.cpp:58 never fails with INTERCEPTOR_MOD_INACCESSIBLE\n"
                "  // (EventID 2) or spawns/terminates a suspended child process.\n"
                "  if (!mozilla::IsWin8OrLater()) {\n"
                "    return Nothing();\n"
                "  }\n",
            ),
        ],
        marker="[Könfox] Skip Win10+ out-of-process launcher",
    )

    # --- 28b. Own AppData\Roaming\Konfox & AppData\Local\Konfox (not under Mozilla\) ---
    _patch_file(
        "browser/moz.configure",
        [
            (
                'imply_option("MOZ_APP_VENDOR", "Mozilla")',
                '# [Könfox] Own top-level %APPDATA%\\Konfox and %LOCALAPPDATA%\\Konfox profile folder.\n'
                'imply_option("MOZ_APP_VENDOR", "Konfox")\n'
                'imply_option("MOZ_APP_PROFILE", "Konfox")',
            ),
        ],
        marker='imply_option("MOZ_APP_PROFILE", "Konfox")',
    )

    _patch_file(
        "mozglue/misc/PreXULSkeletonUI.cpp",
        [
            (
                '  profileDbPath.append(\n'
                '      L"\\\\" MOZ_APP_VENDOR L"\\\\" MOZ_APP_BASENAME L"\\\\profiles.ini");',
                '  // [Könfox] Match MOZ_APP_PROFILE="Konfox" (%APPDATA%\\Konfox\\profiles.ini).\n'
                '  profileDbPath.append(L"\\\\" MOZ_APP_BASENAME L"\\\\profiles.ini");',
            ),
        ],
        marker='[Könfox] Match MOZ_APP_PROFILE="Konfox"',
    )

    _patch_file(
        "toolkit/crashreporter/crash_helper_server/src/logging/env.rs",
        [
            (
                'Some(home_dir.join("AppData").join("Roaming").join(config::MOZ_APP_VENDOR).join(config::MOZ_APP_BASENAME))',
                '/* [Könfox] Own top-level AppData\\Roaming\\Konfox folder */ '
                'Some(home_dir.join("AppData").join("Roaming").join(config::MOZ_APP_BASENAME))',
            ),
        ],
        marker="[Könfox] Own top-level AppData\\Roaming\\Konfox",
    )

    # --- 28c. Complete telemetry & LateWriteChecks removal ---
    _patch_file(
        "xpcom/build/LateWriteChecks.cpp",
        [
            (
                "void InitLateWriteChecks() {\n",
                "void InitLateWriteChecks() {\n"
                "  // [Könfox] Telemetry disabled: never write Telemetry.LateWriteFinal-* files.\n"
                "  return;\n",
            ),
            (
                "void BeginLateWriteChecks() {\n",
                "void BeginLateWriteChecks() {\n"
                "  // [Könfox] Telemetry disabled: never register late-write IO interposer.\n"
                "  return;\n",
            ),
        ],
        marker="[Könfox] Telemetry disabled: never write Telemetry.LateWriteFinal",
    )

    _patch_file(
        "toolkit/components/telemetry/core/Telemetry.cpp",
        [
            (
                "NS_IMETHODIMP\n"
                "TelemetryImpl::SetCanRecordBase(bool canRecord) {\n",
                "NS_IMETHODIMP\n"
                "TelemetryImpl::SetCanRecordBase(bool canRecord) {\n"
                "  // [Könfox] Telemetry completely disabled.\n"
                "  (void)canRecord;\n"
                "  return NS_OK;\n",
            ),
            (
                "NS_IMETHODIMP\n"
                "TelemetryImpl::SetCanRecordExtended(bool canRecord) {\n",
                "NS_IMETHODIMP\n"
                "TelemetryImpl::SetCanRecordExtended(bool canRecord) {\n"
                "  // [Könfox] Telemetry completely disabled.\n"
                "  (void)canRecord;\n"
                "  return NS_OK;\n",
            ),
        ],
        marker="[Könfox] Telemetry completely disabled.",
    )

    _patch_file(
        "toolkit/components/glean/xpcom/FOG.cpp",
        [
            (
                "void FOG::Shutdown() {\n"
                "  MOZ_ASSERT(XRE_IsParentProcess());\n"
                "\n"
                "  if (mIsShutdown) {\n"
                "    return;\n"
                "  }\n"
                "\n"
                "  UnregisterWeakMemoryReporter(this);\n"
                "  glean::impl::fog_shutdown();\n"
                "}",
                "static bool sKonfoxFogSkipped = false;\n"
                "\n"
                "void FOG::Shutdown() {\n"
                "  MOZ_ASSERT(XRE_IsParentProcess());\n"
                "\n"
                "  if (mIsShutdown) {\n"
                "    return;\n"
                "  }\n"
                "  mIsShutdown = true;\n"
                "  UnregisterWeakMemoryReporter(this);\n"
                "  if (sKonfoxFogSkipped) {\n"
                "    // [Könfox] Telemetry/Glean disabled: FOG was never initialized.\n"
                "    return;\n"
                "  }\n"
                "  glean::impl::fog_shutdown();\n"
                "}",
            ),
            (
                "NS_IMETHODIMP\n"
                "FOG::InitializeFOG(const nsACString& aDataPathOverride,\n"
                "                   const nsACString& aAppIdOverride,\n"
                "                   const bool aDisableInternalPings) {\n"
                "  MOZ_ASSERT(XRE_IsParentProcess());\n"
                "  gInitializeCalled = true;\n",
                "NS_IMETHODIMP\n"
                "FOG::InitializeFOG(const nsACString& aDataPathOverride,\n"
                "                   const nsACString& aAppIdOverride,\n"
                "                   const bool aDisableInternalPings) {\n"
                "  MOZ_ASSERT(XRE_IsParentProcess());\n"
                "  gInitializeCalled = true;\n"
                "  if (!Preferences::GetBool(\"datareporting.healthreport.uploadEnabled\", false)) {\n"
                "    // [Könfox] Telemetry/Glean disabled: skip fog_init & datareporting/glean dir.\n"
                "    sKonfoxFogSkipped = true;\n"
                "    return NS_OK;\n"
                "  }\n",
            ),
        ],
        marker="[Könfox] Telemetry/Glean disabled:",
    )

    return touched


def patch_bootstrapped_windows_rs(windows_rs_dir: Path, dry_run: bool) -> list[str]:
    """
    Belt-and-suspenders patch for Mozilla's bootstrapped `~/.mozbuild/windows-rs`
    crate (`windows 0.62.2`, compiled via `build/rust/windows/src/lib.rs`).
    Rewrites `combase.dll` raw-dylib links for Win7-native COM functions
    (`CoCreateFreeThreadedMarshaler`, `CoTaskMemAlloc`, `CoTaskMemFree`) to
    `ole32.dll` directly in the bootstrapped source tree.
    """
    touched: list[str] = []
    if not windows_rs_dir.is_dir():
        return touched

    com_mod = windows_rs_dir / "src/Windows/Win32/System/Com/mod.rs"
    if com_mod.is_file():
        orig = com_mod.read_text(encoding="utf-8", errors="replace")
        patched = orig
        for sym in ("CoCreateFreeThreadedMarshaler", "CoTaskMemAlloc", "CoTaskMemFree"):
            patched = patched.replace(
                f'windows_core::link!("combase.dll" "system" fn {sym}(',
                f'windows_core::link!("ole32.dll" "system" fn {sym}(',
            )
            patched = patched.replace(
                f'windows_link::link!("combase.dll" "system" fn {sym}(',
                f'windows_link::link!("ole32.dll" "system" fn {sym}(',
            )
        if patched != orig:
            if not dry_run:
                com_mod.write_text(patched, encoding="utf-8")
            touched.append(str(com_mod))
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
    parser.add_argument(
        "--patch-windows-rs",
        type=Path,
        default=None,
        help="Only patch Mozilla's bootstrapped ~/.mozbuild/windows-rs directory and exit",
    )
    parser.add_argument("--dry-run", action="store_true", help="Check only; do not write files")
    args = parser.parse_args()

    if args.patch_windows_rs is not None:
        touched = patch_bootstrapped_windows_rs(args.patch_windows_rs, args.dry_run)
        if touched:
            print(f"[konfox-patches] Bootstrapped windows-rs combase->ole32: {len(touched)} change(s)")
            for item in touched:
                print(f"  - {item}")
        else:
            print("[konfox-patches] Bootstrapped windows-rs combase->ole32: up to date / no changes needed")
        return 0

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
        ("IPC (MSCOM/ShMem) & Neqo HTTP/3 Win7 fixes", lambda: patch_ipc_and_networking_win7(args.firefox_dir, args.dry_run)),
        ("Win7 SVG titlebar caption icons (min/max/restore/close)", lambda: patch_win7_titlebar_icons(args.firefox_dir, args.dry_run)),
        ("Remove all AI / ML / GenAI features & AI Controls UI", lambda: patch_remove_ai_features(args.firefox_dir, args.dry_run)),
        ("Own AppData\\Konfox dir, Win7 launcher guard & complete telemetry removal", lambda: patch_konfox_profile_launcher_and_telemetry(args.firefox_dir, args.dry_run)),
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
