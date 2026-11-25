#!/usr/bin/env python3
"""
verify_win7_pe.py — Zero-dependency PE32/PE32+ Import Auditor for Windows 7 SP1 x64.

Scans every compiled .exe and .dll produced by the Linux cross-build and inspects
its static Import Directory (and optionally Delay-Load Imports) to detect ANY
Windows 8 / 8.1 / 10 / 11-only DLLs or API functions BEFORE you ever copy the
build to a Windows 7 machine.

Usage:
  python3 scripts/verify_win7_pe.py /path/to/objdir/dist/konfox
  python3 scripts/verify_win7_pe.py --include-delayload /path/to/konfox.exe
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

# DLLs that do NOT exist on Windows 7 SP1 x64 (static import = instant startup crash)
FORBIDDEN_DLLS_WIN7: dict[str, str] = {
    "api-ms-win-core-synch-l1-2-0.dll": "Win8+ (WaitOnAddress / WakeByAddress*)",
    "api-ms-win-core-winrt-l1-1-0.dll": "Win8+ WinRT runtime",
    "api-ms-win-core-winrt-string-l1-1-0.dll": "Win8+ WinRT HSTRING",
    "api-ms-win-shcore-scaling-l1-1-1.dll": "Win8.1+ per-monitor DPI scaling",
    "bcryptprimitives.dll": "ProcessPrng export is Win10+ only",
    "dcomp.dll": "Win8+ DirectComposition (must be delay-loaded/dynamic)",
    "d3d12.dll": "Win10+ Direct3D 12 (must be delay-loaded/dynamic)",
    "shcore.dll": "Win8.1+ Shell Core (must be delay-loaded/dynamic)",
    "twinapi.appcore.dll": "Win8+ AppCore",
    "windows.storage.dll": "Win10+ Storage",
    "icu.dll": "Win10 1903+ system ICU",
    "microsoft.ui.windowing.dll": "Win11+ Windows App SDK",
}

# Specific Win8/Win8.1/Win10/Win11-only functions inside DLLs that DO exist on Win7
FORBIDDEN_APIS_WIN7: dict[str, dict[str, str]] = {
    "kernel32.dll": {
        "GetSystemTimePreciseAsFileTime": "Win8+ (fallback: GetSystemTimeAsFileTime)",
        "GetTempPath2W": "Win10 20348+ (fallback: GetTempPathW)",
        "GetTempPath2A": "Win10 20348+ (fallback: GetTempPathA)",
        "SetThreadDescription": "Win10 1607+ (must be GetProcAddress)",
        "GetThreadDescription": "Win10 1607+ (must be GetProcAddress)",
        "SetProcessMitigationPolicy": "Win8+ (must be GetProcAddress)",
        "GetProcessMitigationPolicy": "Win8+ (must be GetProcAddress)",
        "DiscardVirtualMemory": "Win8.1+ (must be GetProcAddress)",
        "OfferVirtualMemory": "Win8.1+ (must be GetProcAddress)",
        "ReclaimVirtualMemory": "Win8.1+ (must be GetProcAddress)",
        "PrefetchVirtualMemory": "Win8+ (must be GetProcAddress)",
        "VirtualAlloc2": "Win10 1803+ (must be GetProcAddress)",
        "VirtualAllocFromApp": "Win8+ (must be GetProcAddress)",
        "MapViewOfFile3": "Win10 1803+ (must be GetProcAddress)",
        "WaitOnAddress": "Win8+ (use Rust win7 compat / NtKeyedEvent)",
        "WakeByAddressSingle": "Win8+ (use Rust win7 compat / NtKeyedEvent)",
        "WakeByAddressAll": "Win8+ (use Rust win7 compat / NtKeyedEvent)",
        "GetCurrentThreadStackLimits": "Win8+ (must be GetProcAddress)",
        "SetDefaultDllDirectories": "Win7 only with KB2533623 (prefer GetProcAddress)",
        "AddDllDirectory": "Win7 only with KB2533623 (prefer GetProcAddress)",
        "CreateFile2": "Win8+ (fallback: CreateFileW)",
        "GetSystemCpuSetInformation": "Win10+ (must be GetProcAddress)",
        "SetThreadSelectedCpuSets": "Win10+ (must be GetProcAddress)",
        "SetThreadInformation": "Win8+ (must be GetProcAddress)",
        "SetProcessInformation": "Win8+ (must be GetProcAddress)",
        "CompareObjectHandles": "Win10+ (must be GetProcAddress)",
        "QueryUnbiasedInterruptTimePrecise": "Win10+ (fallback: QueryUnbiasedInterruptTime)",
    },
    "kernelbase.dll": {
        "WaitOnAddress": "Win8+",
        "WakeByAddressSingle": "Win8+",
        "WakeByAddressAll": "Win8+",
        "VirtualAlloc2": "Win10 1803+",
        "MapViewOfFile3": "Win10 1803+",
        "SetThreadDescription": "Win10 1607+",
        "GetTempPath2W": "Win10 20348+",
        "PathCchCanonicalizeEx": "Win8+",
    },
    "user32.dll": {
        "GetDpiForWindow": "Win10 1607+ (must be GetProcAddress)",
        "GetDpiForSystem": "Win10 1607+ (must be GetProcAddress)",
        "GetSystemMetricsForDpi": "Win10 1607+ (must be GetProcAddress)",
        "AdjustWindowRectExForDpi": "Win10 1607+ (must be GetProcAddress)",
        "SetProcessDpiAwarenessContext": "Win10 1703+ (must be GetProcAddress)",
        "EnableNonClientDpiScaling": "Win10 1607+ (must be GetProcAddress)",
        "GetPointerInfo": "Win8+ (must be GetProcAddress)",
        "GetPointerType": "Win8+ (must be GetProcAddress)",
        "GetPointerTouchInfo": "Win8+ (must be GetProcAddress)",
        "GetPointerPenInfo": "Win8+ (must be GetProcAddress)",
        "RegisterPointerInputTarget": "Win8+ (must be GetProcAddress)",
        "AreDpiAwarenessContextsEqual": "Win10 1607+ (must be GetProcAddress)",
    },
    "cfgmgr32.dll": {
        "CM_Register_Notification": "Win8+ (must be GetProcAddress)",
        "CM_Unregister_Notification": "Win8+ (must be GetProcAddress)",
    },
    "advapi32.dll": {
        "EventSetInformation": "Win8+ (must be GetProcAddress)",
    },
    "ntdll.dll": {
        "RtlGetVersion": "OK on Win7 (allowed)",  # explicitly NOT forbidden; removed below
    },
    "dxgi.dll": {
        "CreateDXGIFactory2": "Win8.1+ (must be GetProcAddress)",
    },
    "dwmapi.dll": {
        "DwmGetWindowAttribute": "OK on Win7 (allowed)",
    },
}

# Remove informational-only "OK" markers so FORBIDDEN_APIS_WIN7 only contains actual violations
for _dll in list(FORBIDDEN_APIS_WIN7):
    FORBIDDEN_APIS_WIN7[_dll] = {
        fn: reason
        for fn, reason in FORBIDDEN_APIS_WIN7[_dll].items()
        if not reason.startswith("OK ")
    }
    if not FORBIDDEN_APIS_WIN7[_dll]:
        del FORBIDDEN_APIS_WIN7[_dll]


@dataclass
class Section:
    virtual_address: int
    virtual_size: int
    raw_ptr: int
    raw_size: int


def rva_to_offset(rva: int, sections: list[Section]) -> int | None:
    for s in sections:
        span = max(s.virtual_size, s.raw_size)
        if s.virtual_address <= rva < s.virtual_address + span:
            offset = s.raw_ptr + (rva - s.virtual_address)
            return offset
    return None


def read_cstr(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("ascii", errors="replace")


def parse_pe_imports(pe_path: Path, include_delayload: bool = False) -> tuple[list[tuple[str, list[str]]], list[tuple[str, list[str]]]]:
    """
    Pure-Python PE32 / PE32+ static and delay-load import parser.
    Returns (static_imports, delay_imports) as lists of (dll_name, [func_names...]).
    """
    data = pe_path.read_bytes()
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError(f"{pe_path} is not a PE binary (missing MZ header)")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError(f"{pe_path} is missing PE signature")

    _, num_sections, _, _, _, opt_header_size, _ = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4
    )
    opt_start = pe_offset + 24
    magic = struct.unpack_from("<H", data, opt_start)[0]
    if magic == 0x20B:  # PE32+ (x64)
        is_pe64 = True
        dd_offset = opt_start + 112
        num_rva_sizes = struct.unpack_from("<I", data, opt_start + 108)[0]
    elif magic == 0x10B:  # PE32 (x86)
        is_pe64 = False
        dd_offset = opt_start + 96
        num_rva_sizes = struct.unpack_from("<I", data, opt_start + 92)[0]
    else:
        raise ValueError(f"{pe_path}: unknown PE optional header magic 0x{magic:x}")

    sec_start = opt_start + opt_header_size
    sections: list[Section] = []
    for i in range(num_sections):
        off = sec_start + i * 40
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append(Section(vaddr, vsize, rptr, rsize))

    def read_thunk_names(thunk_rva: int) -> list[str]:
        names: list[str] = []
        off = rva_to_offset(thunk_rva, sections)
        if off is None:
            return names
        entry_size = 8 if is_pe64 else 4
        ord_flag = (1 << 63) if is_pe64 else (1 << 31)
        fmt = "<Q" if is_pe64 else "<I"
        while off + entry_size <= len(data):
            val = struct.unpack_from(fmt, data, off)[0]
            if val == 0:
                break
            if val & ord_flag:
                names.append(f"ordinal#{val & 0xFFFF}")
            else:
                name_off = rva_to_offset(val & 0x7FFFFFFF, sections)
                if name_off is not None and name_off + 2 < len(data):
                    names.append(read_cstr(data, name_off + 2))
            off += entry_size
        return names

    # Directory index 1 = Static Import Table
    static_imports: list[tuple[str, list[str]]] = []
    if num_rva_sizes > 1:
        imp_rva, _ = struct.unpack_from("<II", data, dd_offset + 1 * 8)
        if imp_rva:
            off = rva_to_offset(imp_rva, sections)
            while off is not None and off + 20 <= len(data):
                ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from("<IIIII", data, off)
                if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                    break
                name_off = rva_to_offset(name_rva, sections)
                dll_name = read_cstr(data, name_off) if name_off is not None else "<unknown>"
                thunk_rva = ilt_rva if ilt_rva else iat_rva
                funcs = read_thunk_names(thunk_rva)
                static_imports.append((dll_name, funcs))
                off += 20

    # Directory index 13 = Delay-Load Import Table
    delay_imports: list[tuple[str, list[str]]] = []
    if include_delayload and num_rva_sizes > 13:
        dimp_rva, _ = struct.unpack_from("<II", data, dd_offset + 13 * 8)
        if dimp_rva:
            off = rva_to_offset(dimp_rva, sections)
            while off is not None and off + 32 <= len(data):
                attrs, name_rva, _, _, int_rva, _, _, _ = struct.unpack_from(
                    "<IIIIIIII", data, off
                )
                if attrs == 0 and name_rva == 0 and int_rva == 0:
                    break
                # Only RVA-based delay descriptors (attrs & 1)
                if attrs & 1:
                    name_off = rva_to_offset(name_rva, sections)
                    dll_name = read_cstr(data, name_off) if name_off is not None else "<unknown>"
                    funcs = read_thunk_names(int_rva)
                    delay_imports.append((dll_name, funcs))
                off += 32

    return static_imports, delay_imports


def audit_pe_file(pe_path: Path, include_delayload: bool = False) -> list[str]:
    static_imports, delay_imports = parse_pe_imports(pe_path, include_delayload)
    findings: list[str] = []

    def check_table(table: list[tuple[str, list[str]]], kind: str) -> None:
        for dll, funcs in table:
            dll_lower = dll.lower()
            if dll_lower in FORBIDDEN_DLLS_WIN7:
                findings.append(
                    f"[{kind}] {pe_path.name}: imports forbidden DLL `{dll}` "
                    f"({FORBIDDEN_DLLS_WIN7[dll_lower]}) -> {funcs[:5]}"
                )
            elif dll_lower.startswith("ext-ms-win-"):
                findings.append(
                    f"[{kind}] {pe_path.name}: imports Win8+/10+ ext-ms API set `{dll}` -> {funcs[:5]}"
                )

            bad_map = FORBIDDEN_APIS_WIN7.get(dll_lower, {})
            for fn in funcs:
                if fn in bad_map:
                    findings.append(
                        f"[{kind}] {pe_path.name}: imports `{dll}!{fn}` ({bad_map[fn]})"
                    )

    check_table(static_imports, "STATIC")
    if include_delayload:
        check_table(delay_imports, "DELAY")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Windows 7 SP1 x64 binary import compatibility for PE (.exe/.dll) files."
    )
    parser.add_argument("target", type=Path, help="PE file or directory (e.g. objdir/dist/konfox)")
    parser.add_argument(
        "--include-delayload",
        action="store_true",
        help="Also report delay-loaded Win8+/10+ DLLs/APIs (usually safe if guarded at runtime)",
    )
    args = parser.parse_args()

    if args.target.is_file():
        pe_files = [args.target]
    elif args.target.is_dir():
        pe_files = sorted(
            p for p in args.target.rglob("*") if p.suffix.lower() in (".exe", ".dll")
        )
    else:
        print(f"[verify-win7] Path not found: {args.target}", file=sys.stderr)
        return 2

    if not pe_files:
        print(f"[verify-win7] No .exe or .dll files found under {args.target}", file=sys.stderr)
        return 2

    all_findings: list[str] = []
    scanned = 0
    for pe in pe_files:
        try:
            findings = audit_pe_file(pe, include_delayload=args.include_delayload)
        except ValueError as exc:
            print(f"[verify-win7] skipping {pe.name}: {exc}", file=sys.stderr)
            continue
        scanned += 1
        all_findings.extend(findings)

    print(f"[verify-win7] Scanned {scanned} PE binary/binaries under {args.target}")
    if all_findings:
        print(f"[verify-win7] FAIL: Found {len(all_findings)} Windows 7 compatibility issue(s):")
        for item in all_findings:
            print(f"  ! {item}")
        print(
            "\nTip: Search the Firefox tree for the offending symbol with:\n"
            "  rg '<FunctionName>' <firefox-src-dir>"
        )
        return 1

    print("[verify-win7] PASS: Zero forbidden Win8+/Win10+ static imports detected!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
