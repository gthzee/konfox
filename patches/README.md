# Könfox Patch Queue (`patches/`)

Könfox separates Windows 7 SP1 x64 compatibility into two clean layers:

1. **Automated structural transforms (`scripts/apply_win7_patches.py`)**
   - Relaxes NSIS installer checks (`AtLeastWin10` → `AtLeastWin7`, `MinSupportedVer` → `Windows 7 SP1 x64`).
   - Restores `IsWin7SP1OrLater()`, `IsWin8OrLater()`, `IsWin8Point1OrLater()`, and `IsWin10OrLater()` in `mfbt/WindowsVersion.h`.
   - Converts static Win8+ `CM_Register_Notification` / `CM_Unregister_Notification` calls in `dom/webserial/Win32SerialPlatformService.cpp` to dynamic `LoadLibraryW` / `GetProcAddress`.
   - Scans `third_party/rust/` for vendored Win10+ APIs and provides `.cargo-checksum.json` auto-hashing.

2. **Ordered `.patch` files (`patches/series`)**
   - Because Firefox Nightly moves daily, Mozilla occasionally introduces a new Win8+/Win10+ API call or UI/DirectComposition regression.
   - After `./mach build`, `scripts/verify_win7_pe.py` scans every `.exe` and `.dll` on Linux before you copy anything to Windows 7.
   - If it flags a new static import (e.g., `kernel32.dll!SomeWin10Api`):
     1. Find it in the Firefox checkout: `rg SomeWin10Api work/firefox`
     2. Replace the static call with `GetProcAddress` + a safe fallback.
     3. Export the diff: `git -C work/firefox diff > patches/0001-fix-some-win10-api.patch`
     4. Add `0001-fix-some-win10-api.patch` to `patches/series`.
