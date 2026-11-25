# Könfox Nightly (Firefox Nightly for Windows 7 SP1 x64)

**Könfox** is our clean, Linux-to-Windows cross-compilation build system for running modern **Mozilla Firefox Nightly** on **Windows 7 SP1 x64** — built as Nightly, branded as **Könfox Nightly**, with the Windows content sandbox **enabled**.

---

## How Könfox Differs from `e3kskoy7wqk/Firefox-for-windows-7`

| Area | `e3kskoy7wqk` approach | **Könfox ("our way")** |
| :--- | :--- | :--- |
| **Build Host** | Windows 11 + Visual Studio 2022 | **Linux x86_64 cross-compile** (`clang-cl` + `lld-link` + Mozilla Taskcluster VS sysroot) |
| **Target Scope** | Win7 + Vista + XP legacy + 32-bit (sandbox disabled on x86) | **Strictly Windows 7 SP1 x64** — no XP/Vista clutter, **sandbox stays enabled** |
| **Rust Win7 Support** | Static hand-maintained `Rust<ver>win7.diff` per Rust release | **Version-agnostic Python patcher** (`scripts/patch_rust_win7.py`) rewriting `target_vendor = "win7"` → `target_os = "windows"` (safe for both Linux host and Windows target!) |
| **Firefox Patches** | ~220 opaque `<hash>.diff` files + `.bat` script | **Clean surgical Python transforms + optional `patches/series`** |
| **Verification** | Boot & test on Windows 7 after each build | **Automated PE32+ Import Auditor (`scripts/verify_win7_pe.py`)** catches Win8+/Win10+ static imports on Linux *before* copying to Windows 7 |
| **Branding** | Stock/modified Firefox branding | **Native `browser/branding/konfox`** overlay built on top of live Nightly assets, with Mozilla auto-update disabled so Win7 isn't overwritten |

---

## Option A: Build for Free on GitHub Actions (Recommended — No Linux PC Needed)

GitHub provides **4 vCPU + 16 GB RAM** `ubuntu-24.04` runners for free on **public repositories**. The included `.github/workflows/build-konfox.yml` uses a 2-job pipeline designed specifically to fit inside free runners:

1. **Job 1 (`build-patched-rust`):** Auto-detects the Nightly Rust version, runs `scripts/patch_rust_win7.py`, cross-builds `rustc` + `cargo` + Win7-safe `x86_64-pc-windows-msvc` `std` (using `download-ci-llvm = true` + `xwin`), and **caches** the toolchain in GitHub Actions Cache so future builds skip Rust compilation completely.
2. **Job 2 (`build-konfox-installer`):** Frees ~40+ GB of runner SSD space, adds an 8 GB swapfile safety net, restores the cached patched Rust toolchain, applies Könfox Nightly branding (including rasterizing the SVG into Windows `.ico` files) + Win7 SP1 x64 patches (including `getrandom` → `windows7.rs`), cross-compiles with `--disable-debug-symbols` (low disk/RAM), runs `scripts/verify_win7_pe.py`, and uploads **`konfox-*.en-US.win64.installer.exe`**, **`konfox-*.en-US.win64.zip`**, `SHA256SUMS.txt`, and `win7-pe-audit.txt`.

### How to Run It on GitHub

1. Create a **public** GitHub repository (public repos get the 16 GB RAM runners for free) and push the `konfox/` folder to it.
2. Open the **Actions** tab → select **Build Könfox Nightly (Win7 SP1 x64)** → click **Run workflow** (check *create_release* if you also want a direct GitHub Releases page).
3. When it finishes, download **`konfox-nightly-win7-x64`** from Artifacts (or Releases) and run **`konfox-*.en-US.win64.installer.exe`** on your Windows 7 SP1 x64 machine.

---

## Option B: Build Locally on Linux / WSL2

Cross-compiling Mozilla Firefox Nightly + patched Rust locally requires:
- **OS:** Linux x86_64 (Ubuntu 22.04/24.04, Debian 12+, Arch, Fedora, or WSL2)
- **RAM:** **16 GB minimum** (32 GB recommended; add 16–24 GB swap if using 16 GB RAM, or 32+ GB for `--profile release` cross-LTO)
- **Disk:** **80 GB free** (Firefox checkout + Rust checkout + `~/.mozbuild` SDK + objdir)
- **Packages (Debian/Ubuntu):**
  ```bash
  sudo apt update && sudo apt install -y \
    git python3 python3-pip curl msitools cmake ninja-build \
    zip xz-utils build-essential pkg-config librsvg2-bin imagemagick
  ```

---

## Quick Start

1. **Run the built-in self-tests** (verifies the Rust patcher, Win7 patcher, branding overlay, and PE32+ auditor):
   ```bash
   python3 tests/test_konfox_toolchain.py
   ```

2. **Run a full fast-iteration Nightly build** (produces `out/konfox-*.en-US.win64.installer.exe` and `.zip`):
   ```bash
   chmod +x build.sh
   ./build.sh --profile fast all
   ```

3. **Run individual resumable stages** (useful when iterating on a new Nightly regression):
   ```bash
   ./build.sh check       # Verify Linux host tools, RAM, disk
   ./build.sh fetch       # Shallow-clone mozilla-firefox/firefox (main)
   ./build.sh bootstrap   # Fetch clang-cl, lld-link, VS/Windows SDK sysroot
   ./build.sh rust        # Build Linux-hosted rustc + Win7-safe x86_64-pc-windows-msvc std
   ./build.sh patch       # Apply Könfox Nightly branding + Win7 SP1 x64 patches
   ./build.sh build       # Cross-compile Könfox Nightly
   ./build.sh package     # Build .zip + Windows .installer.exe into out/
   ./build.sh verify      # Run PE32+ import audit on every .exe and .dll
   ```

4. **Production Release Build (with cross-language LTO):**
   ```bash
   ./build.sh --profile release --skip-rust all
   ```

---

## Testing on Real Windows 7 SP1 x64

1. Copy `out/konfox-*.en-US.win64.zip` (portable) or `out/konfox-*.en-US.win64.installer.exe` to your Windows 7 SP1 x64 machine.
2. Verify `about:support`:
   - Application Name: **Könfox Nightly**
   - Update Channel: **nightly**
   - Sandbox Content Process Level: **> 0 (Enabled)**
3. If a future Nightly introduces a new Win10+ API call:
   - `scripts/verify_win7_pe.py` will flag the exact DLL & function name right on Linux.
   - Add a minimal patch in `patches/` and register it in `patches/series`.
