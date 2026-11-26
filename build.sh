#!/usr/bin/env bash
# =============================================================================
# Könfox Nightly — Linux -> Windows 7 SP1 x64 Cross-Compilation Orchestrator
# =============================================================================
# Usage:
#   ./build.sh [options] [stage]
#
# Options:
#   --profile fast|release    Build profile (default: fast; release enables cross-LTO)
#   --rust-version X.Y.Z      Override Rust version (default: auto-detected from Nightly)
#   --rust-dist DIR           Use/install patched Rust toolchain at DIR
#   --firefox-ref REF         Git ref/branch/commit in mozilla-firefox/firefox (default: main)
#   --work-dir DIR            Working directory for checkouts & objdir (default: ./work)
#   --skip-rust               Reuse already-built patched Rust in --rust-dist
#   --low-disk                Prune downloaded .tar.zst toolchain archives to save disk space
#
# Stages (default: all):
#   check | fetch | patch | bootstrap | rust | build | package | verify | all
# =============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="fast"
RUST_VERSION=""
RUST_DIST_DIR=""
FIREFOX_REF="main"
WORK_DIR="${ROOT_DIR}/work"
OUT_DIR="${ROOT_DIR}/out"
SKIP_RUST=0
LOW_DISK=0
STAGE="all"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)      PROFILE="$2"; shift 2 ;;
        --rust-version) RUST_VERSION="$2"; shift 2 ;;
        --rust-dist)    RUST_DIST_DIR="$2"; shift 2 ;;
        --firefox-ref)  FIREFOX_REF="$2"; shift 2 ;;
        --work-dir)     WORK_DIR="$2"; shift 2 ;;
        --skip-rust)    SKIP_RUST=1; shift ;;
        --low-disk)     LOW_DISK=1; shift ;;
        -h|--help)
            sed -n '2,22p' "$0"
            exit 0
            ;;
        *)
            STAGE="$1"
            shift
            ;;
    esac
done

FIREFOX_DIR="${WORK_DIR}/firefox"
RUST_SRC_DIR="${WORK_DIR}/rust-src"
[[ -n "$RUST_DIST_DIR" ]] || RUST_DIST_DIR="${WORK_DIR}/rust-win7-toolchain"
MOZBUILD_DIR="${MOZBUILD_STATE_PATH:-${HOME}/.mozbuild}"
export MOZBUILD_STATE_PATH="$MOZBUILD_DIR"

if [[ "$PROFILE" == "release" ]]; then
    MOZCONFIG_FILE="${ROOT_DIR}/mozconfigs/konfox-nightly-win64.mozconfig"
    OBJDIR="${WORK_DIR}/obj-konfox-win64-release"
else
    MOZCONFIG_FILE="${ROOT_DIR}/mozconfigs/konfox-fast-win64.mozconfig"
    OBJDIR="${WORK_DIR}/obj-konfox-win64-fast"
fi

log() { printf '\n\033[1;36m[konfox]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[konfox:warn]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[konfox:error]\033[0m %s\n' "$*" >&2; exit 1; }

stage_check() {
    log "Checking Linux host requirements..."
    [[ "$(uname -s)" == "Linux" ]] || die "build.sh is designed for a Linux x86_64 cross-compile host."
    [[ "$(uname -m)" == "x86_64" ]] || die "Expected x86_64 Linux host."

    local missing=()
    for cmd in git python3 curl msiextract cmake ninja zip tar xz makensis 7z; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing host tools: ${missing[*]}. On Debian/Ubuntu run:
  sudo apt update && sudo apt install -y git python3 python3-pip curl msitools cmake ninja-build nsis p7zip-full zip xz-utils zstd build-essential pkg-config librsvg2-bin imagemagick libc6-i386 lib32gcc-s1 lib32stdc++6 lib32atomic1 lib32z1"
    fi

    if [[ ! -e /lib/ld-linux.so.2 ]]; then
        die "Missing 32-bit loader /lib/ld-linux.so.2 (required by Mozilla's bootstrapped Wine for midl.exe).
  On Debian/Ubuntu run: sudo apt install -y libc6-i386 lib32gcc-s1 lib32stdc++6 lib32atomic1 lib32z1"
    fi

    local ram_gb avail_gb
    ram_gb=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
    avail_gb=$(df -BG --output=avail "$ROOT_DIR" | tail -n1 | tr -dc '0-9')
    log "Host detected: $(nproc) CPU cores, ${ram_gb} GiB RAM, ${avail_gb} GiB free disk"
    if [[ "$ram_gb" -lt 14 ]]; then
        warn "RAM is ${ram_gb} GiB (< 16 GiB). Linking xul.dll may OOM unless you add swap (e.g. 16–24 GiB swapfile)."
    fi
    if [[ "$avail_gb" -lt 45 ]]; then
        warn "Free disk is ${avail_gb} GiB (< 45 GiB). Full Firefox Nightly cross-build typically needs 45–65 GiB."
    fi
}

stage_fetch() {
    mkdir -p "$WORK_DIR" "$OUT_DIR"
    if [[ ! -d "$FIREFOX_DIR/.git" ]]; then
        log "Cloning Mozilla Firefox Nightly (${FIREFOX_REF})..."
        git clone --depth 1 --branch "$FIREFOX_REF" https://github.com/mozilla-firefox/firefox.git "$FIREFOX_DIR"
    else
        log "Updating existing Firefox checkout in ${FIREFOX_DIR}..."
        git -C "$FIREFOX_DIR" fetch --depth 1 origin "$FIREFOX_REF"
        git -C "$FIREFOX_DIR" checkout -f FETCH_HEAD
    fi

    if [[ -z "$RUST_VERSION" ]]; then
        if [[ -f "$FIREFOX_DIR/docs/writing-rust-code/update-policy.md" ]]; then
            RUST_VERSION=$(python3 - "$FIREFOX_DIR/docs/writing-rust-code/update-policy.md" <<'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(encoding="utf-8")
versions = re.findall(r"\|\s*Firefox\s+\d+\s*\|\s*Rust\s+([0-9]+\.[0-9]+\.[0-9]+)", text)
print(versions[-1] if versions else "1.100.0")
PY
            )
        else
            RUST_VERSION="1.100.0"
        fi
        log "Auto-detected Rust version: ${RUST_VERSION} (override with --rust-version)"
    fi
}

stage_patch() {
    log "Installing Könfox Nightly branding..."
    python3 "${ROOT_DIR}/scripts/apply_branding.py" "$FIREFOX_DIR"

    log "Applying Könfox Windows 7 SP1 x64 patches..."
    python3 "${ROOT_DIR}/scripts/apply_win7_patches.py" "$FIREFOX_DIR"
}

stage_bootstrap() {
    log "Bootstrapping Mozilla Linux->Windows cross-compile toolchains (clang-cl, lld-link, node, nasm, cbindgen)..."
    mkdir -p "$WORK_DIR" "$MOZBUILD_DIR"
    pushd "$FIREFOX_DIR" >/dev/null
    MOZCONFIG="$MOZCONFIG_FILE" ./mach --no-interactive bootstrap \
        --application-choice=browser \
        --no-system-changes || warn "mach bootstrap reported non-fatal warning; continuing to configure..."
    popd >/dev/null

    if [[ -d "${MOZBUILD_DIR}/vs" ]]; then
        log "Ensuring Windows 7-compatible MSVC 14.44 toolset & CRT redist in ${MOZBUILD_DIR}/vs..."
        python3 "${ROOT_DIR}/scripts/install_msvc1444_win7.py" "${MOZBUILD_DIR}/vs"
    fi

    if [[ "$LOW_DISK" -eq 1 ]]; then
        log "Pruning cached .tar.zst archives in ${MOZBUILD_DIR}/toolchains to save disk space..."
        rm -rf "${MOZBUILD_DIR}/toolchains" "${MOZBUILD_DIR}/clang-tools"
    fi
}

stage_rust() {
    if [[ "$SKIP_RUST" -eq 1 && -x "${RUST_DIST_DIR}/bin/rustc" ]]; then
        log "Reusing existing Win7-patched Rust toolchain at ${RUST_DIST_DIR}"
        return 0
    fi

    [[ -n "$RUST_VERSION" ]] || RUST_VERSION="1.100.0"
    log "Building Win7-patched Rust ${RUST_VERSION} x86_64-pc-windows-msvc stdlib (fast stage-0 local-rebuild)..."

    # Ensure official rustup toolchain for $RUST_VERSION is installed
    command -v rustup >/dev/null 2>&1 || die "rustup not found (install via https://rustup.rs)"
    rustup toolchain install "${RUST_VERSION}" --profile minimal
    local rustc_bin cargo_bin official_sysroot
    rustc_bin="$(rustup which --toolchain "${RUST_VERSION}" rustc)"
    cargo_bin="$(rustup which --toolchain "${RUST_VERSION}" cargo)"
    official_sysroot="$("${rustc_bin}" --print sysroot)"

    # Download official source tarball (no .git -> avoids HEAD^1 bootstrap panic, includes vendored crates)
    rm -rf "$RUST_SRC_DIR"
    mkdir -p "$WORK_DIR"
    curl -fsSL "https://static.rust-lang.org/dist/rustc-${RUST_VERSION}-src.tar.xz" | tar -xJ -C "$WORK_DIR"
    mv "${WORK_DIR}/rustc-${RUST_VERSION}-src" "$RUST_SRC_DIR"

    log "Applying version-agnostic Win7 stdlib patches to Rust ${RUST_VERSION}..."
    python3 "${ROOT_DIR}/scripts/patch_rust_win7.py" --strict "$RUST_SRC_DIR"

    # Build wrapper scripts pointing clang --driver-mode=cl & lld-link at bootstrapped VS sysroot
    local vs_dir="${MOZBUILD_DIR}/vs"
    local clang_bin="${MOZBUILD_DIR}/clang/bin"
    local clang_exe="clang"
    local ar_exe="llvm-lib"
    local lld_exe="lld-link"
    [[ -x "${clang_bin}/clang" ]] && clang_exe="${clang_bin}/clang"
    [[ -x "${clang_bin}/llvm-lib" ]] && ar_exe="${clang_bin}/llvm-lib"
    [[ -x "${clang_bin}/lld-link" ]] && lld_exe="${clang_bin}/lld-link"

    local vc_inc ucrt_inc um_inc shared_inc vc_lib ucrt_lib um_lib
    vc_inc=$(find "$vs_dir" -type d -path "*/VC/Tools/MSVC/*/include" | head -n1 || true)
    ucrt_inc=$(find "$vs_dir" -type d -path "*/Windows Kits/10/Include/*/ucrt" | head -n1 || true)
    um_inc=$(find "$vs_dir" -type d -path "*/Windows Kits/10/Include/*/um" | head -n1 || true)
    shared_inc=$(find "$vs_dir" -type d -path "*/Windows Kits/10/Include/*/shared" | head -n1 || true)
    vc_lib=$(find "$vs_dir" -type d -path "*/VC/Tools/MSVC/*/lib/x64" | head -n1 || true)
    ucrt_lib=$(find "$vs_dir" -type d -path "*/Windows Kits/10/Lib/*/ucrt/x64" | head -n1 || true)
    um_lib=$(find "$vs_dir" -type d -path "*/Windows Kits/10/Lib/*/um/x64" | head -n1 || true)
    [[ -n "$vc_lib" && -n "$ucrt_lib" && -n "$um_lib" ]] || die "Windows SDK not found in ${vs_dir}; run ./mach configure or install xwin."

    local wrap_dir="${WORK_DIR}/rust-win7-wrappers"
    mkdir -p "$wrap_dir"
    cat > "${wrap_dir}/clang-cl" <<WRAP
#!/usr/bin/env bash
exec "${clang_exe}" --driver-mode=cl --target=x86_64-pc-windows-msvc \\
  -Wno-unused-command-line-argument \\
  "/imsvc${vc_inc}" "/imsvc${ucrt_inc}" "/imsvc${um_inc}" "/imsvc${shared_inc}" "\$@"
WRAP
    cat > "${wrap_dir}/lld-link" <<WRAP
#!/usr/bin/env bash
if [[ "\${1:-}" == "-flavor" && "\${2:-}" == "link" ]]; then shift 2; fi
exec "${lld_exe}" \\
  "/libpath:${vc_lib}" "/libpath:${um_lib}" "/libpath:${ucrt_lib}" "\$@"
WRAP
    chmod +x "${wrap_dir}/clang-cl" "${wrap_dir}/lld-link"

    cat > "${RUST_SRC_DIR}/bootstrap.toml" <<EOF
change-id = "ignore"

[llvm]
download-ci-llvm = false

[build]
build = "x86_64-unknown-linux-gnu"
host = ["x86_64-unknown-linux-gnu"]
target = ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"]
rustc = "${rustc_bin}"
cargo = "${cargo_bin}"
local-rebuild = true
docs = false
submodules = false
locked-deps = true
vendor = true
extended = false

[rust]
channel = "stable"
deny-warnings = false
lld = false

[target.x86_64-pc-windows-msvc]
cc = "${wrap_dir}/clang-cl"
cxx = "${wrap_dir}/clang-cl"
ar = "${ar_exe}"
linker = "${wrap_dir}/lld-link"
EOF

    pushd "$RUST_SRC_DIR" >/dev/null
    CC_x86_64_pc_windows_msvc="${wrap_dir}/clang-cl" \
    CXX_x86_64_pc_windows_msvc="${wrap_dir}/clang-cl" \
    AR_x86_64_pc_windows_msvc="${ar_exe}" \
    python3 x.py dist --stage 0 rust-std --target x86_64-pc-windows-msvc --warnings=warn
    popd >/dev/null

    rm -rf "$RUST_DIST_DIR" "${WORK_DIR}/std-unpack"
    cp -a "$official_sysroot" "$RUST_DIST_DIR"
    mkdir -p "${WORK_DIR}/std-unpack"
    tar -xJf "${RUST_SRC_DIR}/build/dist/rust-std-${RUST_VERSION}-x86_64-pc-windows-msvc.tar.xz" -C "${WORK_DIR}/std-unpack"
    "${WORK_DIR}/std-unpack/rust-std-${RUST_VERSION}-x86_64-pc-windows-msvc/install.sh" \
        --prefix="$RUST_DIST_DIR" --disable-ldconfig

    [[ -x "${RUST_DIST_DIR}/bin/rustc" ]] || die "Patched rustc missing at ${RUST_DIST_DIR}/bin/rustc"
    log "Patched Rust ready: $("${RUST_DIST_DIR}/bin/rustc" --version)"

    if [[ "$LOW_DISK" -eq 1 ]]; then
        rm -rf "$RUST_SRC_DIR" "${WORK_DIR}/std-unpack"
    fi
}

export_build_env() {
    export MOZCONFIG="$MOZCONFIG_FILE"
    if [[ -x "${RUST_DIST_DIR}/bin/rustc" ]]; then
        export KONFOX_RUSTC="${RUST_DIST_DIR}/bin/rustc"
        export KONFOX_CARGO="${RUST_DIST_DIR}/bin/cargo"
        export PATH="${RUST_DIST_DIR}/bin:${PATH}"
    fi

    local vs_dir="${MOZBUILD_DIR}/vs"
    if [[ -d "$vs_dir" ]]; then
        KONFOX_UCRT_REDIST_DIR=$(find "$vs_dir" -type d -path "*/Windows Kits/10/Redist/*/ucrt/DLLs/x64" | head -n1 || true)
        export KONFOX_UCRT_REDIST_DIR
        [[ -n "$KONFOX_UCRT_REDIST_DIR" ]] && log "Bundling UCRT DLLs from: ${KONFOX_UCRT_REDIST_DIR}"
    fi
}

stage_build() {
    if [[ -d "${MOZBUILD_DIR}/vs" ]]; then
        log "Ensuring Windows 7-compatible MSVC 14.44 toolset & CRT redist in ${MOZBUILD_DIR}/vs..."
        python3 "${ROOT_DIR}/scripts/install_msvc1444_win7.py" "${MOZBUILD_DIR}/vs"
    fi

    export_build_env
    log "Configuring & cross-compiling Könfox Nightly (${PROFILE}) for Windows 7 SP1 x64..."
    pushd "$FIREFOX_DIR" >/dev/null
    local had_vs=0
    [[ -d "${MOZBUILD_DIR}/vs" ]] && had_vs=1

    ./mach configure

    # If --enable-bootstrap just downloaded ~/.mozbuild/vs on first configure,
    # swap VS 2026's Win10+-only MSVC 14.5x for Win7-clean MSVC 14.44 (VS 2022
    # 17.14 LTSC), pick up UCRT redist DLLs, and re-run fast configure.
    if [[ "$had_vs" -eq 0 && -d "${MOZBUILD_DIR}/vs" ]]; then
        log "Swapping bootstrapped VS 2026 MSVC 14.5x -> Win7-compatible MSVC 14.44..."
        python3 "${ROOT_DIR}/scripts/install_msvc1444_win7.py" "${MOZBUILD_DIR}/vs"
        export_build_env
        log "Re-configuring cleanly with MSVC 14.44 & bundled UCRT redist dir..."
        rm -rf "${OBJDIR}"
        ./mach configure
    fi

    if [[ "$LOW_DISK" -eq 1 ]]; then
        rm -rf "${MOZBUILD_DIR}/toolchains"
    fi

    ./mach build
    popd >/dev/null
}

stage_package() {
    export_build_env
    log "Packaging Könfox Nightly (.zip + Windows .installer.exe)..."
    pushd "$FIREFOX_DIR" >/dev/null
    # On WINNT with MOZ_PKG_FORMAT=ZIP, `./mach package` builds BOTH:
    #   1) dist/konfox-*.en-US.win64.zip
    #   2) dist/install/sea/konfox-*.en-US.win64.installer.exe (via browser/installer/windows)
    # Note: Do NOT call `installers-en-US` (that is an l10n repack target that rejects self-overwrite).
    ./mach package
    popd >/dev/null

    if ! find "${OBJDIR}/dist" -maxdepth 4 -name "*.installer.exe" | grep -q .; then
        warn "No .installer.exe found after ./mach package; invoking browser/installer/windows directly..."
        local zip_in
        zip_in=$(find "${OBJDIR}/dist" -maxdepth 2 -name "*.en-US.win64.zip" | head -n1 || true)
        [[ -n "$zip_in" ]] || die "Could not find built .en-US.win64.zip under ${OBJDIR}/dist"
        make -C "${OBJDIR}/browser/installer/windows" ZIP_IN="${zip_in}" installer
    fi

    mkdir -p "$OUT_DIR"
    find "${OBJDIR}/dist" -maxdepth 4 \
        \( -name "*.en-US.win64.zip" -o -name "*.installer.exe" \) \
        -exec cp -v {} "$OUT_DIR/" \;
    (cd "$OUT_DIR" && sha256sum *.zip *.exe 2>/dev/null > SHA256SUMS.txt || true)
    log "Packaged artifacts copied to: ${OUT_DIR}"
    ls -lh "$OUT_DIR"
}

stage_verify() {
    local dist_bin="${OBJDIR}/dist/konfox"
    [[ -d "$dist_bin" ]] || dist_bin="${OBJDIR}/dist/firefox"
    [[ -d "$dist_bin" ]] || dist_bin="${OBJDIR}/dist/bin"
    [[ -d "$dist_bin" ]] || die "Could not locate built distribution folder under ${OBJDIR}/dist"

    mkdir -p "$OUT_DIR"
    log "Auditing every built .exe and .dll for Windows 7 SP1 x64 import compatibility..."
    python3 "${ROOT_DIR}/scripts/verify_win7_pe.py" "$dist_bin" | tee "${OUT_DIR}/win7-pe-audit.txt"
}

case "$STAGE" in
    check)     stage_check ;;
    fetch)     stage_fetch ;;
    patch)     stage_patch ;;
    bootstrap) stage_bootstrap ;;
    rust)      stage_rust ;;
    build)     stage_build ;;
    package)   stage_package ;;
    verify)    stage_verify ;;
    all)
        stage_check
        stage_fetch
        stage_patch
        stage_bootstrap
        stage_rust
        stage_build
        stage_package
        stage_verify
        log "ALL DONE! Copy files from ${OUT_DIR} to your Windows 7 SP1 x64 machine to test."
        ;;
    *)
        die "Unknown stage: ${STAGE}"
        ;;
esac
