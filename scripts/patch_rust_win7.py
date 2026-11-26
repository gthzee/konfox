#!/usr/bin/env python3
"""
patch_rust_win7.py — Version-agnostic Rust stdlib Windows 7 SP1 patcher.

Why this exists ("Könfox way"):
  Instead of hand-maintaining fragile line-numbered .diff files for every
  new Rust release (1.95, 1.100, ...), this script rewrites Rust's own
  built-in `target_vendor = "win7"` conditional compilation guards inside
  `library/std`, `library/windows_targets`, and `library/backtrace`:

    not(target_vendor = "win7")  -->  not(target_os = "windows")
    target_vendor = "win7"       -->  target_os = "windows"

  Algebraic effect:
    * On Linux host builds (`x86_64-unknown-linux-gnu`):
        `target_os = "windows"` is FALSE, `not(target_os = "windows")` is TRUE
        -> host rustc / host std are completely untouched!
    * On Windows target builds (`x86_64-pc-windows-msvc`):
        `target_os = "windows"` is TRUE, `not(target_os = "windows")` is FALSE
        -> standard `x86_64-pc-windows-msvc` ALWAYS emits Win7-compatible code:
           - Uses advapi32 RtlGenRandom instead of Win10+ bcryptprimitives ProcessPrng
           - Dynamically loads WaitOnAddress/WakeByAddressSingle with Nt*KeyedEvent fallback
           - Uses GetSystemTimeAsFileTime fallback for GetSystemTimePreciseAsFileTime
           - Uses Win7 Mutex/Condvar/RwLock/Once/Parker implementations
           - Uses Win7 home_dir_crt() and legacy dbghelp symbolization
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Scoped to the standard library, Windows target link definitions, and backtrace
# so compiler/rustc internals and unrelated tests are untouched.
TARGET_SUBTREES = (
    Path("library/std/src"),
    Path("library/windows_link/src"),
    Path("library/windows_targets/src"),
    Path("library/backtrace/src"),
)

# Match `not(target_vendor = "win7")` first so we don't partially match its inner term.
RE_NOT_WIN7 = re.compile(r'not\(\s*target_vendor\s*=\s*"win7"\s*\)')
RE_WIN7 = re.compile(r'target_vendor\s*=\s*"win7"')

# Also catch `any(target_vendor = "win7")` cleanly (already handled by RE_WIN7,
# producing `any(target_os = "windows")` which is valid Rust cfg syntax).

EXPECTED_CRITICAL_FILES = (
    "library/std/src/sys/pal/windows/c.rs",
    "library/std/src/sys/random/windows.rs",
    "library/std/src/sys/sync/mutex/mod.rs",
)


def transform_rust_source(text: str) -> tuple[str, int, int]:
    """Rewrite win7 vendor cfg predicates to windows target_os predicates."""
    text, n_not = RE_NOT_WIN7.subn('not(target_os = "windows")', text)
    text, n_pos = RE_WIN7.subn('target_os = "windows"', text)
    return text, n_not, n_pos


def patch_rust_tree(rust_dir: Path, dry_run: bool = False) -> dict[str, tuple[int, int]]:
    rust_dir = rust_dir.resolve()
    if not (rust_dir / "library/std/src").is_dir():
        raise FileNotFoundError(
            f"{rust_dir} does not look like a Rust source checkout "
            "(missing library/std/src). Did you clone with --recursive / submodules?"
        )

    changes: dict[str, tuple[int, int]] = {}
    for subtree in TARGET_SUBTREES:
        base = rust_dir / subtree
        if not base.is_dir():
            # Rust 1.100+ replaced windows_targets with windows_link; only warn if neither exists
            if subtree == Path("library/windows_targets/src") and (rust_dir / "library/windows_link/src").is_dir():
                continue
            if subtree == Path("library/windows_link/src") and (rust_dir / "library/windows_targets/src").is_dir():
                continue
            print(f"[warn] subtree not found (submodule missing?): {base}", file=sys.stderr)
            continue
        for rs_file in sorted(base.rglob("*.rs")):
            # Skip unit test files to avoid touching test attributes unnecessarily
            if rs_file.name == "tests.rs" or "tests" in rs_file.parts:
                continue
            original = rs_file.read_text(encoding="utf-8")
            if '"win7"' not in original:
                continue
            updated, n_not, n_pos = transform_rust_source(original)
            if updated != original:
                rel = rs_file.relative_to(rust_dir).as_posix()
                changes[rel] = (n_not, n_pos)
                if not dry_run:
                    rs_file.write_text(updated, encoding="utf-8")

    return changes


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Patch a Rust source checkout so x86_64-pc-windows-msvc targets Windows 7 SP1."
    )
    parser.add_argument("rust_dir", type=Path, help="Path to cloned rust-lang/rust repository")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report files that would be patched without modifying disk",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if expected critical stdlib files were not matched (unless already patched)",
    )
    args = parser.parse_args()

    changes = patch_rust_tree(args.rust_dir, dry_run=args.dry_run)

    mode = "DRY-RUN" if args.dry_run else "PATCHED"
    total_not = sum(v[0] for v in changes.values())
    total_pos = sum(v[1] for v in changes.values())

    if not changes:
        print(
            "[konfox-rust] No `target_vendor = \"win7\"` guards found "
            "(tree is either already patched or Rust removed win7 std support)."
        )
        return 0

    print(
        f"[konfox-rust] {mode} {len(changes)} file(s): "
        f"{total_not} not(win7) -> not(windows), {total_pos} win7 -> windows"
    )
    for rel, (n_not, n_pos) in changes.items():
        print(f"  - {rel} (not_win7={n_not}, win7={n_pos})")

    if args.strict:
        missing = [f for f in EXPECTED_CRITICAL_FILES if f not in changes]
        if missing:
            print(
                f"[konfox-rust] WARNING: critical files not modified: {missing}",
                file=sys.stderr,
            )
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
