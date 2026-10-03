#!/usr/bin/env bash
#
# build_wsl2_vmlinux.sh
#
# Builds a debug-symbol vmlinux from Microsoft's WSL2-Linux-Kernel source tree,
# matching the exact kernel banner running in your WSL2 instance, for use with
# dwarf2json / Volatility3 memory forensics.
#
# Usage:
#   1. Clone the matching tag first, e.g.:
#        git clone --depth 1 --branch linux-msft-wsl-5.15.167.4 \
#          https://github.com/microsoft/WSL2-Linux-Kernel.git
#   2. cd WSL2-Linux-Kernel
#   3. Copy this script in and run: bash build_wsl2_vmlinux.sh
#
# What it does:
#   - Applies Microsoft's WSL config as a base
#   - Enables debug info (CONFIG_DEBUG_INFO) needed for dwarf2json
#   - Disables CONFIG_WERROR so warnings-as-errors don't kill unrelated builds
#     (the WSL2 kernel tree has some bit-rotted netfilter files that trip
#     newer GCC's stricter warnings)
#   - Iteratively detects two classes of failure and self-heals past both:
#       1) "No rule to make target" (missing .c files for some net/netfilter/
#          xt_* targets) -> comments out just those lines in the Makefile.
#       2) A genuine compile error inside a legacy iptables match/target file
#          (net/*/netfilter/{ipt,ip6t,xt}_*.c) -> looks up the exact
#          CONFIG_ symbol that guards that object in its Makefile and
#          disables it via `scripts/config`, instead of patching source.
#          Disabled symbols are recorded in kconfig-disables.txt so they
#          survive the "start from a clean base config" step above on the
#          next re-run of this script.
#     Retries after each fix, up to a fixed number of iterations.
#   - Verifies the final vmlinux has actual DWARF debug sections
#
# NOTE: this disables a small number of unrelated netfilter iptables targets
# (e.g. xt_HL, xt_TCPMSS, ECN) that are broken/missing in this source tree.
# This has zero effect on Volatility3's ability to parse task/process/memory
# structures — it only affects unrelated packet-filtering match/target modules.

set -uo pipefail

MAX_ITERATIONS=15
BUILD_LOG="build.log"
DISABLES_FILE="kconfig-disables.txt"

echo "==> Checking we're in a kernel source tree..."
if [ ! -f "Makefile" ] || [ ! -d "kernel" ]; then
    echo "ERROR: run this from the root of the WSL2-Linux-Kernel checkout." >&2
    exit 1
fi

echo "==> Applying Microsoft WSL2 base config..."
if [ -f "Microsoft/config-wsl" ]; then
    cp Microsoft/config-wsl .config
else
    echo "WARNING: Microsoft/config-wsl not found — assuming .config already exists." >&2
fi

echo "==> Enabling debug info and disabling -Werror..."
scripts/config --enable CONFIG_DEBUG_INFO
scripts/config --set-val CONFIG_WERROR n

# Prefer DWARF4 if the option exists (some dwarf2json versions parse it more
# reliably than DWARF5) — ignore failure if the symbol doesn't exist.
scripts/config --enable CONFIG_DEBUG_INFO_DWARF4 2>/dev/null || true

# Re-apply any CONFIG_ symbols we previously had to disable to work around
# broken legacy netfilter targets (see class-2 handling below). Without this,
# every re-run would silently reintroduce a build we already know is broken,
# because the base-config copy above wipes such changes.
if [ -f "$DISABLES_FILE" ]; then
    echo "==> Re-applying ${DISABLES_FILE} from a previous run:"
    while IFS= read -r sym; do
        [ -z "$sym" ] && continue
        echo "    disabling ${sym}"
        scripts/config --disable "$sym"
    done < "$DISABLES_FILE"
fi

make olddefconfig

echo "==> Starting iterative build (max ${MAX_ITERATIONS} attempts)..."
iteration=1
while [ "$iteration" -le "$MAX_ITERATIONS" ]; do
    echo ""
    echo "=== Build attempt ${iteration}/${MAX_ITERATIONS} ==="
    make -j"$(nproc)" vmlinux > "$BUILD_LOG" 2>&1
    build_status=$?

    if [ "$build_status" -eq 0 ] && [ -f vmlinux ]; then
        echo "==> Build succeeded."
        break
    fi

    # --- Class 1: "No rule to make target 'path/to/file.o'" errors ---
    missing_targets=$(grep -oP "No rule to make target '\K[^']+(?=\.o')" "$BUILD_LOG" | sort -u)

    patched_any=0
    reconfig_needed=0

    if [ -n "$missing_targets" ]; then
        echo "==> Found missing target(s), patching them out of their Makefiles:"
        while IFS= read -r target; do
            [ -z "$target" ] && continue
            obj_path="${target}.o"
            base_name="$(basename "$target")"
            makefile_dir="$(dirname "$target")/Makefile"

            if [ ! -f "$makefile_dir" ]; then
                echo "    WARNING: could not find Makefile at ${makefile_dir} for target ${obj_path}" >&2
                continue
            fi

            if grep -q "^#.*${base_name}\.o" "$makefile_dir"; then
                echo "    ${base_name}.o already commented out in ${makefile_dir} — skipping"
                continue
            fi

            echo "    Commenting out ${base_name}.o in ${makefile_dir}"
            sed -i "/\b${base_name}\.o\b/s/^/#/" "$makefile_dir"
            patched_any=1
        done <<< "$missing_targets"
    fi

    # --- Class 2: a genuine compile error inside a legacy netfilter match/
    # target file (ipt_*.c / ip6t_*.c / xt_*.c). These are optional modules
    # unrelated to task/process structures, so instead of trying to patch
    # the C source we just turn off the Kconfig symbol that builds them.
    if [ "$patched_any" -eq 0 ]; then
        broken_sources=$(grep -oP "^(net|drivers)/\S*/netfilter/(ipt|ip6t|xt)_\w+\.c(?=:\d+:\d+: error:)" "$BUILD_LOG" | sort -u)

        while IFS= read -r src; do
            [ -z "$src" ] && continue
            base_name="$(basename "$src" .c)"
            makefile_dir="$(dirname "$src")/Makefile"

            if [ ! -f "$makefile_dir" ]; then
                echo "    WARNING: could not find Makefile at ${makefile_dir} for ${src}" >&2
                continue
            fi

            # Find the line building this object, e.g.:
            #   obj-$(CONFIG_IP_NF_TARGET_ECN) += ipt_ECN.o
            # and pull out the CONFIG_ symbol that guards it.
            sym=$(grep -oP "CONFIG_[A-Z0-9_]+(?=\)\s*\+=\s*${base_name}\.o)" "$makefile_dir" | head -1)

            if [ -z "$sym" ]; then
                echo "    WARNING: could not find a CONFIG_ symbol for ${base_name}.o in ${makefile_dir} — check manually." >&2
                continue
            fi

            if grep -qx "$sym" "$DISABLES_FILE" 2>/dev/null; then
                echo "    ${sym} already disabled — skipping"
                continue
            fi

            echo "    Compile error in ${src} -> disabling ${sym}"
            scripts/config --disable "$sym"
            echo "$sym" >> "$DISABLES_FILE"
            patched_any=1
            reconfig_needed=1
        done <<< "$broken_sources"
    fi

    if [ "$patched_any" -eq 0 ]; then
        echo "ERROR: build failed and no known-fixable pattern (missing target or" >&2
        echo "broken legacy netfilter module) was found in ${BUILD_LOG}." >&2
        echo "Showing the last 60 lines for diagnosis:" >&2
        tail -60 "$BUILD_LOG" >&2
        exit 1
    fi

    # A Kconfig symbol changed -> re-run olddefconfig so the option is
    # actually cleared before the next build attempt (Makefile comment-outs
    # from class 1 don't need this).
    if [ "$reconfig_needed" -eq 1 ]; then
        make olddefconfig >/dev/null
    fi

    iteration=$((iteration + 1))
done

if [ ! -f vmlinux ]; then
    echo "ERROR: exceeded ${MAX_ITERATIONS} attempts without producing vmlinux." >&2
    echo "Check the tail of ${BUILD_LOG}:" >&2
    tail -60 "$BUILD_LOG" >&2
    exit 1
fi

echo ""
echo "==> Verifying vmlinux has debug sections..."
if command -v readelf >/dev/null 2>&1; then
    if readelf -S vmlinux 2>/dev/null | grep -q "\.debug_info"; then
        echo "    OK: .debug_info section present."
    else
        echo "    WARNING: no .debug_info section found — CONFIG_DEBUG_INFO may not have taken effect." >&2
    fi
else
    echo "    (readelf not found — skipping debug section check)"
fi

echo ""
echo "==> Done. vmlinux details:"
ls -la vmlinux
file vmlinux

echo ""
echo "Next step: generate the Volatility3 ISF, e.g.:"
echo "  dwarf2json linux --elf vmlinux > wsl2-kernel.json"
echo "  xz -9 wsl2-kernel.json"
echo "  mv wsl2-kernel.json.xz /path/to/volatility3/symbols/linux/"