#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 ft7t8drgwf-wq
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
#
# Applies Madeira's own FEX changes (build/fex-patches/*.patch, in order) to the
# FEX checkout before build/fex-arm64ec/build.sh and build/fex-wow64/build.sh
# build it. The FEX submodule and its repository are not changed: the patches
# only touch the working tree, and a patch already applied is skipped, so both
# build scripts can call this. `apply.sh --revert` takes them out again.
# These patches are Madeira's, not FEX-Emu's: see build/fex-patches/README.md.
set -eu
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
F="$R/FEX"
shopt -s nullglob
# FEX is a submodule upstream but an ordinary folder in this fork. git apply run inside a
# subdirectory of a repository reads "diff --git" paths from the repository root and silently
# skips them ("Skipped patch"), so a patch would be reported applied without being applied. When
# FEX has no .git of its own, apply from the repository root with --directory=FEX instead.
fex_apply() {
    if [ -e "$F/.git" ]; then
        git -C "$F" apply "$@"
    else
        git -C "$R" apply --directory=FEX "$@"
    fi
}
patches=("$R"/build/fex-patches/*.patch)
# Nothing to do without patches (and bash 3.2 under set -u rejects "${patches[@]}" when empty).
[ ${#patches[@]} -gt 0 ] || exit 0
if [ "${1:-}" = --revert ]; then
    for ((i = ${#patches[@]} - 1; i >= 0; i--)); do
        p="${patches[$i]}"
        if fex_apply --reverse --check "$p" 2>/dev/null; then
            fex_apply --reverse "$p"
            echo "fex-patches: reverted $(basename "$p")"
        fi
    done
    exit 0
fi
# A later patch can change lines an earlier one touched (0005 is written against the tree with 0001-0004
# applied), so a single earlier patch cannot be tested on its own once a later one is in. Find the last
# patch that is applied (the highest one whose reverse applies cleanly: the patches are a stack, applied
# in order), report the ones up to it as applied, and apply the rest in order.
last=-1
for ((i = ${#patches[@]} - 1; i >= 0; i--)); do
    if fex_apply --reverse --check "${patches[$i]}" 2>/dev/null; then last=$i; break; fi
done
for ((i = 0; i < ${#patches[@]}; i++)); do
    p="${patches[$i]}"
    if [ $i -le $last ]; then
        echo "fex-patches: $(basename "$p") already applied"
    elif fex_apply --check "$p" 2>/dev/null; then
        fex_apply "$p"
        echo "fex-patches: applied $(basename "$p")"
    else
        echo "fex-patches: $(basename "$p") does not apply on FEX $(git -C "$F" rev-parse --short HEAD 2>/dev/null || echo "(folder)")" >&2
        exit 1
    fi
done
