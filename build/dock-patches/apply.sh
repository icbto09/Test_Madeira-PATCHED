#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 ft7t8drgwf-wq
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
#
# Applies this repository's Madeira Dock changes (build/dock-patches/*.patch, in
# order) to the madeira-dock checkout before build/madeira-dock/build.sh builds dockhost.exe.
# The madeira-dock submodule and its repository are not changed: the patches only
# touch the working tree, and a patch already applied is skipped, so every
# build script can call this. `apply.sh --revert` takes them out again.
# See build/dock-patches/README.md.
set -eu
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
S="$R/madeira-dock"
shopt -s nullglob
patches=("$R"/build/dock-patches/*.patch)
# Nothing to do without patches (and bash 3.2 under set -u rejects "${patches[@]}" when empty).
[ ${#patches[@]} -gt 0 ] || exit 0
if [ "${1:-}" = --revert ]; then
    for ((i = ${#patches[@]} - 1; i >= 0; i--)); do
        p="${patches[$i]}"
        if git -C "$S" apply --reverse --check "$p" 2>/dev/null; then
            git -C "$S" apply --reverse "$p"
            echo "dock-patches: reverted $(basename "$p")"
        fi
    done
    exit 0
fi
# A later patch can change lines an earlier one touched (0006 is written against the tree with 0001-0005
# applied), so one earlier patch cannot be tested on its own once a later one is in. Find the last patch
# that is applied (the highest whose reverse applies cleanly: the patches are a stack, applied in order),
# report the ones up to it as applied, and apply the rest in order.
last=-1
for ((i = ${#patches[@]} - 1; i >= 0; i--)); do
    if git -C "$S" apply --reverse --check "${patches[$i]}" 2>/dev/null; then last=$i; break; fi
done
for ((i = 0; i < ${#patches[@]}; i++)); do
    p="${patches[$i]}"
    if [ $i -le $last ]; then
        echo "dock-patches: $(basename "$p") already applied"
    elif git -C "$S" apply --check "$p" 2>/dev/null; then
        git -C "$S" apply "$p"
        echo "dock-patches: applied $(basename "$p")"
    else
        echo "dock-patches: $(basename "$p") does not apply on madeira-dock $(git -C "$S" rev-parse --short HEAD)" >&2
        exit 1
    fi
done
