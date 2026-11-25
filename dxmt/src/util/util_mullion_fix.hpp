/*
 * util_mullion_fix.hpp -- off switches for fixes ported from Mullion.
 *
 * Mullion (https://github.com/dttdrv/mullion) is a DXMT fork by dttdrv and
 * contributors, licensed LGPL-2.1-or-later like DXMT. The fixes guarded by
 * mullionFix() are ported from it; each call site names the Mullion commit.
 *
 * Every ported fix is ON by default. Environment:
 *   MADEIRA_DXMT_MULLION_FIXES=0     turns every ported fix off;
 *   MADEIRA_DXMT_MULLION_<NAME>=0    turns one fix off.
 * Each value is read once per call site (static local), so set it in the
 * game's own config before launch.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "util_env.hpp"

#include <string>

namespace dxmt {

inline bool
mullionFix(const char *name) {
  if (env::getEnvVar("MADEIRA_DXMT_MULLION_FIXES") == "0")
    return false;
  std::string var = std::string("MADEIRA_DXMT_MULLION_") + name;
  return env::getEnvVar(var.c_str()) != "0";
}

} // namespace dxmt
