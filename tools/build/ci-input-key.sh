#!/usr/bin/env bash
set -euo pipefail
xcode=$(xcodebuild -version)
sdk=$(xcrun --sdk iphoneos --show-sdk-version)
compiler=$(xcrun clang --version)
sdk_build=$(xcrun --sdk iphoneos --show-sdk-build-version)
macos_sdk=$(xcrun --sdk macosx --show-sdk-version)
macos_sdk_build=$(xcrun --sdk macosx --show-sdk-build-version)
repo_root=$(git rev-parse --show-toplevel)
rustc=$(cd "$repo_root/build/rppairing-ios" && rustc -vV)
fingerprint() { shasum -a 256 | cut -c1-20; }
flags() { env | LC_ALL=C sort | awk -F= -v pattern="$1" '$1 ~ pattern'; }
key=$( { printf '%s\n' "$xcode" "$sdk" "$sdk_build" "$macos_sdk" "$macos_sdk_build" "$compiler"; uname -sm; flags '^(CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|SDKROOT|MACOSX_DEPLOYMENT_TARGET|IPHONEOS_DEPLOYMENT_TARGET|ImageOS)$'; } | fingerprint)
rust=$( { printf '%s\n' "$key" "$rustc"; flags '^(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|RUSTUP_TOOLCHAIN)$'; } | fingerprint)
graphics=$( { printf '%s\n' "$key"; flags '^(DXMT_METAL_STD|MADEIRA_ONLY|MADEIRA_MSC_ROOT)$'; } | fingerprint)
ipa=$( { printf '%s\n' "$key" "$rust" "$graphics"; flags '^(CONFIGURATION|MADEIRA_MOLTENVK)$'; } | fingerprint)
if [[ -n "${MADEIRA_PLANNED_SDK:-}" && "$key" != "$MADEIRA_PLANNED_SDK" ]]; then
  printf '%s\n' "$xcode" "iOS SDK: $sdk ($sdk_build)" "macOS SDK: $macos_sdk ($macos_sdk_build)" "$compiler" >&2
  echo "ERROR: this runner's build inputs differ from the planned IPA key" >&2
  exit 1
fi
drift=0
if [[ -n "${MADEIRA_PLANNED_IPA:-}" && "$ipa" != "$MADEIRA_PLANNED_IPA" ]]; then
  # Fork test build: GitHub rolls new runner images out gradually, so the plan job and the
  # app job can get images with the same Xcode but a different Rust (rustc -vV is in the IPA
  # key). With MADEIRA_ALLOW_IPA_DRIFT=1 the app is still built, from this runner's tools,
  # but drift=1 keeps it out of the cache under the planned key.
  printf 'rustc on this runner:\n%s\n' "$rustc" >&2
  if [[ "${MADEIRA_ALLOW_IPA_DRIFT:-}" == 1 ]]; then
    echo "WARNING: this runner's app build inputs differ from the planned IPA key (Rust or app flags; Xcode and SDKs match); building without caching the IPA" >&2
    drift=1
  else
    echo "ERROR: this runner's app build inputs differ from the planned IPA key" >&2
    exit 1
  fi
fi
printf 'key=%s\nrust=%s\ngraphics=%s\nipa=%s\ndrift=%s\n' "$key" "$rust" "$graphics" "$ipa" "$drift" >> "$GITHUB_OUTPUT"
