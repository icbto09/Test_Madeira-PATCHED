# Graphics versions: other DXVK and vkd3d-proton builds

Madeira ships one DXVK ([DXVK.md](DXVK.md)) and one vkd3d-proton, built as ARM64EC with
Madeira's Vulkan-on-Metal patches. Graphics versions lets you import other builds and
choose one for every game or for one game, like the version pickers in Android launchers.

## Where

- **Settings › Graphics › DXVK version / vkd3d-proton version**: the choice for every game
  (`dxvk-version` / `vkd3d-version` in madeira.cfg).
- **Game details › Advanced › Graphics versions**: this game only (its own config lines,
  which win over madeira.cfg). "Same as Settings" removes the game's line. This page also
  sets the game's Direct3D 10/11 route (DXMT or DXVK), Direct3D 12 route (madeira-d3d12 or
  vkd3d-proton) and Vulkan driver (MoltenVK or KosmicKrisp).

Each list has **Madeira's build**, then every imported version with its architecture. Tap
one to choose it, swipe left to delete, and use **Import a version…** to add one. Changes
apply at the next game start.

A version is only used on its route:

| Kind | Used when |
| --- | --- |
| DXVK | `d3d11 = dxvk` |
| vkd3d-proton | `d3d12 = vkd3d`, or `d3d11 = dxvk` with `d3d12` unset |

## What can be imported

A folder or an archive: `.zip`, `.7z`, `.rar`, `.tar`, `.tar.gz`, `.tar.xz`, `.tar.zst` or
Winlator's `.wcp`. Madeira searches the whole archive for a 64-bit set: DXVK's `d3d11.dll`
and `dxgi.dll` (plus `d3d10core.dll` if there is one), and vkd3d-proton's `d3d12.dll` (plus
`d3d12core.dll`). If an archive holds both kinds, both are added. Madeira's own
`dxvk-d3d11.dll` naming works too.

- **ARM64EC** DLLs run natively. They are the best choice.
- **x64** DLLs, as in the `x64/` or `system32/` folder of the usual DXVK and vkd3d-proton
  release archives and Android packages, also work. FEX emulates them, so they are slower.
- 32-bit (`x32/`, `syswow64/`) and plain ARM64 (`arm64/`, for Windows on ARM) DLLs are
  skipped. Madeira's 64-bit games cannot load them.

The DLLs go to `Documents/vulkan-versions/dxvk/<name>/` or `.../vkd3d/<name>/` under their
plain names, with `madeira-version.txt` (source, architecture, date). The folder name is
the value written to the config, so you can also copy a folder there in the Files app and
type its name.

## Releases from elsewhere

Android launchers (Winlator, GameHub, and others) use the same upstream releases, and their
x64 DLLs load here. They are not patched for Apple's Vulkan drivers, though. Upstream DXVK
and vkd3d-proton may stop at device creation (for example "Device does not support required
feature" or a missing extension), because MoltenVK and KosmicKrisp lack some features the
unpatched builds require. Madeira's patches (`build/dxvk/patches`,
`build/vkd3d-proton/patches`) make those features optional. The best way to try another
release is to build it with those patches (below).

## Building a version with Madeira's patches

Run **Actions › Build graphics versions (DXVK / vkd3d-proton) › Run workflow**
(`.github/workflows/graphics-versions.yml`). It only runs when started by hand. The inputs:

- **component**: `both`, `dxvk` or `vkd3d-proton`.
- **dxvk_ref / vkd3d_ref**: a tag (`v2.7`), a branch (`master`) or a commit. Leave it empty
  for Madeira's pinned version.
- **patches**: `try` (default) applies every patch that still applies and lists the rest
  in the artifact's `README.txt`. `all` fails if any patch fails, and `none` builds upstream
  as is.

Each kind becomes an artifact named like `dxvk-v2.7-madeira` or
`vkd3d-proton-v2.14-madeira`. Download its `.zip` on the device and import it as it is. The
artifact name becomes the version's name.

The same scripts work locally:

```
DXVK_REF=v2.7 DXVK_PATCHES=try DEST=/tmp/dxvk build/dxvk/build.sh
VKD3D_REF=v2.14 VKD3D_PATCHES=try DEST=/tmp/vkd3d build/vkd3d-proton/build.sh
```

## Log lines

At session start, `[vulkan-version]` lines show which DLLs were used and their
architecture. They also say when a choice fell back to Madeira's build. That happens when
the folder is missing, a required DLL is missing, or a DLL is 32-bit or ARM64. The `[vulkan]`
summary line names the version, and `[graphics-versions]` lines record imports and
choices.
