# vkd3d-proton patches

Applied in numeric order by `build/vkd3d-proton/build.sh` (`patch -p1`) to upstream
vkd3d-proton `4522cc1a8b1347f1ab1b0f7b14a23ed9444d95d1` (v3.1; the first three were written against 750061ae2b and apply unchanged). All three come from NutsEmu
0.0.1 build 1382 (Evan Bolton, published corresponding source,
`patches/vkd3d-proton/`), LGPL-2.1-or-later like vkd3d-proton. Each file's header keeps
the origin and the dates NutsEmu gives. Madeira's copies (2026-10-12) change no code;
comments were reworded to leave out application names.

| Patch | First added (NutsEmu) | Summary |
|---|---|---|
| 0001-transform-feedback-and-texel-alignment-optional.patch | 2026-10-05 | No transform feedback or single-texel alignment: a warning instead of a device-creation failure (stream output then unavailable) |
| 0002-no-layered-api-properties.patch | 2026-10-05 | The VK_KHR_maintenance7 layered-API properties chain is not queried (winevulkan faulted converting it back) |
| 0003-kosmickrisp-shader-model-gates.patch | 2026-10-06 | On VK_DRIVER_ID_MESA_KOSMICKRISP only: feature level 12_0 without tiled resources, shader model past 6.0 without float32 denormal control, the compute-derivatives fallback for 6.6; plus one INFO line with the feature-level inputs (every driver) |
| 0004-kosmickrisp-small-occlusion-pool.patch | Madeira, 2026-11-20 | Smaller occlusion query pools (env MADEIRA_KK_OCCLUSION_POOL = 0 turns it off; 64-4096 sets the size) |
| 0005-placed-buffer-offset.patch | Madeira, 2026-11-20 | Placed buffers at the offset the heap needs (env MADEIRA_VKD3D_PLACED_BUFFER_OFFSET = 0 turns it off) |
| 0006-madeira-atomic64-caps.patch | Madeira, 2026-11-27 | Off by default: env MADEIRA_VKD3D_ATOMIC64 = 1 reports the 64-bit atomic caps (options11 descriptor-heap, options9 typed and groupshared) the driver lacks, for RE Engine's startup check |
| 0007-fl-override-keeps-tiled-tier.patch | Madeira, 2026-11-27 | VKD3D_FEATURE_LEVEL no longer raises TiledResourcesTier on a driver without sparse binding (reserved resources then crashed on the missing sparse queue) |
| 0008-madeira-architecture-override.patch | Madeira, 2026-11-27 | Off by default: env MADEIRA_VKD3D_UMA = 0 reports ARCHITECTURE(1) UMA and CacheCoherentUMA FALSE (KosmicKrisp makes every memory type host visible), MADEIRA_VKD3D_TILE_BASED = 1 reports TileBasedRenderer TRUE, as Madeira's own D3D12 does; one INFO line at the first query |
