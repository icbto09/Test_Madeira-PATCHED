# Mesa patches

Numbered patches (`0001-...` to `0008-...`) are for the OSMesa + Zink build of Mesa 25.0.7
(`build/mesa-ios/build.sh`). Patches named `kosmickrisp-ios-*` are for the KosmicKrisp Vulkan
driver build of Mesa 26.2.4 (`build/mesa-ios/build-kosmickrisp.sh`, `docs/KOSMICKRISP.md`). Each
script applies only its own set. All patches change Mesa code and are offered under Mesa's
licence (MIT).

- `0008-zink-moltenvk-zero-unwritten-fs-inputs.patch`: Metal refuses a fragment input that the
  vertex shader does not output at the same location, component and type. At program link
  (MoltenVK only), the vertex stage first stores zero into every varying component the fragment
  shader reads, and both stages get one variable per slot with the same shape.
  `MADEIRA_ZINK_LINK_FS_INPUTS=0` turns this off, and `=1` turns it on for other drivers.
- `0009-osmesa-allow-compressed-fallback.patch`: Metal on A-series iPhones and iPads has no BC
  texture sampling (`supportsBCTextureCompression = NO`), so MoltenVK and KosmicKrisp report no BC
  formats. Mesa can still expose S3TC (DXT1/3/5), RGTC, LATC and BPTC and decode those uploads to
  RGBA8 on the CPU, but only when `allow_compressed_fallback` is on. The DRI frontends take it from
  driconf, where it defaults to true. OSMesa never reads driconf and left it false, so those
  extensions were missing, a game that uploads DXT data without checking got `GL_INVALID_ENUM`, and
  the incomplete texture sampled as opaque black (Mewgenics, #566). OSMesa now turns the
  option on; a GPU with BC keeps the native formats. `MADEIRA_GL_COMPRESSED_FALLBACK=0` turns it
  off.
- `kosmickrisp-ios-0001-wsi-metal-no-display-sync-on-ios.patch`: the Metal WSI sets
  `CAMetalLayer.displaySyncEnabled`, which iOS does not have. On iOS it is skipped, so an
  immediate-mode swapchain presents with vsync.
- `kosmickrisp-ios-0002-link-system-frameworks.patch`: links Foundation, CoreGraphics and libobjc
  into `libvulkan_kosmickrisp.dylib`. Upstream relies on `-undefined dynamic_lookup` for them. With
  the patch, only the driver's weak, unimplemented entry points are looked up at load time, and
  those resolve to NULL.
- `kosmickrisp-ios-0003-export-get-proc-addr-on-apple.patch`: on Apple platforms the driver also
  exports `vkGetInstanceProcAddr` and `vkGetDeviceProcAddr`. An app can then `dlopen` it and use it
  as its libvulkan without a Vulkan loader, the same way it uses MoltenVK.
- Mesa 26.3.1 (0.2.97): upstream KosmicKrisp now waits for and releases drawables itself, so the
  old 0004 (drawable sync), 0005 (release drawables) and 0006 (present probe) are gone, with their
  switches `MADEIRA_KK_DRAWABLE_SYNC`, `MADEIRA_KK_FEEDBACK_ONCE` and `MADEIRA_KK_PRESENT_PROBE`.
  The 26.2.4 driver stays in the app as `gl/libvulkan_kosmickrisp-26.2.4.dylib`; a game's own
  config can go back to it with `vulkan = gl/libvulkan_kosmickrisp-26.2.4.dylib`.
- `kosmickrisp-ios-0004-timestamp-heap-split.patch`: the old 0007 rebased onto 26.3.1's query code
  (timestamp counter heaps split at 4096 entries). `MADEIRA_KK_TS_HEAP_SPLIT=0` turns it off.
- `kosmickrisp-ios-0005-wsi-layer-residency-on-ios.patch`: upstream adds the `CAMetalLayer`
  residency set only on macOS 26; this enables the same code on iOS 26.
  `MADEIRA_KK_LAYER_RESIDENCY=0` turns it off.
- `kosmickrisp-ios-0006-no-mach-vm-header-on-ios.patch`: a build fix. The iOS SDK refuses
  `<mach/mach_vm.h>`, which 26.3.1's `kk_bo.c` includes; on iOS the same calls go through
  `vm_remap`, `vm_map` and `vm_deallocate` from `<mach/vm_map.h>`.
- `kosmickrisp-ios-0007-disk-shader-cache.patch` (0.2.98): KosmicKrisp creates Mesa's disk shader
  cache, the way Asahi's driver does (upstream frees it but never creates it). On iOS it defaults
  `MESA_SHADER_CACHE_DIR` to `$HOME/Library/Caches` and the cap to 4G, only when unset, and logs
  one `[kk-disk-cache]` line. Needs `-Dshader-cache=enabled` (build-kosmickrisp.sh).
  `MADEIRA_KK_DISK_CACHE=0` turns it off. Metal still compiles the pipelines each run.
- Build (0.2.98, kk-linkedit-align): build-kosmickrisp.sh no longer runs `install_name_tool` or
  `strip` on the driver (LLVM 21's tools wrote the LINKEDIT string table 4 bytes off 8-byte
  alignment and dyld refused 0.2.97's driver); `check-linkedit-align.py` fails the build on such a
  file. Build-only, no runtime switch; fallback per game is
  `vulkan = gl/libvulkan_kosmickrisp-26.2.4.dylib`.
- `0010-zink-moltenvk-int-vertex-attribs.patch`: Metal refuses a pipeline whose vertex shader reads an int or uint input from a float, normalized or scaled vertex format ("Cannot convert attribute from MTLAttributeFormatFloat to int1"), and Zink then skips those draws (Vintage Story). On MoltenVK, such attributes get the same-size SINT/UINT format. `MADEIRA_ZINK_INT_ATTRIBS=0` turns this off, and `=1` turns it on for other drivers.
- `kosmickrisp-ios-0008-compile-timing-probe.patch` (0.2.99, kk-compile-timing): log only. Times
  `kk_compile_shaders` (new pipelines) and `kk_deserialize_shader` (cache hits), the share spent in
  Metal's library/pipeline calls, and how many pipelines are built at once; at most one
  `[kk-compile]` line every 10 s while pipelines are made. Touches only `kk_shader.c`.
  `MADEIRA_KK_COMPILE_TIMING=0` turns it off.
- `kosmickrisp-ios-0009-metal-archive.patch` (0.2.100, kk-metal-archive): opt-in. With
  `MADEIRA_KK_METAL_ARCHIVE=1` each compiling thread captures Apple's compiled pipelines (Metal 4
  pipeline data set serializer) into `$MESA_SHADER_CACHE_DIR/kk-metal-archive/*.mtl4a` and later runs
  pass them as lookup archives; `[kk-archive]` lines. Unset or anything but 1: as upstream.
  Touches only `bridge/mtl_compiler.m`.
