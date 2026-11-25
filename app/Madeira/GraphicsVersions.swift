// SPDX-License-Identifier: GPL-3.0-or-later
// Madeira Converter Exception: see LICENSE-EXCEPTION.md
//
//  Graphics versions: DXVK and vkd3d-proton builds besides the bundle's, chosen per game or for
//  every game, like the Android launchers' version pickers.
//
//  A version is a folder in Documents/vulkan-versions/dxvk or .../vkd3d holding the 64-bit DLLs
//  under their plain names (d3d11.dll, dxgi.dll and d3d10core.dll; d3d12.dll and d3d12core.dll)
//  and madeira-version.txt (where it came from, its architecture). The import takes a folder or
//  an archive (.zip, .7z, .rar, and .tar, .tar.gz, .tar.xz, .tar.zst or .wcp through the system's
//  libarchive), looks through it for the 64-bit set (an Android package's x64/ or system32/, a
//  Madeira build's dxvk-*.dll names), and copies only those DLLs. 32-bit and plain ARM64 copies
//  are skipped: Madeira's x64 games load x64 or ARM64EC DLLs only.
//
//  The choice is madeira.cfg / a game's own lines `dxvk-version = <folder>` and
//  `vkd3d-version = <folder>`; WineProcessBridge.m (madeira_vulkan_version_dir) links that
//  folder's DLLs in place of the bundle's when the session uses DXVK (d3d11 = dxvk) or
//  vkd3d-proton (d3d12 = vkd3d). Unset or "bundled": the bundle's build.
//
//  A version without Madeira's patches (build/dxvk/patches, build/vkd3d-proton/patches) may refuse
//  the Vulkan-on-Metal drivers ("Device does not support required feature ..."), and an x64 build
//  runs emulated by FEX; the session log's [vulkan-version] lines name what was loaded.

import SwiftUI
import UniformTypeIdentifiers
import Darwin

enum GraphicsKind: String, CaseIterable, Identifiable {
    case dxvk, vkd3d

    var id: String { rawValue }
    var title: String { self == .dxvk ? "DXVK" : "vkd3d-proton" }
    /// The madeira.cfg key that names the chosen folder.
    var key: String { self == .dxvk ? "dxvk-version" : "vkd3d-version" }
    /// The DLLs a version must have, then the ones it may have (WineProcessBridge.m checks the same).
    var required: [String] { self == .dxvk ? ["d3d11.dll", "dxgi.dll"] : ["d3d12.dll"] }
    var optional: [String] { self == .dxvk ? ["d3d10core.dll"] : ["d3d12core.dll"] }
    var files: [String] { required + optional }
    /// The DLL whose folder marks a set in an import.
    var marker: String { required[0] }
    /// What the session needs for this kind to be used at all.
    var routeNote: String {
        self == .dxvk ? "Used when Direct3D 10/11 is DXVK (d3d11 = dxvk)."
                      : "Used when Direct3D 12 is vkd3d-proton (d3d12 = vkd3d, or d3d11 = dxvk with d3d12 unset)."
    }
}

struct GraphicsVersion: Identifiable, Hashable {
    let kind: GraphicsKind
    let name: String
    let arch: String
    let source: String
    var id: String { kind.rawValue + "/" + name }
}

enum GraphicsVersionError: LocalizedError {
    case noDocuments
    case nothingFound(String)
    case only32Bit(String)
    case unsupported(String)
    case archive(String)

    var errorDescription: String? {
        switch self {
        case .noDocuments: return "Madeira's Documents folder is not available."
        case .nothingFound(let name): return "\(name) has no DXVK (d3d11.dll and dxgi.dll) or vkd3d-proton (d3d12.dll) DLLs."
        case .only32Bit(let detail): return "Only DLLs Madeira's 64-bit games cannot load were found (\(detail)). Use a package with x64 or ARM64EC DLLs."
        case .unsupported(let name): return "\(name) is not a folder or an archive Madeira can unpack. Unpack it in the Files app and import the folder."
        case .archive(let why): return "The archive could not be unpacked: \(why)."
        }
    }
}

enum GraphicsVersions {
    static let infoFile = "madeira-version.txt"

    /// Documents/vulkan-versions.
    static var root: URL? { MadeiraConfig.documents?.appendingPathComponent("vulkan-versions", isDirectory: true) }
    static func folder(_ kind: GraphicsKind) -> URL? { root?.appendingPathComponent(kind.rawValue, isDirectory: true) }

    /// The versions of `kind` that have their required DLLs, in name order.
    static func installed(_ kind: GraphicsKind) -> [GraphicsVersion] {
        let fm = FileManager.default
        guard let dir = folder(kind), let names = try? fm.contentsOfDirectory(atPath: dir.path) else { return [] }
        return names.filter { !$0.hasPrefix(".") }
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
            .compactMap { name in
                let d = dir.appendingPathComponent(name, isDirectory: true)
                guard kind.required.allSatisfy({ fm.fileExists(atPath: d.appendingPathComponent($0).path) }) else { return nil }
                let info = MadeiraConfig.parse(MadeiraConfig.readText(d.appendingPathComponent(infoFile)) ?? "")
                let arch = info["arch"] ?? peArch(d.appendingPathComponent(kind.marker))
                return GraphicsVersion(kind: kind, name: name, arch: arch, source: info["source"] ?? "")
            }
    }

    static func delete(_ version: GraphicsVersion) throws {
        guard let dir = folder(version.kind) else { throw GraphicsVersionError.noDocuments }
        try FileManager.default.removeItem(at: dir.appendingPathComponent(version.name, isDirectory: true))
    }

    /// A DLL's PE architecture: "ARM64EC", "x64", "ARM64", "ARM64X", "i386", or why there is none.
    /// ARM64EC images carry the AMD64 machine value; their load config's CHPE metadata pointer is
    /// what tells them from x64. Same logic as WineProcessBridge.m madeira_pe_arch_path.
    static func peArch(_ url: URL) -> String {
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return "missing" }
        let b = [UInt8](data)
        func u16(_ o: Int) -> Int { o >= 0 && o + 1 < b.count ? Int(b[o]) | Int(b[o + 1]) << 8 : 0 }
        func u32(_ o: Int) -> Int { u16(o) | u16(o + 2) << 16 }
        guard b.count >= 0x40, b[0] == 0x4D, b[1] == 0x5A else { return "not a PE file" }
        let pe = u32(0x3C)
        guard pe + 24 <= b.count, b[pe] == 0x50, b[pe + 1] == 0x45, b[pe + 2] == 0, b[pe + 3] == 0 else { return "not a PE file" }
        let machine = u16(pe + 4), sections = u16(pe + 6), optSize = u16(pe + 20), opt = pe + 24
        if machine == 0x14C { return "i386" }
        guard u16(opt) == 0x20B else { return "unknown machine" }
        let lcRVA = u32(opt + 112 + 80), lcSize = u32(opt + 112 + 84)
        var chpe = 0
        if lcRVA != 0, lcSize >= 0xD0 {
            for i in 0..<sections {
                let s = opt + optSize + 40 * i
                guard s + 40 <= b.count else { break }
                let vsz = u32(s + 8), va = u32(s + 12), rsz = u32(s + 16), raw = u32(s + 20)
                if lcRVA >= va, lcRVA - va < max(vsz, rsz) {
                    let o = raw + (lcRVA - va)
                    if o + 0xD0 <= b.count, u32(o) >= 0xD0 { chpe = u32(o + 0xC8) | u32(o + 0xCC) }
                    break
                }
            }
        }
        if machine == 0x8664 { return chpe != 0 ? "ARM64EC" : "x64" }
        if machine == 0xAA64 { return chpe != 0 ? "ARM64X" : "ARM64" }
        return "unknown machine"
    }

    /// Whether Madeira's x64 sessions can load a DLL of this architecture.
    static func usable(_ arch: String) -> Bool { arch == "ARM64EC" || arch == "x64" }

    /// The name an import gets: the file or folder name without its archive extensions, in
    /// letters, digits, dots, dashes and underscores (madeira.cfg values and folder names).
    static func baseName(_ url: URL) -> String {
        var name = url.lastPathComponent
        for ext in [".tar.gz", ".tar.xz", ".tar.zst", ".tar.bz2", ".tgz", ".txz", ".wcp", ".zip", ".7z", ".rar", ".tar"]
        where name.lowercased().hasSuffix(ext) {
            name = String(name.dropLast(ext.count))
            break
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        let cleaned = String(name.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" })
            .trimmingCharacters(in: CharacterSet(charactersIn: ".-"))
        return cleaned.isEmpty || cleaned.lowercased() == "bundled" ? "version" : cleaned
    }

    /// `name`, or `name-2`, `name-3`, ... when a version of that name is already in `dir`.
    static func uniqueName(_ name: String, in dir: URL) -> String {
        var candidate = name, n = 2
        while FileManager.default.fileExists(atPath: dir.appendingPathComponent(candidate).path) {
            candidate = "\(name)-\(n)"; n += 1
        }
        return candidate
    }

    /// One set of DLLs for a kind found in an import: each file's URL and the marker's architecture.
    struct FoundSet {
        var files: [String: URL]
        var arch: String
    }

    /// The best set of `kind` under `tree`: a folder holding the marker DLL (or Madeira's
    /// dxvk-<name> spelling) whose architecture a 64-bit session can load, ARM64EC before x64,
    /// then the one with more of the optional DLLs. `rejected` collects what was skipped.
    static func bestSet(_ kind: GraphicsKind, in tree: URL, rejected: inout [String]) -> FoundSet? {
        let fm = FileManager.default
        guard let walker = fm.enumerator(at: tree, includingPropertiesForKeys: [.isRegularFileKey]) else { return nil }
        var byFolder: [URL: [String: URL]] = [:]
        for case let url as URL in walker {
            var name = url.lastPathComponent.lowercased()
            if kind == .dxvk, name.hasPrefix("dxvk-") { name = String(name.dropFirst(5)) }
            guard kind.files.contains(name) else { continue }
            byFolder[url.deletingLastPathComponent().standardizedFileURL, default: [:]][name] = url
        }
        var best: FoundSet?
        func rank(_ s: FoundSet) -> (Int, Int) { (s.arch == "ARM64EC" ? 2 : 1, s.files.count) }
        for (folder, files) in byFolder {
            guard kind.required.allSatisfy({ files[$0] != nil }), let marker = files[kind.marker] else { continue }
            let arch = peArch(marker)
            guard usable(arch) else {
                rejected.append("\(kind.title) \(arch) in \(folder.lastPathComponent)")
                continue
            }
            // Every DLL of the set must be the same kind of 64-bit image as the marker.
            let usableFiles = files.filter { usable(peArch($0.value)) }
            let set = FoundSet(files: usableFiles, arch: arch)
            guard kind.required.allSatisfy({ set.files[$0] != nil }) else { continue }
            if best == nil || rank(set) > rank(best!) { best = set }
        }
        return best
    }

    /// Copies a found set into Documents/vulkan-versions/<kind>/<name> under plain names.
    static func install(_ kind: GraphicsKind, set: FoundSet, name: String, source: String) throws -> GraphicsVersion {
        let fm = FileManager.default
        guard let dir = folder(kind) else { throw GraphicsVersionError.noDocuments }
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let final = uniqueName(name, in: dir)
        let staging = dir.appendingPathComponent(".\(final).importing", isDirectory: true)
        try? fm.removeItem(at: staging)
        try fm.createDirectory(at: staging, withIntermediateDirectories: true)
        do {
            for (file, url) in set.files { try fm.copyItem(at: url, to: staging.appendingPathComponent(file)) }
            let stamp = ISO8601DateFormatter().string(from: Date())
            let info = "# Imported by Madeira (Graphics versions)\nsource = \(source)\narch = \(set.arch)\nadded = \(stamp)\n"
            try info.write(to: staging.appendingPathComponent(infoFile), atomically: true, encoding: .utf8)
            try fm.moveItem(at: staging, to: dir.appendingPathComponent(final, isDirectory: true))
        } catch {
            try? fm.removeItem(at: staging)
            throw error
        }
        return GraphicsVersion(kind: kind, name: final, arch: set.arch, source: source)
    }

    /// Imports `source` (a folder, an archive, or a single DLL): every kind found in it becomes a
    /// version. Runs off the main thread; `progress` gets a short phase name.
    static func importItem(_ source: URL, progress: @escaping (String) -> Void) throws -> [GraphicsVersion] {
        let fm = FileManager.default
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        let staging = fm.temporaryDirectory.appendingPathComponent("graphics-import-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: staging, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: staging) }

        let tree: URL
        if ModPath.isDirectory(source) {
            tree = source
        } else {
            progress("Unpacking")
            let out = staging.appendingPathComponent("files", isDirectory: true)
            if ItchArchive.isZip(source) || ItchArchive.is7z(source) {
                _ = try ItchArchive.unpackAny(source, to: out)
            } else if ModRar.isRar(source) {
                try ModRar.unpack(source, to: out)
            } else if source.pathExtension.lowercased() == "dll" {
                try fm.createDirectory(at: out, withIntermediateDirectories: true)
                try fm.copyItem(at: source, to: out.appendingPathComponent(source.lastPathComponent))
            } else {
                try GraphicsArchive.unpack(source, to: out, name: source.lastPathComponent)
            }
            tree = out
        }
        progress("Looking for the DLLs")
        var rejected: [String] = []
        var added: [GraphicsVersion] = []
        let name = baseName(source)
        for kind in GraphicsKind.allCases {
            guard let set = bestSet(kind, in: tree, rejected: &rejected) else { continue }
            progress("Copying \(kind.title)")
            added.append(try install(kind, set: set, name: name, source: source.lastPathComponent))
        }
        if added.isEmpty {
            if !rejected.isEmpty { throw GraphicsVersionError.only32Bit(rejected.sorted().joined(separator: ", ")) }
            throw GraphicsVersionError.nothingFound(source.lastPathComponent)
        }
        return added
    }
}

/// Tar archives and their compressed forms (.tar.gz, .tar.xz, .tar.zst, .tar.bz2, Winlator's
/// .wcp) through the libarchive iOS has in /usr/lib, opened at run time like ModRar: Madeira links
/// nothing for it. Every name is checked with ItchArchive.safeName; links and devices are skipped.
enum GraphicsArchive {
    private typealias New = @convention(c) () -> OpaquePointer?
    private typealias Call = @convention(c) (OpaquePointer?) -> Int32
    private typealias Open = @convention(c) (OpaquePointer?, UnsafePointer<CChar>?, Int) -> Int32
    private typealias Next = @convention(c) (OpaquePointer?, UnsafeMutablePointer<OpaquePointer?>?) -> Int32
    private typealias Name = @convention(c) (OpaquePointer?) -> UnsafePointer<CChar>?
    private typealias FileType = @convention(c) (OpaquePointer?) -> mode_t
    private typealias Read = @convention(c) (OpaquePointer?, UnsafeMutableRawPointer?, Int) -> Int

    private static let ok: Int32 = 0, eof: Int32 = 1, warn: Int32 = -20
    private static let library = dlopen("/usr/lib/libarchive.2.dylib", RTLD_NOW | RTLD_LOCAL)

    private static func symbol<T>(_ name: String, _ type: T.Type) -> T? {
        guard let library, let pointer = dlsym(library, name) else { return nil }
        return unsafeBitCast(pointer, to: type)
    }

    static func unpack(_ archive: URL, to destination: URL, name: String) throws {
        guard library != nil,
              let new = symbol("archive_read_new", New.self), let free = symbol("archive_read_free", Call.self),
              let formats = symbol("archive_read_support_format_all", Call.self),
              let filters = symbol("archive_read_support_filter_all", Call.self),
              let open = symbol("archive_read_open_filename", Open.self), let next = symbol("archive_read_next_header", Next.self),
              let pathname = symbol("archive_entry_pathname", Name.self), let filetype = symbol("archive_entry_filetype", FileType.self),
              let read = symbol("archive_read_data", Read.self), let errorString = symbol("archive_error_string", Name.self),
              let reader = new() else {
            throw GraphicsVersionError.unsupported(name)
        }
        defer { _ = free(reader) }
        _ = formats(reader)
        _ = filters(reader)
        func failure(_ fallback: String) -> GraphicsVersionError {
            .archive(errorString(reader).map { String(cString: $0) } ?? fallback)
        }
        guard open(reader, archive.path, 1 << 16) == ok else { throw GraphicsVersionError.unsupported(name) }
        let fm = FileManager.default
        try fm.createDirectory(at: destination, withIntermediateDirectories: true)
        var buffer = [UInt8](repeating: 0, count: 1 << 20)
        var entries = 0
        while true {
            var entry: OpaquePointer?
            let status = next(reader, &entry)
            if status == eof { break }
            guard status >= warn, let entry else { throw failure("it is damaged or compressed in a way this iOS cannot read") }
            entries += 1
            let raw = pathname(entry).map { String(cString: $0) } ?? ""
            let type = UInt32(filetype(entry)) & 0o170000
            guard let safe = ItchArchive.safeName(raw) else { continue }
            let target = destination.appendingPathComponent(safe)
            if type == 0o040000 { try fm.createDirectory(at: target, withIntermediateDirectories: true); continue }
            guard type == 0o100000 else { continue }
            try fm.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            guard fm.createFile(atPath: target.path, contents: nil) else { throw GraphicsVersionError.archive("a file could not be written") }
            let output = try FileHandle(forWritingTo: target)
            defer { try? output.close() }
            while true {
                let count = buffer.withUnsafeMutableBytes { read(reader, $0.baseAddress, $0.count) }
                if count == 0 { break }
                guard count > 0 else { throw failure("it is damaged") }
                try output.write(contentsOf: Data(buffer[0..<count]))
            }
        }
        if entries == 0 { throw GraphicsVersionError.unsupported(name) }
    }
}

/// Where a choice is written: madeira.cfg (every game) or one game's own lines
/// (GameProfiles.swift, which win over madeira.cfg for that game).
enum GraphicsVersionScope: Hashable {
    case global
    case game(windowsPath: String)

    func value(_ key: String) -> String? {
        let v: String?
        switch self {
        case .global: v = MadeiraConfig.get(key)
        case .game(let path): v = GameProfile(windowsPath: path).values[key]
        }
        let t = v?.trimmingCharacters(in: .whitespaces) ?? ""
        return t.isEmpty ? nil : t
    }

    func set(_ key: String, _ value: String?) {
        switch self {
        case .global:
            MadeiraConfig.set(key, value)
        case .game(let path):
            let profile = GameProfile(windowsPath: path)
            var lines = profile.text.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" })
                .map(String.init)
            if lines.last == "" { lines.removeLast() }
            lines.removeAll { line in
                let t = line.trimmingCharacters(in: .whitespaces)
                guard !t.hasPrefix("#"), let eq = t.firstIndex(of: "=") else { return false }
                return t[..<eq].trimmingCharacters(in: .whitespaces) == key
            }
            if let value { lines.append("\(key) = \(value)") }
            profile.text = lines.joined(separator: "\n")
        }
        LogStore.shared.log("[graphics-versions] \(self == .global ? "madeira.cfg" : "game") \(key) = \(value ?? "(removed)")")
    }
}

/// Settings › Graphics › DXVK / vkd3d-proton versions, and Game details › Graphics versions: the
/// bundle's build and every imported version for each kind, one tap to choose, swipe to delete,
/// and Import for a folder or an archive. In a game's page the Direct3D routes and the Vulkan
/// driver can be set for that game too, since a version is only used on its route.
struct GraphicsVersionsView: View {
    let scope: GraphicsVersionScope
    /// nil: both kinds; otherwise only this one (Settings rows).
    var only: GraphicsKind?

    @State private var versions: [GraphicsKind: [GraphicsVersion]] = [:]
    @State private var chosen: [GraphicsKind: String] = [:]   // "" unset, "bundled", or a folder name
    @State private var routes: [String: String] = [:]          // game scope: d3d11, d3d12, vulkan ("" unset)
    @State private var importing = false
    @State private var busy: String?
    @State private var message: String?
    @State private var failed = false

    private var kinds: [GraphicsKind] { only.map { [$0] } ?? GraphicsKind.allCases }
    private var isGame: Bool { if case .game = scope { return true } else { return false } }

    private struct RouteChoice: Hashable { let value: String; let label: String }
    private struct Route: Identifiable {
        let key: String
        let title: String
        let choices: [RouteChoice]
        var id: String { key }
    }
    /// A game's own lines: "dxmt" and "madeira" are not values the native side looks for, so they
    /// mean the default route while still overriding a madeira.cfg that names DXVK or vkd3d-proton.
    private static let routeChoices: [Route] = [
        Route(key: "d3d11", title: "Direct3D 10/11", choices: [
            RouteChoice(value: "", label: "Same as Settings"), RouteChoice(value: "dxmt", label: "DXMT (Metal)"),
            RouteChoice(value: "dxvk", label: "DXVK (Vulkan)")]),
        Route(key: "d3d12", title: "Direct3D 12", choices: [
            RouteChoice(value: "", label: "Same as Settings"), RouteChoice(value: "madeira", label: "madeira-d3d12 (Metal)"),
            RouteChoice(value: "vkd3d", label: "vkd3d-proton (Vulkan)")]),
        Route(key: "vulkan", title: "Vulkan driver", choices: [
            RouteChoice(value: "", label: "Same as Settings"), RouteChoice(value: "moltenvk", label: "MoltenVK"),
            RouteChoice(value: "kosmickrisp", label: "KosmicKrisp")]),
    ]

    private func reload() {
        for kind in GraphicsKind.allCases {
            versions[kind] = GraphicsVersions.installed(kind)
            chosen[kind] = scope.value(kind.key) ?? ""
        }
        for route in Self.routeChoices { routes[route.key] = (scope.value(route.key) ?? "").lowercased() }
    }

    private func choose(_ kind: GraphicsKind, _ value: String) {
        scope.set(kind.key, value.isEmpty ? nil : value)
        chosen[kind] = value
    }

    private func delete(_ version: GraphicsVersion) {
        do {
            try GraphicsVersions.delete(version)
            // A choice that named it goes back to the default here; other games' lines that name it
            // fall back to the bundle's build at their next start (WineProcessBridge logs it).
            if chosen[version.kind] == version.name { choose(version.kind, "") }
            message = "Deleted \(version.kind.title) \(version.name)."; failed = false
        } catch {
            message = error.localizedDescription; failed = true
        }
        reload()
    }

    private func runImport(_ url: URL) {
        busy = "Reading \(url.lastPathComponent)"
        message = nil
        Task.detached(priority: .userInitiated) {
            let result = Result { try GraphicsVersions.importItem(url) { phase in Task { @MainActor in busy = phase } } }
            await MainActor.run {
                busy = nil
                switch result {
                case .success(let added):
                    message = "Added " + added.map { "\($0.kind.title) \($0.name) (\($0.arch))" }.joined(separator: " and ") + "."
                    failed = false
                    LogStore.shared.log("[graphics-versions] imported \(url.lastPathComponent): "
                                        + added.map { "\($0.kind.rawValue)/\($0.name) \($0.arch)" }.joined(separator: ", "))
                case .failure(let error):
                    message = error.localizedDescription
                    failed = true
                    LogStore.shared.log("[graphics-versions] import of \(url.lastPathComponent) failed: \(error.localizedDescription)")
                }
                reload()
            }
        }
    }

    private func row(_ kind: GraphicsKind, value: String, title: String, detail: String) -> some View {
        Button { choose(kind, value) } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).foregroundStyle(.primary)
                    if !detail.isEmpty { Text(detail).font(.caption).foregroundStyle(.secondary) }
                }
                Spacer()
                if (chosen[kind] ?? "").lowercased() == value.lowercased() { Image(systemName: "checkmark").foregroundStyle(.tint) }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func bundledDetail(_ kind: GraphicsKind) -> String {
        let has = kind.files.allSatisfy { file in
            GraphicsSettings.bundled("vulkan/arm64ec-windows/" + (kind == .dxvk ? "dxvk-" + file : file))
        }
        return has ? "ARM64EC, with Madeira's Vulkan-on-Metal patches" : "Not in this build"
    }

    @ViewBuilder private func section(_ kind: GraphicsKind) -> some View {
        let current = chosen[kind] ?? ""
        let known = current.isEmpty || current.lowercased() == "bundled"
            || (versions[kind] ?? []).contains(where: { $0.name == current })
        let missing: String? = known ? nil : current
        Section {
            if isGame { row(kind, value: "", title: "Same as Settings", detail: "madeira.cfg decides") }
            row(kind, value: isGame ? "bundled" : "", title: "Madeira's build", detail: bundledDetail(kind))
            ForEach(versions[kind] ?? []) { v in
                row(kind, value: v.name, title: v.name,
                    detail: v.arch + (v.arch == "x64" ? " (emulated by FEX)" : "") + (v.source.isEmpty ? "" : " · from \(v.source)"))
                .swipeActions { Button("Delete", role: .destructive) { delete(v) } }
            }
            if let missing {
                Text("\(kind.key) = \(missing) names no imported version, so the session uses Madeira's build.")
                    .font(.caption).foregroundStyle(.orange)
            }
        } header: { Text(kind.title) } footer: { Text(kind.routeNote) }
    }

    var body: some View {
        Form {
            if isGame {
                Section {
                    ForEach(Self.routeChoices) { route in
                        Picker(route.title, selection: Binding(get: { routes[route.key] ?? "" }, set: { value in
                            routes[route.key] = value
                            scope.set(route.key, value.isEmpty ? nil : value)
                        })) {
                            ForEach(route.choices, id: \.value) { Text($0.label).tag($0.value) }
                            if let v = routes[route.key], !route.choices.contains(where: { $0.value == v }) {
                                Text("Other (\(v))").tag(v)
                            }
                        }
                    }
                } header: { Text("This game's routes") } footer: {
                    Text("Written to this game's own config lines, which win over madeira.cfg. DXVK and vkd3d-proton are experimental and 64-bit only.")
                }
            }
            ForEach(kinds) { section($0) }
            Section {
                Button { importing = true } label: { Label("Import a version…", systemImage: "square.and.arrow.down") }
                    .disabled(busy != nil)
                if let busy { HStack(spacing: 8) { ProgressView(); Text(busy).font(.callout) } }
                if let message { Text(message).font(.caption).foregroundStyle(failed ? Color.orange : Color.secondary) }
            } footer: {
                Text("A folder, a .zip, .7z or .rar, or a .tar.gz, .tar.xz, .tar.zst or .wcp package. Madeira copies the 64-bit DLLs only (x64 or ARM64EC); ARM64EC runs natively, x64 runs emulated. Builds without Madeira's Vulkan-on-Metal patches may refuse the GPU: the game's log names the reason. Changes apply at the next game start.")
            }
        }
        .navigationTitle(only.map { "\($0.title) versions" } ?? "Graphics versions")
        .navigationBarTitleDisplayMode(.inline)
        .fileImporter(isPresented: $importing, allowedContentTypes: [.folder, .item]) { result in
            switch result {
            case .success(let url): runImport(url)
            case .failure(let error): message = error.localizedDescription; failed = true
            }
        }
        .onAppear(perform: reload)
    }
}
