// SPDX-License-Identifier: GPL-3.0-or-later
// Madeira Converter Exception: see LICENSE-EXCEPTION.md

import SwiftUI
import UIKit
import Combine

// "Does it run?": a status label per game and per device (iPhone / iPad), and the console
// look's Library as a grid of covers (Cameron's go, Nov 21 2026; mockups run-badge-grid).
//
//   env.MADEIRA_RUN_BADGE = 0       no status label, no corner marks, no "Why this rating"
//   env.MADEIRA_GRID_LIBRARY = 0    the Library is the rail and stage again (FluxLook.swift),
//                                   and the tab is called "Stores" again
//   env.MADEIRA_PRESS_TO_PLAY = 0   a tap on a cover picks it (a second tap opens its page),
//                                   Y is Search, X plays: the rail's buttons
//
// The ratings come from run-status.json, bundled with the app and written on the PC by
// scripts/make-run-status.py from our own records. Only proven results are in it; a game
// with none is "Not tested yet". Each tier has its own symbol and word, never colour alone
// (Apple rulebook 4.2). Apple's "badge" is the red count bubble, so the code calls this a
// status label.

// MARK: - Switches and settings

enum RunBadge {
    static let enabled = MadeiraConfig.flag("MADEIRA_RUN_BADGE")
    /// Settings › Appearance › Run marks on covers.
    static let marksKey = "madeiraRunMarks"
    /// Settings › Appearance › Run mark size: 0 small, 1 medium, 2 large.
    static let markSizeKey = "madeiraRunMarkSize"
    /// The game page should open "Why this rating" once it is up (a cover's context menu).
    static var autoWhy: UUID?
    /// The game page should open Get Help once it is up (a cover's context menu).
    static var autoHelp: UUID?
}

enum GridLibrary {
    static let enabled = MadeiraConfig.flag("MADEIRA_GRID_LIBRARY")
    /// Settings › Appearance › Games per row: 0 = automatic (the device's default), else 3-6.
    static let perRowKey = "madeiraGridPerRow"
    /// The store filter over the grid, kept between visits.
    static let filterKey = "madeiraGridFilter"

    /// Covers across: the setting, else iPhone sideways 4, upright 3; iPad sideways 6,
    /// upright 4; one more for Small covers and one fewer for Large (Appearance › Cover size).
    static func columns(perRow: Int, coverStep: Int, pad: Bool, sideways: Bool) -> Int {
        if (3...6).contains(perRow) { return perRow }
        let base = pad ? (sideways ? 6 : 4) : (sideways ? 4 : 3)
        return min(6, max(3, base + (coverStep == 0 ? 1 : coverStep == 2 ? -1 : 0)))
    }
}

enum PressToPlay {
    /// Only with the grid: the rail keeps its own buttons.
    static var enabled: Bool { GridLibrary.enabled && MadeiraConfig.flag("MADEIRA_PRESS_TO_PLAY") }
}

// MARK: - Tiers

enum RunTier: String, Codable, CaseIterable {
    case runsWell, runsWithFixes, runsWithProblems, startsOnly, doesntRun, notTested

    var word: String {
        switch self {
        case .runsWell: return L("Runs well")
        case .runsWithFixes: return L("Runs with fixes")
        case .runsWithProblems: return L("Runs with problems")
        case .startsOnly: return L("Starts only")
        case .doesntRun: return L("Doesn't run")
        case .notTested: return L("Not tested yet")
        }
    }
    var meaning: String {
        switch self {
        case .runsWell: return L("Worked when tested.")
        case .runsWithFixes: return L("Worked when tested, with fix lines (Known fix lines, below, says which Madeira adds and which you add by hand).")
        case .runsWithProblems: return L("Got in game when tested, but crashed, had slow parts or missing sound or video.")
        case .startsOnly: return L("Opened when tested, but stopped before you could really play.")
        case .doesntRun: return L("Did not open when tested.")
        case .notTested: return L("No proven result yet. Madeira never guesses a rating.")
        }
    }
    var symbol: String {
        switch self {
        case .runsWell: return "checkmark.circle.fill"
        case .runsWithFixes: return "wrench.and.screwdriver.fill"
        case .runsWithProblems: return "exclamationmark.triangle.fill"
        case .startsOnly: return "pause.circle.fill"
        case .doesntRun: return "xmark.octagon.fill"
        case .notTested: return "questionmark.circle.dashed"
        }
    }
    var color: Color {
        switch self {
        case .runsWell: return .green
        case .runsWithFixes: return .cyan
        case .runsWithProblems: return .yellow
        case .startsOnly: return .orange
        case .doesntRun: return .red
        case .notTested: return .gray
        }
    }
    static let retestSymbol = "arrow.triangle.2.circlepath"
}

// MARK: - Data (run-status.json)

struct RunStatusFile: Decodable {
    struct Result: Decodable {
        /// "iPhone", "iPad" or "unknown" (the record did not say).
        let device: String
        let tier: RunTier
        /// The build it was tested on ("0.2.78", "Wave 5", "build 67").
        let build: String
        let summary: String
        /// Where the proof is (a record and line), for the PC side; not shown.
        var source: String? = nil
    }
    struct Game: Decodable {
        /// "steam:<app id>", "exe:<file name, lower case>", "title:<title, lower case>".
        let keys: [String]
        let title: String
        let results: [Result]
        var lastGood: String? = nil
        var firstGood: String? = nil
        var retest: Bool? = nil
        /// With retest: the build its newest result is from. The words (and "latest", this app's
        /// own build) are put together at run time (RunStatusStore.retestReason).
        var retestBuild: String? = nil
        /// Fix lines the player adds to the game's own config by hand (Madeira does not add them).
        var handLines: [String]? = nil
        /// Sentry crash counts in words, when the generator had them.
        var sentry: String? = nil
        /// Get Help reports from all players in words, when the generator had them.
        var reports: String? = nil
    }
    let version: Int
    let generated: String
    let newestBuild: String
    let games: [Game]
}

/// The rating Madeira shows for one game on this device.
struct RunStatus {
    let tier: RunTier
    /// The result it comes from (nil: Not tested yet).
    let result: RunStatusFile.Result?
    let game: RunStatusFile.Game?
    /// The result is from the other kind of device (none for this one).
    let otherDevice: Bool
    var retest: Bool { tier != .notTested && game?.retest == true }

    static let notTested = RunStatus(tier: .notTested, result: nil, game: nil, otherDevice: false)
}

enum RunStatusStore {
    /// Read once, at first use. A missing or broken file: every game is Not tested yet.
    static let file: RunStatusFile? = {
        guard let url = Bundle.main.url(forResource: "run-status", withExtension: "json"),
              let data = try? Data(contentsOf: url) else {
            LogStore.shared.log("[run-badge] run-status.json missing: every game is Not tested yet")
            return nil
        }
        do {
            let file = try JSONDecoder().decode(RunStatusFile.self, from: data)
            LogStore.shared.log("[run-badge] \(file.games.count) games rated (data \(file.generated), newest build \(file.newestBuild))")
            return file
        } catch {
            LogStore.shared.log("[run-badge] run-status.json unreadable: \(error)")
            return nil
        }
    }()

    private static let index: [String: RunStatusFile.Game] = {
        var map: [String: RunStatusFile.Game] = [:]
        for game in file?.games ?? [] { for key in game.keys { map[key.lowercased()] = game } }
        return map
    }()

    static var thisDevice: String { UIDevice.current.userInterfaceIdiom == .pad ? "iPad" : "iPhone" }

    /// This app's own build, read at run time: "0.2.84" from the stamp "Madeira Nightly 0.2.84 · 11-22 00:30"
    /// (or "v0.2.0 (5)"); a stamp with no version number is shown as it is, without its time.
    static let runningBuild: String = {
        let stamp = BuildStamp.text
        if let range = stamp.range(of: #"\d+\.\d+\.\d+"#, options: .regularExpression) { return String(stamp[range]) }
        return stamp.components(separatedBy: " · ").first ?? stamp
    }()

    /// Why Retest shows: the tested build from the data, "latest" from this app.
    static func retestReason(_ status: RunStatus) -> String {
        String(format: L("Tested on %@. Newer builds changed Wine or FEX, which every game uses (latest: %@). Retest suggested."),
               status.game?.retestBuild ?? status.result?.build ?? "?", runningBuild)
    }

    /// The fix lines behind a rating: how many Madeira's own list for the game adds
    /// (GameRecommendations.swift), and the lines the player adds by hand (run-status.json).
    static func fixLines(_ entry: LibraryEntry, _ status: RunStatus) -> (added: Int, byHand: [String]) {
        var added = 0
        // The standard list and the engine presets only carry the standard line: not a fix for this game.
        if let rec = GameRecommendations.recommendation(for: entry), rec.id != GameRecommendations.standard.id,
           !rec.id.hasPrefix("engine-") {
            added = rec.config.split(separator: "\n").filter {
                let line = $0.trimmingCharacters(in: .whitespaces)
                return !line.isEmpty && !line.hasPrefix("#")
            }.count
        }
        return (added, status.game?.handLines ?? [])
    }

    /// The game's keys, most exact first: its Steam app id, its program's file name, its title.
    static func keys(_ entry: LibraryEntry) -> [String] {
        var keys: [String] = []
        // Only the Steam app the game is installed from: steamID is also set when "Find on Steam"
        // picked cover art for a game from another store.
        if let id = entry.steamAppID { keys.append("steam:\(id)") }
        let exe = (entry.relativePath as NSString).lastPathComponent.lowercased()
        if exe.hasSuffix(".exe") { keys.append("exe:" + exe) }
        // Titles only for games from outside Steam: a Steam copy is rated by its app id alone
        // (a title record is another store's copy, such as Satisfactory from Epic).
        if entry.steamAppID == nil {
            keys.append("title:" + entry.title.lowercased().trimmingCharacters(in: .whitespaces))
        }
        return keys
    }

    static func status(_ entry: LibraryEntry) -> RunStatus {
        guard RunBadge.enabled, entry.desktop != true,
              let game = keys(entry).lazy.compactMap({ index[$0] }).first else { return .notTested }
        // This device's newest result; else a result whose device was not recorded; else the other device's.
        if let mine = game.results.last(where: { $0.device == thisDevice }) {
            return RunStatus(tier: mine.tier, result: mine, game: game, otherDevice: false)
        }
        if let any = game.results.last(where: { $0.device == "unknown" }) {
            return RunStatus(tier: any.tier, result: any, game: game, otherDevice: false)
        }
        if let other = game.results.last {
            return RunStatus(tier: other.tier, result: other, game: game, otherDevice: true)
        }
        return .notTested
    }
}

// MARK: - Pill (game page) and mark (covers)

/// Under the game's name: the tier's symbol and word, and Retest when a newer build changed
/// something the game uses. A tap (or Y anywhere on the page) opens "Why this rating".
struct RunStatusPill: View {
    let entry: LibraryEntry
    /// Its id for the controller's highlight (the Library's header and the game page each have one).
    var padID = "gp-run-status"
    /// False: no controller item (the Steam store sheet, whose layer takes A as Install while it
    /// has no items; Y opens "Why this rating" there instead).
    var pad = true
    let why: () -> Void
    var body: some View {
        let status = RunStatusStore.status(entry)
        Button(action: why) {
            HStack(spacing: 6) {
                Image(systemName: status.tier.symbol).foregroundStyle(status.tier.color)
                Text(status.tier.word).fontWeight(.semibold)
                if let result = status.result, result.device != "unknown" {
                    Text("· " + L(result.device)).foregroundStyle(.secondary)
                }
                if status.retest {
                    Image(systemName: RunTier.retestSymbol).foregroundStyle(.yellow)
                        .accessibilityLabel(L("Retest suggested"))
                }
            }
            .font(.subheadline)
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(.ultraThinMaterial, in: Capsule())
            .overlay(Capsule().strokeBorder(Color.primary.opacity(0.12), lineWidth: 0.5))
            // A 44 pt tap area around the small pill (Apple rulebook 9.1).
            .frame(minWidth: 44, minHeight: 44)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(status.tier.word + ". " + L("Why this rating"))
        .accessibilityValue(status.retest ? L("Retest suggested") : "")
        .accessibilityHint(L("Shows why this game has this rating"))
        .padItem(padID, when: pad, capsule: true, press: why)
    }
}

/// A cover's corner mark: the tier's symbol on a dark disc. It follows Dynamic Type and
/// Appearance › Run mark size; it is not a tap target (the cover is).
struct RunStatusMark: View {
    let status: RunStatus
    @AppStorage(RunBadge.markSizeKey) private var sizeStep = 0
    @ScaledMetric(relativeTo: .caption) private var base: CGFloat = 15
    var body: some View {
        // (stock-apple-stage3) Smaller marks, the symbol drawn at a fixed share of its disc and centered
        // in it (a resized ".circle.fill" symbol filled the disc edge to edge, off its middle).
        let steps: [CGFloat] = StockApple.stage3 ? [0.8, 1.05, 1.35] : [1, 1.3, 1.7]
        let size = base * steps[min(2, max(0, sizeStep))]
        ZStack {
            Circle().fill(.black.opacity(0.55))
            if StockApple.stage3 {
                Image(systemName: status.tier.symbol)
                    .font(.system(size: size * 0.62, weight: .semibold))
                    .foregroundStyle(status.tier.color)
                    .frame(width: size, height: size, alignment: .center)
            } else {
                Image(systemName: status.tier.symbol)
                    .resizable().scaledToFit()
                    .foregroundStyle(status.tier.color)
                    .padding(size * 0.12)
            }
        }
        .frame(width: size, height: size)
        .overlay(alignment: .bottomTrailing) {
            if status.retest {
                Image(systemName: RunTier.retestSymbol).font(.system(size: size * 0.45, weight: .bold))
                    .foregroundStyle(.yellow)
                    .background(Circle().fill(.black.opacity(0.7)).padding(-1))
                    .offset(x: size * 0.2, y: size * 0.2)
            }
        }
        .accessibilityHidden(true)
    }
}

// MARK: - Why this rating

/// The sources behind a game's rating, each with what data exists for it (none is said in
/// words, never left out). B closes it (padSheet).
struct RunStatusWhySheet: View {
    let entry: LibraryEntry
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            RunStatusWhyList(entry: entry)
            .navigationTitle(L("Why this rating"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(L("Done")) { dismiss() }.padItem("why-done", capsule: true) { dismiss() }
                }
            }
        }
        .presentationDetents([.medium, .large])
        .padSheet()
    }
}

/// (stock-apple-stage3) "Why this rating" as a page pushed over the game's page: the sheet's
/// list, Back (or B, or a swipe from the edge) returns to the rating row. The Steam store
/// sheet's pill keeps the sheet. Off (env.MADEIRA_WHY_PAGE = 0): the sheet, as in 0.2.88.
struct RunStatusWhyPage: View {
    let entry: LibraryEntry
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        RunStatusWhyList(entry: entry, padTop: true)
            .navigationTitle(L("Why this rating"))
            .navigationBarTitleDisplayMode(.inline)
            .padNoSystemFocus()
            // Its own controller layer: B goes back to the game page, where the highlight returns
            // to the rating row (the layer under it kept its place: PadLayerKeep).
            .modifier(FluxPageLayer(name: "why-page", embedded: false, back: { dismiss() }))
    }
}

/// The rating's sources: the sheet's and the page's content.
struct RunStatusWhyList: View {
    let entry: LibraryEntry
    /// The page: the top row is a controller item, so the highlight has somewhere to be (the
    /// sheet has its Done button).
    var padTop = false
    var body: some View {
        let status = RunStatusStore.status(entry)
            List {
                Section {
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: status.tier.symbol).font(.title).foregroundStyle(status.tier.color)
                        VStack(alignment: .leading, spacing: 4) {
                            // The game's name, so the sheet always says which game it is about.
                            Text(entry.title).font(.headline)
                            Text(status.tier.word).font(.title3.bold())
                            Text(subtitle(status)).font(.subheadline).foregroundStyle(.secondary)
                            Text(status.tier.meaning).font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityElement(children: .combine)
                    .padItem("why-top", cornerRadius: 12, when: padTop, inset: -6) {}
                    if status.retest {
                        Label {
                            Text(RunStatusStore.retestReason(status))
                        } icon: {
                            Image(systemName: RunTier.retestSymbol).foregroundStyle(.yellow)
                        }
                        .font(.subheadline)
                    }
                }
                Section {
                    row(L("Device tests"), deviceTests(status), ok: status.result != nil)
                    row(L("Regression timeline"), timeline(status), ok: status.game?.lastGood != nil)
                    row(L("Build changes since"), changes(status), ok: status.game?.retest != nil)
                    row(L("Get Help reports"), reports(status), ok: status.game?.reports != nil || GetHelp.reported[entry.windowsPath] != nil)
                    row(L("Sentry crashes"), status.game?.sentry ?? L("No data in the app yet"), ok: status.game?.sentry != nil)
                    row(L("Known fix lines"), fixLines(status), ok: true)
                } header: { Text(L("Where this comes from")) } footer: {
                    Text(L("The rating only uses proven results. No proof means Not tested yet."))
                }
            }
        .onAppear {
            let keys = RunStatusStore.keys(entry).joined(separator: ",")
            LogStore.shared.log("[run-badge] why sheet: \(entry.title) [\(keys)] = \(status.tier.rawValue) from \(status.game?.title ?? "no entry")")
        }
    }

    private func subtitle(_ status: RunStatus) -> String {
        guard let result = status.result else { return L("No result for this game yet") }
        let device = result.device == "unknown" ? L("device not recorded") : String(format: L("On %@"), L(result.device))
        return device + " · " + String(format: L("tested on %@"), result.build)
            + (status.otherDevice ? " · " + String(format: L("not tested on this %@ yet"), L(RunStatusStore.thisDevice)) : "")
    }
    private func deviceTests(_ status: RunStatus) -> String {
        guard let result = status.result else { return L("None yet") }
        return result.summary
    }
    private func timeline(_ status: RunStatus) -> String {
        switch (status.game?.lastGood, status.game?.firstGood) {
        case let (last?, first?): return String(format: L("Last good: %@ · first good: %@"), last, first)
        case let (last?, nil): return String(format: L("Last good: %@"), last)
        case let (nil, first?): return String(format: L("First good: %@"), first)
        default: return L("No data yet")
        }
    }
    private func changes(_ status: RunStatus) -> String {
        guard let retest = status.game?.retest else { return L("No data yet") }
        guard retest else {
            let upTo = RunStatusStore.file?.newestBuild ?? "?"
            let said = String(format: L("Nothing it uses changed up to %@"), upTo)
            // The data can be older than this app: say so rather than claim a build it never looked at.
            return upTo == RunStatusStore.runningBuild ? said : said + " · " + String(format: L("this app is %@"), RunStatusStore.runningBuild)
        }
        return RunStatusStore.retestReason(status)
    }
    private func reports(_ status: RunStatus) -> String {
        var parts: [String] = []
        if let all = status.game?.reports { parts.append(all) }
        if GetHelp.enabled, let mine = GetHelp.reported[entry.windowsPath] {
            parts.append(mine.asked ? L("You sent a report") : L("You sent a report; \"Does it work now?\" not asked yet"))
        }
        return parts.isEmpty ? L("No data in the app yet") : parts.joined(separator: " · ")
    }
    /// The lines Madeira's own list adds for this game (GameRecommendations.swift) and the lines
    /// the player adds by hand. "None for this game" never stands beside "Runs with fixes".
    private func fixLines(_ status: RunStatus) -> String {
        let lines = RunStatusStore.fixLines(entry, status)
        var parts: [String] = []
        if lines.added > 0 { parts.append(String(format: L("%d lines added for you"), lines.added)) }
        if !lines.byHand.isEmpty { parts.append(String(format: L("Add by hand: %@"), lines.byHand.joined(separator: "; "))) }
        if !parts.isEmpty { return parts.joined(separator: " · ") }
        // The data says it needed fixes, but none reach this copy (another store's copy, say).
        return status.tier == .runsWithFixes ? L("Not in the app yet: see Device tests") : L("None for this game")
    }
    private func row(_ title: String, _ value: String, ok: Bool) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(title)
            Spacer(minLength: 8)
            Text(value).font(.footnote).foregroundStyle(ok ? .primary : .secondary).multilineTextAlignment(.trailing)
        }
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Library grid

/// The console look's Library as a grid: the selected game's art behind, on a wide page a
/// short header (its name, Play, Edit and status label), store filters, and covers that fill
/// the width. Replaces the rail (FluxHomePage) while env.MADEIRA_GRID_LIBRARY is on.
struct FluxGridPage: View {
    let games: [LibraryReadyGame]
    let enableJIT: () -> Void
    let open: (LibraryEntry) -> Void
    let play: (LibraryEntry) -> Void
    var refresh: (() async -> Void)? = nil
    var top = 0
    @State private var pickedID: String?
    @AppStorage(GridLibrary.filterKey) private var filterRaw = StoreFilter.all.rawValue
    @AppStorage(GridLibrary.perRowKey) private var perRow = 0
    @AppStorage(NewLook.coverWidthKey) private var coverWidth: Double = 104
    @AppStorage(RunBadge.marksKey) private var marks = true
    /// (stock-apple-stage3) Settings › Appearance › Game art behind pages.
    @AppStorage(StockApple.artKey) private var artSetting = true
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.newLookHintsInset) private var hintsInset

    enum StoreFilter: String, CaseIterable {
        case all, steam, epic, gog, other
        var name: String {
            switch self {
            case .all: return L("All")
            case .steam: return "Steam"
            case .epic: return "Epic"
            case .gog: return "GOG"
            case .other: return L("Other")
            }
        }
        func keeps(_ game: LibraryReadyGame) -> Bool {
            switch self {
            case .all: return true
            case .steam: return game.id.hasPrefix("steam:")
            case .epic: return game.id.hasPrefix("epic:")
            case .gog: return game.id.hasPrefix("gog:")
            case .other: return !(game.id.hasPrefix("steam:") || game.id.hasPrefix("epic:") || game.id.hasPrefix("gog:"))
            }
        }
    }

    private var filter: StoreFilter { StoreFilter(rawValue: filterRaw) ?? .all }
    /// (stock-apple-stage2) The game played last, big, with Play and Game Page, over the grid: the
    /// classic Library's top card (NewLookBanner), which the grid left out on iPhone since 0.2.84
    /// (Cameron, Nov 22: "it doesn't show last played"). iPhone, under All, once a game was played;
    /// an iPad keeps the picked game's header instead. Its game is not in the grid too (Nov 11).
    private var banner: LibraryReadyGame? {
        guard StockApple.stage2, filter == .all, UIDevice.current.userInterfaceIdiom != .pad,
              let first = games.first, first.played != nil else { return nil }
        return first
    }
    private var shown: [LibraryReadyGame] {
        let kept = games.filter(filter.keeps)
        guard let banner else { return kept }
        return kept.filter { $0.id != banner.id }
    }
    private var picked: LibraryReadyGame? { shown.first { $0.id == pickedID } ?? shown.first }

    var body: some View {
        GeometryReader { geo in
            let pad = UIDevice.current.userInterfaceIdiom == .pad
            let sideways = geo.size.width > geo.size.height
            let columns = GridLibrary.columns(perRow: perRow, coverStep: NewLook.coverStep(coverWidth), pad: pad, sideways: sideways)
            let side: CGFloat = pad ? 28 : 16
            let art = StockApple.on && StockArt.shows(artSetting)
            ZStack(alignment: .topLeading) {
                // (stock-apple) Apple's plain background: no game art behind the page.
                if !StockApple.on, let game = picked { backdrop(game) }
                // (stock-apple-stage3) The last played (iPhone) or picked (iPad) game's art behind the
                // title, the filter and the header, fading to black.
                if art { StockArtBackdrop(entry: (banner ?? picked)?.entry, height: pad ? 460 : 400) }
                ScrollViewReader { reader in
                    ScrollView(.vertical, showsIndicators: false) {
                        VStack(alignment: .leading, spacing: 14) {
                            // The short art header: a wide page only (an iPhone shows the art behind alone).
                            if StockApple.on {
                                // (stock-apple) JIT and Memory+ take their own row, then Apple's large title and a
                                // segmented control. In 0.2.84 the pills floated over the page at the chips' height
                                // on iPhone (FluxGridPage's ZStack), so they covered the filters.
                                // (stock-apple-stage3) JIT and Memory+ are the bolt in the bar instead.
                                if !StockApple.jitBolt {
                                    NewLookStatusPill(enableJIT: enableJIT)
                                        .frame(maxWidth: .infinity, alignment: .trailing)
                                        .id("pad-top")
                                }
                                Text(L("Library")).font(.largeTitle.bold()).accessibilityAddTraits(.isHeader)
                                    .id(StockApple.jitBolt ? "pad-top" : "library-title")
                                if StockApple.stage2, !games.isEmpty {
                                    // (stock-apple-stage2) The classic Library's count line.
                                    Text(games.count == 1 ? L("1 game · last played first")
                                         : String(format: L("%@ games · last played first"), String(games.count)))
                                        .font(.subheadline).foregroundStyle(.secondary)
                                }
                                stockFilter
                                if let game = banner {
                                    // A game with no Steam art keeps the card (its blurred cover and whole-card tap: review finding 11).
                                    if art, FluxLook.hasHero(game.entry) {
                                        // (stock-apple-stage3) The card becomes the art header's text and buttons.
                                        StockArtHeader(game: game, play: { play(game.entry) }, open: { open(game.entry) })
                                    } else {
                                        NewLookBanner(game: game, wide: false, play: { play(game.entry) }, open: { open(game.entry) })
                                    }
                                }
                                // A wide page keeps the picked game's short header (name, rating pill, Play,
                                // Game Page) under the filter, on the plain background.
                                if pad, let game = picked { header(game) }
                            } else {
                                if pad, let game = picked { header(game).padding(.top, sideways ? 40 : 90).id("pad-top") }
                                chips
                            }
                            if shown.isEmpty {
                                // A saved filter for a store with no installed games (finding 6).
                                Text(filter == .other ? L("No games from other stores installed. Pick All to see every game.")
                                     : String(format: L("No %@ games installed. Pick All to see every game."), filter.name))
                                    .font(.subheadline).foregroundStyle(.secondary).padding(.top, 8)
                            }
                            grid(columns: columns)
                        }
                        .padding(.horizontal, side)
                        .padding(.top, pad ? 0 : 8)
                        .padding(.bottom, 16 + hintsInset)
                    }
                    .modifier(FluxGridRefresh(refresh: refresh))
                    .padScrollFollow(reader)
                    .onChange(of: top) { _, _ in
                        pickedID = nil
                        // (stock-apple-stage2) The tab tapped again: back to the very top, with the last played card.
                        if banner != nil {
                            withAnimation(reduceMotion ? nil : .default) { reader.scrollTo("pad-top", anchor: .top) }
                        } else if let first = shown.first {
                            withAnimation(reduceMotion ? nil : .default) { reader.scrollTo(first.padID, anchor: .top) }
                        }
                    }
                }
                if !StockApple.on {
                    NewLookStatusPill(enableJIT: enableJIT)
                        .padding(.trailing, side).padding(.top, 8)
                        .frame(maxWidth: .infinity, alignment: .trailing)
                }
            }
            .onAppear { PadHighlight.shared.setGrid("library", ids: shown.map(\.padID), columns: columns) }
            .onChange(of: shown.map(\.padID)) { _, ids in PadHighlight.shared.setGrid("library", ids: ids, columns: columns) }
            .onChange(of: columns) { _, new in PadHighlight.shared.setGrid("library", ids: shown.map(\.padID), columns: new) }
            // (stock-apple-stage3) Over the art the page is dark, so its text is white on black.
            .modifier(StockArtScheme(on: art))
        }
        .toolbar {
            // (stock-apple-stage3) JIT and Memory+ as one button in the bar (the "+" is on the other side).
            if StockApple.jitBolt {
                ToolbarItem(placement: .topBarLeading) { StockJITBolt(enableJIT: enableJIT) }
            }
        }
        .onDisappear { PadHighlight.shared.removeGrid("library") }
        // Back on the Library: a hand-off to a game page that never opened is dropped, so it
        // cannot pop up on a later visit.
        .onAppear { RunBadge.autoWhy = nil; RunBadge.autoHelp = nil }
        // The highlight on a cover selects it (its art goes behind the page).
        .onReceive(PadHighlight.shared.$focus.combineLatest(PadHighlight.shared.$shown)
            .map { focus, shown in shown ? focus : nil }.removeDuplicates()) { focus in
            guard let focus, focus.hasPrefix("g-") else { return }
            let id = String(focus.dropFirst(2))
            if id != pickedID, games.contains(where: { $0.id == id }) { pick(id) }
        }
        .onChange(of: games.map(\.id)) { _, ids in
            if let pickedID, !ids.contains(pickedID) { self.pickedID = nil }
        }
    }

    private func pick(_ id: String) {
        withAnimation(reduceMotion ? nil : .easeOut(duration: 0.2)) { pickedID = id }
    }

    /// X: the next store filter.
    private func nextFilter() { setFilter(padNext(StoreFilter.allCases, after: filter)) }

    /// A filter picked (a chip, or X): the highlight goes to its first cover, so the next X or
    /// A still has a cover (the highlighted one may be gone from the new filter); with no cover,
    /// to the chip itself.
    private func setFilter(_ new: StoreFilter, follow: Bool = true) {
        filterRaw = new.rawValue
        LogStore.shared.log("[grid-library] filter \(new.rawValue)")
        guard follow, PadHighlight.enabled, PadHighlight.shared.shown else { return }
        // (stock-apple-stage2) The first cover the grid shows: under All the last played game is the
        // card over the grid, not a cover, so its Play when nothing else is there.
        let first = StockApple.stage2 ? shown.first : games.first(where: new.keeps)
        let none = StockApple.stage2 && banner != nil ? "banner-play" : (StockApple.on ? "gr-filter" : "gr-chip-" + new.rawValue)
        PadHighlight.shared.move(to: first?.padID ?? none, scroll: true)
    }

    /// The selected game's art over the whole page, darkening towards the covers so their
    /// names and the header read on any art (Apple rulebook 9.68).
    private func backdrop(_ game: LibraryReadyGame) -> some View {
        let background = Color(uiColor: .systemBackground)
        return ZStack {
            background
            LibraryArtwork(entry: game.entry, backdrop: true)
                .blur(radius: FluxLook.hasHero(game.entry) ? 0 : 30)
                .id(game.id)
                .transition(.opacity)
            LinearGradient(colors: [background.opacity(0.35), background.opacity(0.75), background.opacity(0.95)],
                           startPoint: .top, endPoint: .bottom)
            LinearGradient(colors: [background.opacity(0.6), .clear], startPoint: .top, endPoint: UnitPoint(x: 0.5, y: 0.18))
        }
        .clipped()
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }

    private func header(_ game: LibraryReadyGame) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            // (stock-apple) A title, not a second large title under "Library".
            Text(game.entry.title).font(StockApple.on ? .title2.bold() : .largeTitle.weight(.heavy)).lineLimit(2).minimumScaleFactor(0.6)
                .accessibilityAddTraits(.isHeader)
            HStack(spacing: 8) {
                Text(game.note).font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
                if RunBadge.enabled {
                    // Its "Why this rating" is on the game's page.
                    RunStatusPill(entry: game.entry, padID: "gr-run-status") { RunBadge.autoWhy = game.entry.id; open(game.entry) }
                }
            }
            HStack(spacing: 12) {
                Button { play(game.entry) } label: {
                    Label("Play", systemImage: "play.fill").fontWeight(.semibold).padding(.horizontal, 8)
                }
                .modifier(LookPlayStyle(overArt: true))
                Button { open(game.entry) } label: { Text(StockApple.on ? L("Game Page") : L("Edit")).fontWeight(.semibold) }
                    .modifier(FluxSecondButtonStyle())
            }
        }
        .dynamicTypeSize(...DynamicTypeSize.accessibility1)
    }

    /// (stock-apple) The store filter as Apple's segmented control. The controller: D-pad left / right
    /// change the store and the highlight stays on the control; A and X step to the next store.
    private var stockFilter: some View {
        Picker(L("Store"), selection: Binding(get: { filter }, set: { setFilter($0, follow: false) })) {
            ForEach(StoreFilter.allCases, id: \.self) { Text($0.name).tag($0) }
        }
        .pickerStyle(.segmented)
        .frame(maxWidth: 520)
        .padItem("gr-filter", cornerRadius: 9, play: { setFilter(padNext(StoreFilter.allCases, after: filter), follow: false) },
                 adjust: { by in setFilter(padStep(StoreFilter.allCases, from: filter, by: by), follow: false) }) {
            setFilter(padNext(StoreFilter.allCases, after: filter), follow: false)
        }
    }

    private var chips: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(StoreFilter.allCases, id: \.self) { store in
                    let on = store == filter
                    Button { setFilter(store) } label: {
                        Text(store.name).font(.subheadline.weight(on ? .semibold : .regular))
                            .padding(.horizontal, 14).frame(minHeight: 36)
                            .background(on ? AnyShapeStyle(Color.primary.opacity(0.22)) : AnyShapeStyle(.ultraThinMaterial), in: Capsule())
                            .frame(minHeight: 44)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(on ? .isSelected : [])
                    .padItem("gr-chip-" + store.rawValue, play: { nextFilter() }, capsule: true) { setFilter(store) }
                }
            }
            .padding(.vertical, 4).padding(.horizontal, 6)
        }
        .accessibilityLabel(L("Store"))
    }

    private func grid(columns: Int) -> some View {
        let spacing: CGFloat = columns >= 6 ? 12 : 16
        let layout = Array(repeating: GridItem(.flexible(), spacing: spacing), count: columns)
        let current = picked?.id
        return LazyVGrid(columns: layout, spacing: spacing) {
            ForEach(shown, id: \.padID) { game in
                let on = game.id == current
                Button {
                    if PressToPlay.enabled { play(game.entry) }
                    else if on { open(game.entry) }
                    else {
                        pick(game.id)
                        if PadHighlight.enabled { PadHighlight.shared.move(to: game.padID, scroll: false) }
                    }
                } label: {
                    FluxGridCover(game: game, on: on, marks: RunBadge.enabled && marks)
                }
                .buttonStyle(LibraryCardButtonStyle())
                // (stock-apple-stage2) Touch and hold lifts the cover with its own rounded corners, not
                // the square around them. Off: no preview shape, as in 0.2.87.
                .modifier(StockApplePreviewShape())
                .contextMenu { menu(game) }
                // A plays; Menu and (press to play) Y open the game's page; X (press to play) changes the filter.
                .padItem(game.padID, cornerRadius: 12, grid: "library",
                         play: PressToPlay.enabled ? { nextFilter() } : { play(game.entry) },
                         menu: { open(game.entry) },
                         alt: PressToPlay.enabled ? { open(game.entry) } : nil) { play(game.entry) }
            }
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder private func menu(_ game: LibraryReadyGame) -> some View {
        Button { play(game.entry) } label: { Label("Play", systemImage: "play.fill") }
        Button { open(game.entry) } label: {
            Label(PressToPlay.enabled && !StockApple.on ? L("Edit game") : L("Game Page"), systemImage: PressToPlay.enabled && !StockApple.on ? "pencil" : "info.circle")
        }
        if PressToPlay.enabled {
            if RunBadge.enabled {
                let status = RunStatusStore.status(game.entry)
                Button { RunBadge.autoWhy = game.entry.id; open(game.entry) } label: {
                    Label(status.tier.word, systemImage: status.tier.symbol)
                }
            }
            if GetHelp.enabled {
                Button { RunBadge.autoHelp = game.entry.id; open(game.entry) } label: {
                    Label(L("Get Help"), systemImage: "questionmark.circle")
                }
            }
        }
    }
}

/// A cover in the grid: its art, its name over the bottom, its run mark in the top corner,
/// and an outline on the selected one.
struct FluxGridCover: View {
    let game: LibraryReadyGame
    let on: Bool
    let marks: Bool
    @Environment(\.libraryCardPressed) private var pressed
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// (stock-apple-stage3) Settings › Appearance › Names on covers; the name stays in VoiceOver's label.
    @AppStorage(StockApple.namesKey) private var names = true
    /// A picture of its own: a chosen cover, a Steam match, or a store cover the cache knows.
    private var hasArt: Bool {
        game.entry.coverFile != nil || (game.entry.steamID ?? game.entry.steamAppID) != nil
            || LibraryCoverCache.Source.entry(game.entry) != nil
    }
    var body: some View {
        let status = marks ? RunStatusStore.status(game.entry) : .notTested
        LibraryArtwork(entry: game.entry).aspectRatio(2.0 / 3.0, contentMode: .fit)
            .overlay(alignment: .bottomLeading) {
                // A cover with no picture (the glyph only) keeps its name, or covers look alike (review finding 10).
                if names || !StockApple.stage3 || !hasArt {
                    Text(game.entry.title).font(.subheadline.weight(.semibold)).foregroundStyle(.white)
                        .lineLimit(2).minimumScaleFactor(0.8)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(LinearGradient(colors: [.clear, .black.opacity(0.75)], startPoint: .top, endPoint: .bottom))
                }
            }
            .overlay(alignment: .topTrailing) {
                if marks { RunStatusMark(status: status).padding(6) }
            }
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(on && !StockApple.on ? Color.primary.opacity(0.85) : Color.primary.opacity(0.12), lineWidth: on && !StockApple.on ? 2.5 : 0.5))
            .shadow(color: .black.opacity(0.25), radius: 6, y: 3)
            // (stock-apple-stage2) No shrink on press: touch and hold, the cover shrank while the menu's
            // preview was being taken, then sprang back under it (Cameron, Nov 22: the popup flickers).
            // Apple's own grids have only the menu's lift. Off (env.MADEIRA_STOCK_APPLE_2 = 0): as in 0.2.87.
            .scaleEffect(pressed && !StockApple.stage2 ? 0.95 : 1)
            .animation(reduceMotion ? nil : .spring(response: 0.3, dampingFraction: 0.7), value: pressed)
            .contentShape(Rectangle())
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(game.entry.title)
            .accessibilityValue(marks ? game.note + ", " + status.tier.word : game.note)
            .accessibilityHint(PressToPlay.enabled ? L("Starts the game. Touch and hold for more.")
                               : (on ? L("Opens the game's page") : L("Shows this game")))
            .accessibilityAddTraits(on ? [.isButton, .isSelected] : .isButton)
    }
}

/// (stock-apple-stage2) The cover's rounded corners for touch and hold's lifted preview.
private struct StockApplePreviewShape: ViewModifier {
    @ViewBuilder func body(content: Content) -> some View {
        if StockApple.stage2 {
            content.contentShape(.contextMenuPreview, RoundedRectangle(cornerRadius: 12, style: .continuous))
        } else {
            content
        }
    }
}

private struct FluxGridRefresh: ViewModifier {
    let refresh: (() async -> Void)?
    @ViewBuilder func body(content: Content) -> some View {
        if let refresh { content.refreshable { await refresh() } } else { content }
    }
}

// MARK: - Settings › Appearance

/// Games per row, Run marks on covers and Run mark size (Cover size is the Library's own row).
struct RunGridAppearanceRows: View {
    @AppStorage(GridLibrary.perRowKey) private var perRow = 0
    @AppStorage(RunBadge.marksKey) private var marks = true
    @AppStorage(RunBadge.markSizeKey) private var markSize = 0
    @AppStorage(FluxLook.key) private var consoleLook = true
    @AppStorage(StockApple.namesKey) private var names = true
    var body: some View {
        // Only where they do something: the console look's grid (finding 7).
        if GridLibrary.enabled, FluxLook.allowed, consoleLook {
            rows
        }
    }
    @ViewBuilder private var rows: some View {
        Picker(L("Games per row"), selection: $perRow) {
            Text(L("Automatic")).tag(0)
            ForEach(3...6, id: \.self) { Text("\($0)").tag($0) }
        }
        .padItem("ap-per-row", cornerRadius: 12) { perRow = padNext([0, 3, 4, 5, 6], after: perRow) }
        // (stock-apple-stage3) The game's name over the bottom of its cover.
        if StockApple.stage3 {
            Toggle(L("Names on covers"), isOn: $names)
                .padToggle("ap-cover-names", $names)
        }
        if RunBadge.enabled {
            Toggle(L("Run marks on covers"), isOn: $marks)
                .padToggle("ap-run-marks", $marks)
            if marks {
                Picker(L("Run mark size"), selection: $markSize) {
                    Text(L("Small")).tag(0)
                    Text(L("Medium")).tag(1)
                    Text(L("Large")).tag(2)
                }
                .padItem("ap-run-mark-size", cornerRadius: 12) { markSize = (markSize + 1) % 3 }
            }
        }
    }
}

// MARK: - Stock Apple stage 3: start

extension StockApple {
    /// Once, as Madeira starts: the stage's log line, and a new install's own Library defaults
    /// (iPhone: 4 covers a row; names off the covers). Never over a value the player set: only a
    /// key that was never written, and only on an install that has never been set up (no setup
    /// revision, no Library look settings, no Wine folder yet).
    @MainActor static func stage3Start() {
        let defaults = UserDefaults.standard
        let seededKey = "madeiraStockApple3Seeded"
        // Switched off later: a 4 a row this stage wrote (and the player never changed) is taken back,
        // so the switch gives 0.2.88's Automatic (review finding 9). Names already show with it off.
        if !stage3, defaults.bool(forKey: seededKey) {
            if defaults.integer(forKey: GridLibrary.perRowKey) == 4 { defaults.removeObject(forKey: GridLibrary.perRowKey) }
            defaults.removeObject(forKey: seededKey)
        }
        guard on else { return }
        var seeded: [String] = []
        if stage3 {
            let fresh = defaults.object(forKey: OnboardingRules.revisionKey) == nil
                && defaults.object(forKey: "madeiraOnboardingDone") == nil
                && defaults.object(forKey: FluxLook.key) == nil
                && defaults.object(forKey: NewLook.coverWidthKey) == nil
                && !FileManager.default.fileExists(atPath: LibraryModel.documents.appendingPathComponent("wine").path)
            if fresh {
                if UIDevice.current.userInterfaceIdiom == .phone, defaults.object(forKey: GridLibrary.perRowKey) == nil {
                    defaults.set(4, forKey: GridLibrary.perRowKey); defaults.set(true, forKey: seededKey); seeded.append("per-row=4")
                }
                // iPhone only, as the 4 a row (review finding 9: the brief's defaults are the iPhone's).
                if UIDevice.current.userInterfaceIdiom == .phone, defaults.object(forKey: namesKey) == nil {
                    defaults.set(false, forKey: namesKey); seeded.append("names=off")
                }
            }
        }
        func word(_ on: Bool) -> String { on ? "1" : "0" }
        LogStore.shared.log("[stock-apple-3] " + (stage3 ? "on" : "off")
                            + " art=\(word(artHeader)) bolt=\(word(jitBolt)) store-list=\(word(storeList)) why-page=\(word(whyPage))"
                            + (seeded.isEmpty ? "" : " new-install " + seeded.joined(separator: ",")))
    }
}

// MARK: - Stock Apple stage 3: game art behind the page

/// (stock-apple-stage3) The game's own Steam art (the hero picture LibraryArtwork's backdrop and
/// the starting screen use), full width at the top of the page, under a dark scrim that fades to
/// black. The scrim is at least 82 % black everywhere, so white text keeps 4.5:1 or more
/// even over white art ((1 + 0.05) / (0.18 + 0.05) = 4.6). No Steam art, Reduce Transparency or
/// the setting off: plain black. Reduce Motion: no fade between games.
struct StockArtBackdrop: View {
    let entry: LibraryEntry?
    var height: CGFloat = 380
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        ZStack(alignment: .top) {
            Color.black
            if !reduceTransparency, let entry, FluxLook.hasHero(entry) {
                LibraryArtwork(entry: entry, backdrop: true)
                    .frame(maxWidth: .infinity).frame(height: height)
                    .clipped()
                    .overlay {
                        // 82 % from the very top: the large title starts right under the bar (review finding 3).
                        LinearGradient(stops: [.init(color: .black.opacity(0.82), location: 0),
                                               .init(color: .black.opacity(0.88), location: 0.7),
                                               .init(color: .black, location: 1)],
                                       startPoint: .top, endPoint: .bottom)
                    }
                    .id(entry.id)
                    .transition(reduceMotion ? .identity : .opacity)
            }
        }
        .ignoresSafeArea()
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// (stock-apple-stage3) A page with the art behind it is dark (white text on the black scrim),
/// its bar too. Off: nothing added.
struct StockArtScheme: ViewModifier {
    let on: Bool
    @ViewBuilder func body(content: Content) -> some View {
        if on {
            content.environment(\.colorScheme, .dark).toolbarColorScheme(.dark, for: .navigationBar)
        } else {
            content
        }
    }
}

/// (stock-apple-stage3) The game page's list over the game's art: the list's own background goes,
/// the art (or black) is behind it, and the page is dark. Off: the list as it was.
struct StockGameArt: ViewModifier {
    let on: Bool
    let entry: LibraryEntry
    var height: CGFloat = 420
    @ViewBuilder func body(content: Content) -> some View {
        if on {
            content
                .scrollContentBackground(.hidden)
                .background { StockArtBackdrop(entry: entry, height: height) }
                .modifier(StockArtScheme(on: true))
        } else {
            content
        }
    }
}

/// (stock-apple-stage3) The art header's switch: the stage, its own switch and the setting.
enum StockArt {
    @MainActor static func shows(_ setting: Bool) -> Bool { StockApple.artHeader && setting }
}

/// (stock-apple-stage3) The iPhone Library's last played game as the art header's own text and
/// buttons (it replaces the card, NewLookBanner): its name, "Steam · Played today", its rating
/// in words, Play (the page's prominent button) and Game Page. The art itself is the page's
/// backdrop (StockArtBackdrop). Same controller items as the card it replaces.
struct StockArtHeader: View {
    let game: LibraryReadyGame
    let play: () -> Void
    let open: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(game.entry.title).font(.title.bold()).lineLimit(2).minimumScaleFactor(0.7)
                    .accessibilityAddTraits(.isHeader)
                Text(game.note).font(.subheadline).foregroundStyle(.white.opacity(0.85)).lineLimit(1)
            }
            .foregroundStyle(.white)
            .accessibilityElement(children: .combine)
            if RunBadge.enabled, game.entry.desktop != true {
                // Its "Why this rating" is on the game's page.
                RunStatusPill(entry: game.entry, padID: "banner-run-status") { RunBadge.autoWhy = game.entry.id; open() }
            }
            HStack(spacing: 12) {
                Button(action: play) {
                    Label("Play", systemImage: "play.fill").fontWeight(.semibold).padding(.horizontal, 8)
                }
                .modifier(LookPlayStyle(overArt: true))
                .padItem("banner-play", capsule: true, press: play)
                Button(action: open) { Text("Game Page").fontWeight(.semibold) }
                    .modifier(FluxSecondButtonStyle())
                    .padItem("banner-open", capsule: true, press: open)
            }
        }
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .dynamicTypeSize(...DynamicTypeSize.accessibility1)
    }
}

// MARK: - Stock Apple stage 3: JIT and Memory+

/// (stock-apple-stage3) JIT and Memory+ as one button in the Library's bar: a bolt, green with
/// JIT on and gray with it off (and said in words to VoiceOver, not by color alone). Its menu:
/// Enable JIT (the pill's action) and Memory+, which only shows how things are: it comes from
/// how this copy of Madeira was signed and cannot be switched here (NewLookStatusPill).
/// The controller: A on it enables JIT (Apple's menus cannot be opened or pressed by the
/// controller here: NewLookPopupLayer); with JIT on there is nothing for A to do.
struct StockJITBolt: View {
    let enableJIT: () -> Void
    @ObservedObject private var jit = LibraryJITState.shared
    @ObservedObject private var starter = NewLookJITStart.shared
    @State private var memory: Bool?
    var body: some View {
        let on = jit.enabled
        let starting = starter.starting && !on
        Menu {
            if on {
                Label(L("JIT is on"), systemImage: "checkmark.circle.fill")
            } else {
                Button { starter.start(enableJIT) } label: {
                    Label(starting ? L("Enabling JIT…") : L("Enable JIT"), systemImage: "bolt.fill")
                }
                .disabled(starting)
            }
            if let memory {
                Label(L("Memory+") + ": " + (memory ? L("On") : L("Off")), systemImage: memory ? "checkmark.circle.fill" : "minus.circle")
            }
        } label: {
            Group {
                if starting { ProgressView() }
                // On and off differ by shape too, not by color alone (review finding 2).
                else { Image(systemName: on ? "bolt.fill" : "bolt.slash.fill").foregroundStyle(on ? Color.green : Color(white: 0.75)) }
            }
            .frame(minWidth: 44, minHeight: 44)
            .contentShape(Rectangle())
        }
        .accessibilityLabel(L("JIT and Memory+"))
        .accessibilityValue((on ? L("JIT on") : L("JIT off")) + (memory.map { ", " + L("Memory+") + " " + ($0 ? L("On") : L("Off")) } ?? ""))
        .padItem("status", capsule: true) { starter.start(enableJIT) }
        .task { memory = EntitlementStatus.check().increasedMemory }
    }
}
