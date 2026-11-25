// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 ft7t8drgwf-wq
// Madeira Converter Exception: see LICENSE-EXCEPTION.md

import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// (auto-test) Test Run: a tester ticks games in Settings > Advanced > Test Run and taps Start. Each game runs
/// for a set time, then the app judges it, quits it, copies the app run's log and one result line to a folder
/// the tester picked once (e.g. iCloud Drive > Madeira Builds), and closes itself. One game per app run is a
/// hard limit (LibraryModel.holdForRestart), so the next game starts in the next app run: an iOS Shortcuts
/// automation "When Madeira is closed > Open Madeira" reopens it, or the tester opens it by hand.
///
/// Hidden and inert until env.MADEIRA_AUTO_TEST = 1 in madeira.cfg. With it off nothing here runs: no row in
/// Settings, a saved run is never resumed, and LogTrail's hook returns at once. Our own design.
///
/// The judge reads only facts gathered during this app run (LogTrail's session for this game and the runner's
/// own frame samples), never log text, so a "Previous run" summary at the top of a log can't count as evidence.
enum AutoTest {
    static var enabled: Bool { MadeiraConfig.flag("MADEIRA_AUTO_TEST", fallback: false) }
    static let minuteChoices = [1, 2, 3, 5]
    /// A saved run older than this is dropped instead of resumed, so a forgotten run never starts a game later.
    static let staleAfter: TimeInterval = 30 * 60
}

// MARK: - Judge (pure, no app state: the host check mirrors it)

enum AutoTestOutcome: String, Codable {
    case pass = "PASS", stuck = "STUCK", froze = "FROZE", crashed = "CRASHED", exited = "EXITED", inconclusive = "INCONCLUSIVE"
}

/// What the runner saw for one game in this app run.
struct AutoTestFacts {
    /// Seconds from Play to "game shown" (LogTrail step), nil if the game's window never showed.
    var shownAt: Double?
    /// JIT was on: the "JIT on" step, a session that began (it can't without JIT), or CS_DEBUGGED now.
    var jitOn: Bool
    /// The session itself began (LogTrail Session.began).
    var began: Bool
    /// Shown presents (madeira_shown_frame_count, the FPS readout's count) in the last 30 s before the judge ran.
    var recentFrames: Int
    /// The game ended before the timer: LogTrail's [game-end] words ("it closed by itself", ...) and code
    /// ("exit code 0 (normal)", "Windows error 0xC0000005", ...). nil while it still runs at the timer.
    var endWhy: String?
    var endCode: String?
    /// Why the session was ended by hand or failed to start (LogTrail Session.reason), nil when it ended by itself.
    var endReason: String?
    /// Madeira was away from the screen for more than 5 s after the game's session began.
    var leftApp: Bool
    /// The session ended because only one-time installers ran and a restart is needed.
    var installsOnly: Bool
}

enum AutoTestJudge {
    static func judge(_ f: AutoTestFacts) -> (AutoTestOutcome, String) {
        if f.leftApp { return (.inconclusive, "Madeira left the screen during the run") }
        if f.installsOnly { return (.inconclusive, "only one-time installers ran") }
        if !f.jitOn { return (.inconclusive, "JIT never turned on") }
        if let reason = f.endReason {
            if reason.hasPrefix("the start failed") { return (.stuck, reason) }
            return (.inconclusive, "ended by hand (\(reason))")
        }
        if let why = f.endWhy {
            let code = f.endCode ?? "exit code not reported"
            if code.hasPrefix("Windows error") || (code.hasPrefix("exit code ") && !code.hasPrefix("exit code 0") && code != "exit code not reported") {
                return (.crashed, "\(why); \(code)")
            }
            // A clean exit (the game's own process; LogTrail.gameChildEnd already looks past a launcher's 0).
            if code.hasPrefix("exit code 0") { return (.exited, f.shownAt == nil ? "closed itself with code 0 before its window showed" : "closed itself with code 0") }
            if f.shownAt == nil { return (.stuck, "\(why); \(code)") }
            return (.inconclusive, "ended after its window showed, no exit code reported")
        }
        // Still running at the timer. Time alone is not play: no window means STUCK.
        guard let shown = f.shownAt else { return (.stuck, f.began ? "no game window" : "the game session never began") }
        if f.recentFrames == 0 { return (.froze, String(format: "shown at %.0f s, no frames in the last 30 s", shown)) }
        return (.pass, String(format: "shown at %.0f s", shown))
    }
}

// MARK: - Saved run

struct AutoTestRun: Codable {
    struct Game: Codable { var id: UUID; var title: String; var windowsPath: String; var retried = false }
    struct Result: Codable { var title: String; var outcome: AutoTestOutcome; var detail: String; var seconds: Int; var log: String? }
    var id: String
    var build: String
    var minutes: Int
    var games: [Game]
    var index = 0
    var results: [Result] = []
    var touched = Date()
    var finished = false
    /// The index of the game launched and not yet written up. Still set at the next app start = Madeira itself
    /// closed during that game (a crash, iOS memory kill): recorded as CRASHED, so the run never loops on it.
    var inFlight: Int?

    private static let key = "madeira.autoTestRun"
    static func load() -> AutoTestRun? {
        guard let data = UserDefaults.standard.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(AutoTestRun.self, from: data)
    }
    func save() { if let data = try? JSONEncoder().encode(self) { UserDefaults.standard.set(data, forKey: Self.key) } }
    static func clear() { UserDefaults.standard.removeObject(forKey: key) }

    static func newID() -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX"); f.calendar = Calendar(identifier: .gregorian)
        f.dateFormat = "yyyy-MM-dd HH-mm"
        return f.string(from: Date())
    }
}

// MARK: - Runner

@MainActor final class AutoTestRunner: ObservableObject {
    static let shared = AutoTestRunner()

    @Published private(set) var run: AutoTestRun?
    /// Seconds left of the game now running (the pill), nil when no game runs for the test.
    @Published private(set) var secondsLeft: Int?
    /// Counting down before the next game starts at an app start, so the tester can stop it.
    @Published var countdown: Int?
    @Published private(set) var folderName: String?

    private var timer: Timer?
    private var countdownTimer: Timer?
    private var started = Date()
    private var samples: [(Date, UInt64)] = []
    private var leftAt: Date?
    private var leftApp = false
    private var judged: (AutoTestOutcome, String)?
    private var wrapping = false

    /// Only created with env.MADEIRA_AUTO_TEST on (AutoTestOverlay and the Settings row check it first).
    private init() {
        run = AutoTestRun.load()
        folderName = Self.readFolderName()
        NotificationCenter.default.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { AutoTestRunner.shared.leftAt = Date() }
        }
        NotificationCenter.default.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated {
                let me = AutoTestRunner.shared
                // Away during Enable JIT (Shortcuts, StikDebug) is part of starting; only time away once the
                // game's session began counts.
                if let at = me.leftAt, Date().timeIntervalSince(at) > 5, me.secondsLeft != nil,
                   LogTrail.autoTestSnapshot().began { me.leftApp = true }
                me.leftAt = nil
            }
        }
    }

    var active: Bool { run.map { !$0.finished } ?? false }

    // MARK: Folder (picked once; a security-scoped bookmark, as ExternalDrives keeps its folders)

    private static let folderKey = "madeira.autoTestFolder"
    private static func readFolderName() -> String? {
        guard let url = resolveFolder() else { return nil }
        defer { url.stopAccessingSecurityScopedResource() }
        return url.lastPathComponent
    }
    func setFolder(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        if let data = try? url.bookmarkData() { UserDefaults.standard.set(data, forKey: Self.folderKey) }
        folderName = Self.readFolderName()
    }
    /// The picked folder with access started (the caller stops it), or nil.
    private static func resolveFolder() -> URL? {
        guard let data = UserDefaults.standard.data(forKey: folderKey) else { return nil }
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: data, bookmarkDataIsStale: &stale),
              url.startAccessingSecurityScopedResource() else { return nil }
        if stale, let fresh = try? url.bookmarkData() { UserDefaults.standard.set(fresh, forKey: folderKey) }
        return url
    }

    // MARK: Start, resume, stop

    func start(_ entries: [LibraryEntry], minutes: Int) {
        guard AutoTest.enabled, !entries.isEmpty, LibraryModel.sessionsThisRun == 0 else { return }
        let r = AutoTestRun(id: AutoTestRun.newID(), build: BuildStamp.text, minutes: minutes,
                            games: entries.map { .init(id: $0.id, title: $0.title, windowsPath: $0.windowsPath) })
        r.save(); run = r
        LogStore.shared.log("[auto-test] run \(r.id) started: \(r.games.count) game(s), \(minutes) min each, build \(r.build)")
        launchCurrent()
    }

    /// Run Again (the finished card): the same games as a new run. A game already ran in this app run, so
    /// Madeira closes and the next app start begins it (the same reopen as between games).
    func runAgain() {
        guard AutoTest.enabled, let old = run else { return }
        var seen = Set<UUID>()
        let games = old.games.filter { seen.insert($0.id).inserted }.map { AutoTestRun.Game(id: $0.id, title: $0.title, windowsPath: $0.windowsPath) }
        let r = AutoTestRun(id: AutoTestRun.newID(), build: BuildStamp.text, minutes: old.minutes, games: games)
        r.save(); run = r
        LogStore.shared.log("[auto-test] run \(r.id) started again (\(games.count) game(s)); closing Madeira so the first one starts fresh")
        if LibraryModel.sessionsThisRun == 0 { launchCurrent() } else { exit(0) }
    }

    /// From the app's first screen: a saved run that is not finished starts its next game after a 5 s countdown.
    func resumeAtAppStart() {
        guard AutoTest.enabled, var r = run, !r.finished else { return }
        guard Date().timeIntervalSince(r.touched) < AutoTest.staleAfter else {
            LogStore.shared.log("[auto-test] run \(r.id) was idle over 30 min: stopped, not resumed")
            r.finished = true; r.inFlight = nil; r.save(); run = r; return
        }
        guard LibraryModel.sessionsThisRun == 0, countdown == nil, secondsLeft == nil else { return }
        // Madeira closed during the last game without writing it up: that game took the app down.
        if let i = r.inFlight, i == r.index, i < r.games.count {
            let game = r.games[i]
            LogStore.shared.log("[auto-test] result \(game.title): CRASHED (Madeira closed during the game)")
            let log = copyLog(r, game: game, from: LibraryModel.documents.appendingPathComponent("madeira-log.prev.txt"))
            r.results.append(.init(title: game.title, outcome: .crashed, detail: "Madeira closed during the game", seconds: 0, log: log))
            r.index += 1; r.inFlight = nil
            r.finished = r.index >= r.games.count
            r.save(); run = r
            writeResults(r)
            if r.finished { return }
        }
        // A game the last app run asked for must not start in the test's place.
        if NextSteamApp.take() != nil || NextLibraryGame.take() != nil {
            LogStore.shared.log("[auto-test] dropped a game the last run held for a restart: the test run's next game starts instead")
        }
        countdown = 5
        countdownTimer?.invalidate()
        countdownTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { t in
            MainActor.assumeIsolated {
                let me = AutoTestRunner.shared
                guard let c = me.countdown else { t.invalidate(); return }
                if c <= 1 { t.invalidate(); me.countdown = nil; me.launchCurrent() } else { me.countdown = c - 1 }
            }
        }
    }

    /// Start Now on the countdown alert.
    func startNow() {
        countdownTimer?.invalidate(); countdownTimer = nil
        countdown = nil
        launchCurrent()
    }

    func stop() {
        countdownTimer?.invalidate(); countdownTimer = nil
        countdown = nil; timer?.invalidate(); timer = nil; secondsLeft = nil
        guard var r = run, !r.finished else { return }
        LogStore.shared.log("[auto-test] run \(r.id) stopped by the tester at game \(r.index + 1) of \(r.games.count)")
        r.finished = true; r.inFlight = nil; r.save(); run = r
        writeResults(r)
    }

    func forget() { AutoTestRun.clear(); run = nil }

    private func launchCurrent() {
        guard var r = run, !r.finished, r.index < r.games.count, secondsLeft == nil else { return }
        // A game already started in this app run (one per run): stop rather than time the wrong game.
        guard LibraryModel.sessionsThisRun == 0, LibraryModel.shared.current == nil else {
            LogStore.shared.log("[auto-test] another game is already running in this app run: test run stopped", level: .error)
            stop(); return
        }
        let game = r.games[r.index]
        r.touched = Date(); r.inFlight = r.index
        r.save(); run = r
        started = Date(); samples = []; leftApp = false; judged = nil; wrapping = false
        LogStore.shared.log("[auto-test] game \(r.index + 1) of \(r.games.count): \(game.title) (\(r.minutes) min)")
        ShortcutRouter.shared.pendingExe = game.windowsPath   // the same start as a Home Screen link
        secondsLeft = r.minutes * 60
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in
            MainActor.assumeIsolated { AutoTestRunner.shared.tick() }
        }
    }

    private func tick() {
        guard let r = run, !r.finished else { timer?.invalidate(); timer = nil; return }
        let now = Date()
        samples.append((now, madeira_shown_frame_count()))
        samples.removeAll { now.timeIntervalSince($0.0) > 35 }
        let left = r.minutes * 60 - Int(now.timeIntervalSince(started))
        secondsLeft = max(0, left)
        if left <= 0, judged == nil { timeUp() }
    }

    private var recentFrames: Int {
        guard let first = samples.first, let last = samples.last, last.0.timeIntervalSince(first.0) >= 25 else { return 0 }
        return Int(last.1 &- first.1)
    }

    private func facts(endWhy: String?, endCode: String?, endReason: String?) -> AutoTestFacts {
        let s = LogTrail.autoTestSnapshot()
        return AutoTestFacts(shownAt: s.shownAt, jitOn: s.jitOn || s.began || SigningStatus.current.debugged, began: s.began,
                             recentFrames: recentFrames, endWhy: endWhy, endCode: endCode, endReason: endReason,
                             leftApp: leftApp, installsOnly: LibraryModel.shared.installsRestartReady)
    }

    private func timeUp() {
        timer?.invalidate(); timer = nil
        let s = LogTrail.autoTestSnapshot()
        if s.began, LibraryModel.shared.current == nil {
            // The game already ended and LogTrail is waiting for Wine (up to 90 s) to report the exit code:
            // wait for that rather than judge without it.
            LogStore.shared.log("[auto-test] time up while the game's end is still being read; waiting for it")
            DispatchQueue.main.asyncAfter(deadline: .now() + 95) { MainActor.assumeIsolated { AutoTestRunner.shared.fallback() } }
            return
        }
        judged = AutoTestJudge.judge(facts(endWhy: nil, endCode: nil, endReason: nil))
        if let (o, d) = judged { LogStore.shared.log("[auto-test] time up: \(o.rawValue) (\(d)); asking the game to close") }
        if LibraryModel.shared.current != nil { LibraryModel.shared.requestQuit() }
        // A game that ignores Alt+F4 doesn't hold the run: the app closes anyway 15 s later (exit ends Wine).
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { MainActor.assumeIsolated { AutoTestRunner.shared.fallback() } }
    }

    private func fallback() {
        if judged == nil { judged = AutoTestJudge.judge(facts(endWhy: nil, endCode: nil, endReason: nil)) }
        wrapUp()
    }

    /// From LogTrail.finished: the game's session ended (by itself, by hand, or after the runner's quit).
    func gameEnded(why: String, code: String, reason: String?) {
        guard AutoTest.enabled, active, secondsLeft != nil else { return }
        if judged == nil {
            timer?.invalidate(); timer = nil
            judged = AutoTestJudge.judge(facts(endWhy: why, endCode: code, endReason: reason))
        }
        wrapUp()
    }

    private func wrapUp() {
        // A run the tester stopped meanwhile stays stopped: no result, no close.
        guard !wrapping, var r = run, !r.finished, let (outcome, detail) = judged, r.index < r.games.count else { return }
        wrapping = true
        secondsLeft = nil
        var game = r.games[r.index]
        let seconds = Int(Date().timeIntervalSince(started))
        LogStore.shared.log("[auto-test] result \(game.title): \(outcome.rawValue) (\(detail)), \(seconds) s")
        let logName = copyLog(r, game: game, from: LogStore.shared.logURL)
        r.results.append(.init(title: game.title, outcome: outcome, detail: detail, seconds: seconds, log: logName))
        // An inconclusive game runs once more at the end of the queue.
        if outcome == .inconclusive, !game.retried { game.retried = true; r.games.append(game) }
        r.index += 1
        r.inFlight = nil
        r.finished = r.index >= r.games.count
        r.touched = Date()
        r.save(); run = r
        writeResults(r)
        if r.finished {
            LogStore.shared.log("[auto-test] run \(r.id) finished: " + AutoTestOutcomeCount.text(r.results))
            return   // stays in the app; Settings > Test Run shows the results
        }
        LogStore.shared.log("[auto-test] closing Madeira for the next game (one game per app run)")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { exit(0) }
    }

    // MARK: Files

    /// "<folder>/Test runs/<run id> <build>/": the picked folder, else (or if writing there fails) Documents.
    private func withRunFolder(_ r: AutoTestRun, _ body: (URL) throws -> Void) {
        let safe = String((r.id + " " + r.build).map { "/\\:*?\"<>|".contains($0) ? "_" : $0 })
        func attempt(_ base: URL) -> Bool {
            let dir = base.appendingPathComponent("Test runs", isDirectory: true).appendingPathComponent(safe, isDirectory: true)
            do {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                try body(dir); return true
            } catch {
                LogStore.shared.log("[auto-test] could not write to \(base.lastPathComponent)/Test runs: \(error.localizedDescription)", level: .error)
                return false
            }
        }
        if let picked = Self.resolveFolder() {
            let ok = attempt(picked)
            picked.stopAccessingSecurityScopedResource()
            if ok { return }
        }
        _ = attempt(LibraryModel.documents)
    }

    private func copyLog(_ r: AutoTestRun, game: AutoTestRun.Game, from source: URL) -> String? {
        var name: String?
        withRunFolder(r) { dir in
            let safe = String(game.title.map { "/\\:*?\"<>|".contains($0) ? "_" : $0 })
            let file = String(format: "%02d %@.txt", r.index + 1, safe)
            let dest = dir.appendingPathComponent(file)
            try? FileManager.default.removeItem(at: dest)
            try FileManager.default.copyItem(at: source, to: dest)
            name = file
        }
        return name
    }

    /// results.jsonl (one line per game, rewritten whole) and summary.txt, for the PC side to compare.
    private func writeResults(_ r: AutoTestRun) {
        withRunFolder(r) { dir in
            let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys]
            var lines = ""
            for res in r.results {
                let row: [String: String] = ["run": r.id, "build": r.build, "minutes": String(r.minutes), "game": res.title,
                                             "result": res.outcome.rawValue, "detail": res.detail, "seconds": String(res.seconds),
                                             "log": res.log ?? ""]
                if let d = try? enc.encode(row), let s = String(data: d, encoding: .utf8) { lines += s + "\n" }
            }
            try lines.write(to: dir.appendingPathComponent("results.jsonl"), atomically: true, encoding: .utf8)
            var text = "Test run \(r.id) · \(r.build) · \(r.minutes) min per game\n" + AutoTestOutcomeCount.text(r.results) + "\n\n"
            for res in r.results { text += "\(res.outcome.rawValue)\t\(res.title)\t\(res.detail)\n" }
            try text.write(to: dir.appendingPathComponent("summary.txt"), atomically: true, encoding: .utf8)
        }
    }
}

enum AutoTestOutcomeCount {
    static let order: [AutoTestOutcome] = [.pass, .crashed, .froze, .stuck, .exited, .inconclusive]
    static func counts(_ results: [AutoTestRun.Result]) -> [(AutoTestOutcome, Int)] {
        order.compactMap { o in
            let n = results.filter { $0.outcome == o }.count
            return n == 0 ? nil : (o, n)
        }
    }
    static func text(_ results: [AutoTestRun.Result]) -> String {
        counts(results).map { "\($0.1) \($0.0.rawValue.lowercased())" }.joined(separator: " · ")
    }
}

// MARK: - Screens (mockups/auto-test-2026-11-21: A's pick list, C's finished card; Cameron's pick Nov 21)

struct AutoTestSettingsView: View {
    @ObservedObject private var runner = AutoTestRunner.shared
    @ObservedObject private var library = LibraryModel.shared
    @State private var picked = Set<UUID>()
    @State private var minutes = 2
    @State private var choosingFolder = false

    private var games: [LibraryEntry] { library.entries.filter { $0.desktop != true } }

    /// A game row's tap, and A on it (test-run-pad-rows).
    private func toggle(_ id: UUID) { if picked.contains(id) { picked.remove(id) } else { picked.insert(id) } }
    private func startRun() { runner.start(games.filter { picked.contains($0.id) }, minutes: minutes) }


    var body: some View {
        Form {
            if let r = runner.run, r.finished || !r.results.isEmpty { finishedCard(r); results(r) }
            if !runner.active {
                Section("Games") {
                    ForEach(games) { g in
                        Button { toggle(g.id) } label: {
                            HStack(spacing: 12) {
                                Image(systemName: picked.contains(g.id) ? "checkmark.circle.fill" : "circle")
                                    .font(.title3).foregroundStyle(picked.contains(g.id) ? Color.accentColor : Color.secondary)
                                Text(g.title).foregroundStyle(.primary)
                            }
                        }
                        .accessibilityAddTraits(picked.contains(g.id) ? .isSelected : [])
                        .padRow("tr-game-\(g.id.uuidString)") { toggle(g.id) }
                    }
                }
                Section {
                    Picker("Time per game", selection: $minutes) {
                        ForEach(AutoTest.minuteChoices, id: \.self) { Text("\($0) min").tag($0) }
                    }
                    .padPicker("tr-minutes", $minutes, AutoTest.minuteChoices)
                    Button { choosingFolder = true } label: {
                        LabeledContent("Save logs to", value: runner.folderName ?? "Madeira (Files)")
                    }
                    .padRow("tr-folder") { choosingFolder = true }
                } header: { Text("Options") }
                Section {
                    Button("Start Test Run (\(picked.count) game\(picked.count == 1 ? "" : "s"))") { startRun() }
                    .disabled(picked.isEmpty || LibraryModel.sessionsThisRun > 0)
                    .padRow("tr-start", when: !(picked.isEmpty || LibraryModel.sessionsThisRun > 0)) { startRun() }
                } footer: {
                    Text(LibraryModel.sessionsThisRun > 0
                         ? "A game already ran in this app run. Close Madeira and open it again to start a test run."
                         : "Keep the phone plugged in, unlocked and on Madeira. Each game runs for its time, then Madeira closes. A Shortcuts automation \"When Madeira is closed, open Madeira\" reopens it for the next game, or open it yourself.")
                }
            } else {
                Section {
                    Button("Stop Test Run", role: .destructive) { runner.stop() }
                        .padRow("tr-stop") { runner.stop() }
                } footer: { Text("The test run is in progress. The next game starts when Madeira opens.") }
            }
        }
        .navigationTitle("Test Run")
        .fileImporter(isPresented: $choosingFolder, allowedContentTypes: [.folder]) { result in
            if case .success(let url) = result { runner.setFolder(url) }
        }
    }

    /// Mockup C's card: state and build, a tag per result kind, Run Again.
    @ViewBuilder private func finishedCard(_ r: AutoTestRun) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 10) {
                Text("\(r.finished ? "Finished" : "In progress") · \(r.build)").font(.headline)
                HStack(spacing: 6) {
                    ForEach(AutoTestOutcomeCount.counts(r.results), id: \.0) { item in
                        Text("\(item.1) \(item.0.rawValue)").font(.caption.weight(.semibold))
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(Self.color(item.0), in: RoundedRectangle(cornerRadius: 6))
                            .foregroundStyle(.white)
                    }
                }
                .accessibilityElement(children: .combine)
                ProgressView(value: Double(r.results.count), total: Double(max(r.games.count, 1)))
            }
            .padding(.vertical, 4)
            if r.finished {
                Button("Run Again") { runner.runAgain() }.frame(maxWidth: .infinity)
                    .padRow("tr-run-again") { runner.runAgain() }
            }
        } footer: {
            Text("\(r.minutes) min per game. Logs are in Test runs > \(r.id).\(r.finished && LibraryModel.sessionsThisRun > 0 ? " Run Again closes Madeira, and the first game starts when it opens." : "")")
        }
    }

    @ViewBuilder private func results(_ r: AutoTestRun) -> some View {
        Section {
            ForEach(Array(r.results.enumerated()), id: \.offset) { _, res in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(res.title)
                        Spacer()
                        Text(res.outcome.rawValue).font(.caption.weight(.semibold))
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(Self.color(res.outcome), in: RoundedRectangle(cornerRadius: 6))
                            .foregroundStyle(.white)
                    }
                    Text(res.detail).font(.footnote).foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
            }
            if r.finished { Button("Clear Results") { runner.forget() }.padRow("tr-clear") { runner.forget() } }
        } header: { Text("Results") }
    }

    static func color(_ o: AutoTestOutcome) -> Color {
        switch o {
        case .pass: return Color(red: 0.14, green: 0.54, blue: 0.24)
        case .crashed: return Color(red: 0.84, green: 0.0, blue: 0.08)
        case .froze, .stuck: return Color(red: 0.79, green: 0.2, blue: 0.0)
        case .exited: return Color(red: 0.0, green: 0.38, blue: 0.78)
        case .inconclusive: return Color(white: 0.39)
        }
    }
}

/// Attached once at the root. With env.MADEIRA_AUTO_TEST off it adds nothing and never creates the runner.
struct AutoTestOverlay: ViewModifier {
    @ViewBuilder func body(content: Content) -> some View {
        if AutoTest.enabled { content.modifier(AutoTestOverlayOn()) } else { content }
    }
}

/// The capsule over a running test game, and the countdown alert before the next game.
private struct AutoTestOverlayOn: ViewModifier {
    @ObservedObject private var runner = AutoTestRunner.shared
    func body(content: Content) -> some View {
        content
            .overlay(alignment: .top) {
                if let left = runner.secondsLeft, let r = runner.run, r.index < r.games.count {
                    Text("Test run \(r.index + 1) of \(r.games.count) · \(r.games[r.index].title) · \(left / 60):\(String(format: "%02d", left % 60)) left")
                        .font(.footnote.weight(.semibold)).lineLimit(1)
                        .padding(.horizontal, 14).padding(.vertical, 8)
                        .background(.ultraThinMaterial, in: Capsule())
                        .padding(.top, 8)
                        .allowsHitTesting(false)
                }
            }
            // The buttons do the work; the binding's setter does nothing, so dismissing can't cancel a start.
            .alert("Test Run", isPresented: Binding(get: { runner.countdown != nil }, set: { _ in })) {
                Button("Stop Test Run", role: .destructive) { runner.stop() }
                Button("Start Now", role: .cancel) { runner.startNow() }
            } message: {
                if let r = runner.run, r.index < r.games.count {
                    Text("\(r.games[r.index].title) starts in \(runner.countdown ?? 0) s (game \(r.index + 1) of \(r.games.count)).")
                }
            }
            .onAppear { runner.resumeAtAppStart() }
    }
}
