//
//  RecommendedMerge.swift
//  Madeira
//
//  recommended-merge (owner's yes, 2026-11-22): a game that already has a config of its
//  own keeps it, but now also gets the lines of its recommended list that the config does
//  not have at all, once per version of the list.
//    - Only MISSING keys are added. A key the player has (set, or commented out with #)
//      is never touched, whatever its value.
//    - Only a list written for the game itself: not the standard list, an engine list or a shared list.
//    - Added at the end of the game's config under a "# Added by Madeira" line.
//    - The library asks Keep or Undo (RecommendedMergeNotice). Undo removes exactly the
//      lines that were added and Madeira never adds those keys to that game again.
//    - A game whose config Madeira wrote itself at this version (the player may have removed
//      a line on purpose) is skipped.
//  Off: env.MADEIRA_RECOMMENDED_MERGE = 0 (madeira.cfg). Logs: [recommended-merge] ...
//

import Foundation

enum RecommendedMerge {
    static var enabled: Bool { MadeiraConfig.flag("MADEIRA_RECOMMENDED_MERGE") }

    /// Starts with "# Added by Madeira:", so GameRecommendationsApply.splitAdded counts these lines as
    /// Madeira's additions (kept below a rewritten list), not as the player's own.
    static let marker = "# Added by Madeira: recommended settings"

    // MARK: - The pure part (no files, no defaults)

    /// The keys a config line names: `key = value`, or the same behind one or more `#`.
    static func key(of line: String, allowComment: Bool) -> String? {
        var t = line.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("#") {
            guard allowComment else { return nil }
            while t.hasPrefix("#") { t.removeFirst() }
            t = t.trimmingCharacters(in: .whitespaces)
        }
        guard let eq = t.firstIndex(of: "=") else { return nil }
        let k = t[..<eq].trimmingCharacters(in: .whitespaces)
        // A comment that merely contains an "=" in a sentence is not a key.
        guard !k.isEmpty, !k.contains(" "), !k.contains("\t") else { return nil }
        return k
    }

    /// The lines of `recommended` whose key `existing` (and the entry's own lines) does not
    /// have, in the list's order; the last line wins for a key the list repeats.
    static func missing(existing: String, ownLines: String?, recommended: String, declined: Set<String>) -> [(key: String, line: String)] {
        var have = Set<String>()
        for text in [existing, ownLines ?? ""] {
            for raw in text.split(omittingEmptySubsequences: true, whereSeparator: \.isNewline) {
                if let k = key(of: String(raw), allowComment: true) { have.insert(k) }
            }
        }
        var order: [String] = []
        var lines: [String: String] = [:]
        for raw in recommended.split(omittingEmptySubsequences: true, whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard let k = key(of: line, allowComment: false), !have.contains(k), !declined.contains(k) else { continue }
            if lines[k] == nil { order.append(k) }
            lines[k] = line
        }
        return order.map { (key: $0, line: lines[$0]!) }
    }

    /// `existing` with the lines added at the end under the marker; nothing else changes.
    static func appending(_ lines: [String], to existing: String, version: String) -> String {
        var text = existing
        if !text.isEmpty, !text.hasSuffix("\n") { text += "\n" }
        return text + "\(marker) (\(version))\n" + lines.joined(separator: "\n") + "\n"
    }

    /// `text` without exactly these lines and without the marker lines in front of them.
    static func removing(_ lines: [String], from text: String) -> String {
        let gone = Set(lines)
        let kept = text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).map(String.init).filter {
            let t = $0.trimmingCharacters(in: .whitespaces)
            return !(gone.contains(t) || t.hasPrefix(marker))
        }
        return kept.joined(separator: "\n")
    }

    // MARK: - What Madeira remembers

    private static let mergedKey = "madeira.recommended.merged"        // path -> "<id>#<version>" last handled
    private static let declinedKey = "madeira.recommended.mergeDeclined" // path -> [keys] the player undid
    private static let pendingKey = "madeira.recommended.mergePending"  // [{path,title,lines}] waiting for Keep/Undo
    private static let lock = NSLock()
    static let notification = Notification.Name("madeira.recommended-merge.added")

    struct Added: Equatable, Identifiable {
        let windowsPath: String, title: String, lines: [String]
        var id: String { windowsPath }
    }

    private static func dict<T>(_ key: String) -> [String: T] { (UserDefaults.standard.dictionary(forKey: key) as? [String: T]) ?? [:] }

    /// From GameRecommendationsApply for a game that keeps its own config. `alreadyAtThisVersion`:
    /// Madeira wrote this very version into the file itself.
    static func merge(_ rec: GameRecommendation, windowsPath: String, title: String, ownLines: String?, alreadyAtThisVersion: Bool) {
        guard enabled, rec.id != GameRecommendations.standard.id, !rec.id.hasPrefix("engine-"),
              !SharedConfigs.isShared(rec) else { return }
        let version = "\(rec.id)#\(rec.version)"
        let path = windowsPath.lowercased()
        // Cheap exit first: prepare runs for every game on every save.
        guard (dict(mergedKey) as [String: String])[path] != version else { return }
        lock.lock(); defer { lock.unlock() }
        var merged: [String: String] = dict(mergedKey)
        guard merged[path] != version else { return }
        merged[path] = version
        UserDefaults.standard.set(merged, forKey: mergedKey)   // once per version, whatever happens next
        if alreadyAtThisVersion { return }
        let file = GameProfile(windowsPath: windowsPath)
        let declined = Set((dict(declinedKey) as [String: [String]])[path] ?? [])
        let existing = file.text
        // Nothing of the player's own (an emptied config stays empty; only Madeira's or Get Help's additions
        // is `due`'s first-sight case): the list is not merged into it.
        let ownBase = GameRecommendations.splitAdded(existing).base
        guard !(ownBase + (ownLines ?? "")).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        let add = missing(existing: existing, ownLines: ownLines, recommended: rec.fileText, declined: declined)
        guard !add.isEmpty else {
            LogStore.shared.log("[recommended-merge] \(title): \(version) nothing missing")
            return
        }
        let lines = add.map { $0.line }
        let new = appending(lines, to: existing, version: version)
        file.text = new
        guard file.text == new else {
            LogStore.shared.log("[recommended-merge] \(title): could not write the added lines", level: .error)
            return
        }
        LogStore.shared.log("[recommended-merge] \(title): \(version) added \(lines.count) missing line(s), the player's own lines untouched: "
                            + lines.joined(separator: " | "))
        var pending = (UserDefaults.standard.array(forKey: pendingKey) as? [[String: Any]]) ?? []
        // Lines still waiting for an answer from an earlier version stay with this entry.
        let earlier = pending.first { ($0["path"] as? String) == windowsPath }?["lines"] as? [String] ?? []
        pending.removeAll { ($0["path"] as? String) == windowsPath }
        pending.append(["path": windowsPath, "title": title, "lines": earlier + lines])
        UserDefaults.standard.set(pending, forKey: pendingKey)
        NotificationCenter.default.post(name: notification, object: nil)
    }

    /// Reset to Recommended rewrote the config: the added lines are the list's own now, so nothing to undo.
    static func forget(windowsPath: String) {
        lock.lock(); defer { lock.unlock() }
        var pending = (UserDefaults.standard.array(forKey: pendingKey) as? [[String: Any]]) ?? []
        let before = pending.count
        pending.removeAll { ($0["path"] as? String) == windowsPath }
        if pending.count != before { UserDefaults.standard.set(pending, forKey: pendingKey) }
        var merged: [String: String] = dict(mergedKey)
        merged[windowsPath.lowercased()] = nil
        UserDefaults.standard.set(merged, forKey: mergedKey)
    }

    /// Everything waiting for Keep or Undo.
    static var pending: [Added] {
        lock.lock(); defer { lock.unlock() }
        return ((UserDefaults.standard.array(forKey: pendingKey) as? [[String: Any]]) ?? []).compactMap {
            guard let p = $0["path"] as? String, let t = $0["title"] as? String, let l = $0["lines"] as? [String] else { return nil }
            return Added(windowsPath: p, title: t, lines: l)
        }
    }

    /// The answer for these games. Undo removes exactly the added lines and remembers their keys.
    static func answered(_ list: [Added], undo: Bool) {
        lock.lock(); defer { lock.unlock() }
        var pending = (UserDefaults.standard.array(forKey: pendingKey) as? [[String: Any]]) ?? []
        // Only entries whose lines are exactly what was asked about; lines added meanwhile stay pending.
        pending.removeAll { p in list.contains { $0.windowsPath == (p["path"] as? String) && $0.lines == (p["lines"] as? [String]) } }
        UserDefaults.standard.set(pending, forKey: pendingKey)
        for a in list {
            guard undo else { LogStore.shared.log("[recommended-merge] \(a.title): keep"); continue }
            let file = GameProfile(windowsPath: a.windowsPath)
            file.text = removing(a.lines, from: file.text)
            var declined: [String: [String]] = dict(declinedKey)
            let path = a.windowsPath.lowercased()
            let keys = a.lines.compactMap { key(of: $0, allowComment: false) }
            declined[path] = Array(Set((declined[path] ?? []) + keys)).sorted()
            UserDefaults.standard.set(declined, forKey: declinedKey)
            LogStore.shared.log("[recommended-merge] \(a.title): undo, \(a.lines.count) added line(s) removed; not added again")
        }
    }
}
