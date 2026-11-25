// SPDX-License-Identifier: GPL-3.0-or-later
// Madeira Converter Exception: see LICENSE-EXCEPTION.md

import SwiftUI
import UIKit
import Combine
import GameController

// The controller in Madeira's own screens (NewLook.swift): Madeira owns one highlight, on every screen.
// The pad is player 1's, read by GamepadInput and turned into commands by LibraryController,
// so it only reaches Madeira's own screens while no game has the pad.
//
//   D-pad / left stick  moves the highlight to the nearest item that way (held: repeats)
//   A                   presses the highlighted item (opens, toggles, picks)
//   B                   back, cancel or stop: the top layer's own back
//   X                   Play or Install on the highlighted game, else the layer's Play
//   Y / View            Search
//   LB / RB             the previous or next tab
//   LT / RT             a page up or down
//   Menu                the highlighted game's page (its settings)
//
// Layers: a screen or sheet over another one (the game page, a question, the options) is a
// layer. Only the top layer's items can be highlighted, the layer starts on its own safe
// item, and when it goes the highlight returns to the item it came from. The first press
// only shows the highlight; touching the screen hides it. env.MADEIRA_NEW_LOOK_PAD = 0 turns
// the highlight off (Madeira's screens then work by touch only).

@MainActor final class PadHighlight: ObservableObject {
    static let shared = PadHighlight()
    static var enabled: Bool { MadeiraConfig.flag("MADEIRA_NEW_LOOK_PAD") }
    /// Sheets open over the tabs (a store game's sheet, a Settings sheet), for the log trail.
    var sheets = 0

    /// The highlight is showing: the controller was used since the last touch.
    @Published private(set) var shown = false
    /// The highlighted item's id.
    @Published private(set) var focus: String?
    /// The last left/right and when (pad-pages): a held direction's repeats do not open or leave pages.
    private var lastSide: (String, Date) = ("", .distantPast)
    /// The top layer's name, for the hints under the screen.
    @Published private(set) var layerName = PadLayer.root

    /// A press on an item: the item runs its own current action (PadItem's onReceive).
    /// (run-badge-grid) `alt`: Y on an item that has its own Y (a Library grid cover: its page).
    /// decrease / increase (pad-pages): D-pad left / right on an item that changes its value (a slider, a
    /// switch, a choice), when PadDpadRows is on.
    enum Kind { case press, play, menu, alt, decrease, increase }
    let action = PassthroughSubject<(String, Kind), Never>()

    struct Item {
        var frame: CGRect
        var layer: String
        var play: Bool
        var menu: Bool
        /// The grid the item belongs to, for moving through covers that are not drawn yet.
        var grid: String?
        /// (run-badge-grid) Y does the item's own thing, not Search.
        var alt = false
        /// The view that registered it: a hidden tab's item with the same id never takes it away.
        var owner: ObjectIdentifier? = nil
        /// Left and right change its value instead of moving the highlight (PadDpadRows).
        var adjust = false
        /// A row that opens a page: right with nothing to its right opens it (PadDpadRows).
        var opens = false
    }
    private var items: [String: Item] = [:]

    /// A grid of covers: its items' ids in order and how many sit across.
    struct Grid { var ids: [String]; var columns: Int }
    private var grids: [String: Grid] = [:]

    /// A layer: its name, what B does, what X does when the highlight is on no game, and
    /// the item the highlight goes back to when it closes.
    struct Layer {
        let name: String
        var back: (() -> Void)?
        var play: (() -> Void)?
        var start: String?
        let returnTo: String?
        /// A on a layer with nothing to highlight (a store game's sheet): its Install or Open.
        var accept: (() -> Void)? = nil
        /// The view that opened it (PadLayerModifier). With a page stack per tab two layers can
        /// share a name (a store's page in Stores and in Search): each closes only its own.
        var token: UUID? = nil
        /// A page pushed inside a tab (a store's page, a Settings page, a game's page): LB/RB and
        /// Y still change tabs over it, as a tap on the tab bar does. A popup or sheet is not one.
        var page = false
        /// (run-badge-grid) Y on this layer when the highlighted item has no Y of its own
        /// (a game page: "Why this rating"). nil: Y is Search, as before.
        var alt: (() -> Void)? = nil
        /// (pad-layer-keep) A page another page was pushed over: its view is off screen but still in
        /// the stack, so its layer stays (with the item to go back to) until it shows again.
        var covered = false
        /// (pad-layer-keep) A page whose covered page under it showed again: it is going (a swipe
        /// back, or Back), and closes on its own onDisappear. A cancelled swipe makes it live again.
        var leaving = false
    }
    private var layers: [Layer] = [Layer(name: PadLayer.root, back: nil, play: nil, start: nil, returnTo: nil)]
    var top: Layer { layers[layers.count - 1] }

    /// What the tab bar does: LB/RB, Y, and the tab's own first item.
    var tabs: ((Int) -> Void)?
    var search: (() -> Void)?
    /// B on a tab with no layer over it: Search goes back to the tab you came from
    /// (LibraryView.newLookBody). A pushed page (a store's, a Settings page) is a layer of its
    /// own, and its B goes back a page.
    var rootBack: (() -> Void)?
    /// The highlight's last place on each root page (a tab), for coming back to it.
    private var remembered: [String: String] = [:]
    /// The item a closed layer hands the highlight back to while that item is not laid out again
    /// yet (a game page coming back from Display): it keeps the highlight when it is.
    private var pending: String?
    var page = "library"
    private var started = false
    private var bag: AnyCancellable?

    /// Listens to the controller's commands, once.
    func start() {
        guard !started, Self.enabled else { return }
        started = true
        bag = LibraryController.shared.commands.sink { [weak self] command in
            MainActor.assumeIsolated { self?.handle(command) }
        }
        installTouchWatch()
        LogStore.shared.log("[pad-highlight] on")
    }

    // MARK: Items and layers

    func register(_ id: String, _ item: Item) {
        items[id] = item
        if id == pending { pending = nil; if focus == id, shown { scrollRequest.send(id) }; return }
        // A layer that just opened rings its start item as soon as it is laid out.
        if pending == nil, shown, focus == nil || items[focus ?? ""]?.layer != top.name, item.layer == top.name,
           top.start == id || (top.start == nil && !settling) {
            move(to: id, scroll: false)
        }
    }
    func unregister(_ id: String, owner: ObjectIdentifier? = nil) {
        if owner == nil || items[id]?.owner == owner { items[id] = nil }
    }
    func setGrid(_ id: String, ids: [String], columns: Int) { grids[id] = Grid(ids: ids, columns: max(1, columns)) }
    func removeGrid(_ id: String) { grids[id] = nil }

    func push(_ name: String, start: String?, back: (() -> Void)?, play: (() -> Void)?, accept: (() -> Void)? = nil,
              token: UUID? = nil, page: Bool = false, alt: (() -> Void)? = nil) {
        // (pad-layer-keep) A covered page shown again (a page pushed over it went back): it keeps the
        // item it goes back to, and the pages over it go (they close a moment later on their own).
        var kept: String??
        if let i = layers.firstIndex(where: { token != nil ? $0.token == token : $0.name == name }), i > 0 {
            if PadLayerKeep.on, layers[i].covered, i < layers.count - 1 {
                // It goes on top with its own item to go back to; the pages that were over it stay,
                // marked leaving, so a swipe back that is called off can put them back (leave()).
                // The highlight goes to the row that opened the page over it.
                let old = layers.remove(at: i)
                let resume = layers[i].returnTo
                for j in i..<layers.count { layers[j].leaving = true }
                layers.append(Layer(name: name, back: back, play: play, start: start, returnTo: old.returnTo,
                                    accept: accept, token: token, page: page, alt: alt))
                entering = nil
                layerName = name
                if shown {
                    move(to: resume.flatMap { items[$0]?.layer == name ? $0 : nil }
                         ?? start.flatMap { items[$0] != nil ? $0 : nil } ?? first(in: name), scroll: true)
                }
                LogStore.shared.log("[pad-highlight] layer \(name) shown again")
                return
            }
            if layers[i].covered { kept = .some(layers[i].returnTo) }
            layers.removeSubrange(i...)
        }
        // The item to come back to: only one on the layer under it (a page reopened in another
        // tab must not come back to an item of the tab it was opened from).
        // (None while a tab change is under way: the old tab's item is not on this tab.)
        let returnTo = kept ?? (entering != nil ? nil : focus.flatMap { id in
            items[id]?.layer == top.name || grids.values.contains(where: { $0.ids.contains(id) }) ? id : nil
        })
        layers.append(Layer(name: name, back: back, play: play, start: start, returnTo: returnTo, accept: accept, token: token, page: page, alt: alt))
        entering = nil
        layerName = name
        if shown { move(to: start.flatMap { items[$0] != nil ? $0 : nil } ?? first(in: name), scroll: false) }
        // No start item: once the layer is laid out, its top-left row (items register in no set
        // order: a game's Controls page started on its last row, Control size).
        if start == nil { settleSoon(layer: name, page: nil) }
        LogStore.shared.log("[pad-highlight] layer \(name) opened")
    }
    func update(_ name: String, back: (() -> Void)?, play: (() -> Void)?) {
        guard let i = layers.firstIndex(where: { $0.name == name }) else { return }
        layers[i].back = back; layers[i].play = play
    }
    /// (pad-layer-keep) A layer's view went off screen (PadLayerModifier.onDisappear). A page with
    /// another page pushed over it is only covered: SwiftUI's NavigationStack calls onDisappear on
    /// the page under a push (Apple forums 718738; oleb.net "Understanding SwiftUI view lifecycles"),
    /// and 0.2.84-0.2.87 closed the game page's layer on every push and opened it again on the way
    /// back (Cameron's log: "layer game closed / close game page (now the library)" on each
    /// sub-page). Anything else closes as before. env.MADEIRA_PAD_LAYER_KEEP = 0: always closes.
    func leave(_ name: String, token: UUID?) {
        // A swipe back that was called off: the page under came back on top (push, above) and now goes
        // again, while the pages over it that were leaving stay on screen. It goes back under them,
        // covered, and they are live again.
        if PadLayerKeep.on, let token, let i = layers.lastIndex(where: { $0.token == token }), i > 0,
           i == layers.count - 1, layers[i].page, let k = layers.firstIndex(where: \.leaving), k < i {
            var layer = layers.remove(at: i)
            layer.covered = true
            layers.insert(layer, at: k)
            for j in (k + 1)..<layers.count { layers[j].leaving = false }
            layerName = top.name
            if shown { move(to: first(in: top.name), scroll: false) }
            LogStore.shared.log("[pad-highlight] layer \(name) covered again (back called off)")
            return
        }
        if PadLayerKeep.on, let token, let i = layers.lastIndex(where: { $0.token == token }), i > 0,
           i < layers.count - 1, layers[i].page, !layers[i].leaving, layers[(i + 1)...].allSatisfy(\.page) {
            layers[i].covered = true
            LogStore.shared.log("[pad-highlight] layer \(name) covered")
            return
        }
        pop(name, token: token)
    }

    func pop(_ name: String, token: UUID? = nil) {
        guard let i = layers.lastIndex(where: { token != nil ? $0.token == token : $0.name == name }), i > 0 else { return }
        // Only this layer goes: a layer over it (the starting screen over a game page that the
        // session replaced) stays, and the highlight moves back only when this one was on top.
        let wasTop = i == layers.count - 1
        var back = layers[i].returnTo
        layers.remove(at: i)
        // (pad-layer-keep) Pages left covered under it whose views are gone too (the tab went back to
        // its first page, or another tab took over): they close with it, and the highlight goes back
        // to what opened the lowest of them (the game's cover), not to a row of a page that is gone.
        while PadLayerKeep.on, wasTop, layers.count > 1, top.covered {
            LogStore.shared.log("[pad-highlight] layer \(top.name) closed (was covered)")
            back = top.returnTo
            layers.removeLast()
        }
        layerName = top.name
        LogStore.shared.log("[pad-highlight] layer \(name) closed")
        guard wasTop else {
            // The page under it came back on top first (a game's own page closed inside a tab: the
            // game's page appeared again before this one went): the highlight goes back to its row.
            // (stock-apple, pad-pop-keep) Not when the highlight is already on that page: the sub-page's
            // layer closes about half a second after the page under it came back, and a press in that time
            // (an up after a left out of Cloud saves) was undone, the ring snapping back to the row it left
            // (Cameron, 0.2.84 log 00:47:52.631 up to Steam, 00:47:52.842 "layer game-cloud closed", the next
            // up again from Cloud). env.MADEIRA_PAD_POP_KEEP = 0: as before.
            let already = PadPopKeep.on && focus.flatMap { items[$0]?.layer } == top.name
            if let back, items[back]?.layer == top.name, !already { move(to: back, scroll: true) }
            return
        }
        // A tab was picked while this page was open on the old tab: the highlight goes to the
        // new tab's place, not back to the old tab's row.
        if layers.count == 1, let name = entering { entering = nil; land(on: name); return }
        // The page under it may not be laid out again yet (Cameron, Nov 9: back from Display the
        // controller did nothing until a touch): its item takes the highlight when it is.
        if let back, items[back] == nil { move(to: back, scroll: false); pending = back; return }
        move(to: back.flatMap { items[$0]?.layer == top.name ? $0 : nil } ?? first(in: top.name), scroll: true)
    }

    /// A tab became the root page: the highlight goes to its remembered item, else its first.
    func enterPage(_ name: String) {
        // A tab-bar button is never remembered: coming back to a page starts on the page
        // (Cameron, Nov 9: back from Search the highlight sat on the Search button, down did nothing).
        if let focus, items[focus]?.layer == PadLayer.root, !focus.hasPrefix("tab-") { remembered[page] = focus }
        page = name
        // A page pushed on the old tab still has its layer (it closes just after): the new tab's
        // place is taken once it has (pop). A layer the new tab opens itself clears this (push).
        guard layers.count == 1 else { entering = name; return }
        entering = nil
        land(on: name)
    }
    /// A tab picked while a pushed page's layer was still up (enterPage, pop).
    private var entering: String?
    private func land(on name: String) {
        let kept = remembered[name].flatMap { items[$0] != nil ? $0 : nil }
        move(to: kept, scroll: true)
        guard kept == nil else { return }
        // The new page's items lay out after this: once they have, its remembered item, else its
        // top-left item on screen, takes the highlight.
        settleSoon(layer: PadLayer.root, page: name)
    }
    private var settling = false
    /// Controller presses so far: a press while a page settles keeps where it put the highlight.
    private var presses = 0
    private func settleSoon(layer: String, page: String?) {
        settling = true
        let at = presses
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { [weak self] in self?.settle(layer: layer, page: page, at: at) }
    }
    private func settle(layer: String, page: String?, at: Int) {
        settling = false
        guard top.name == layer, page == nil || self.page == page, presses == at else { return }
        if let id = home(layer: layer, page: page) { move(to: id, scroll: true) }
    }
    /// Where the highlight belongs on a layer: the page's remembered item, else its top-left
    /// item on screen, else its first.
    private func home(layer: String, page: String?) -> String? {
        let height = windowSize.height
        return page.flatMap { remembered[$0] }.flatMap { items[$0] != nil ? $0 : nil }
            ?? items.filter { $0.value.layer == layer && !$0.key.hasPrefix("tab-") && $0.value.frame.width > 0
                              && $0.value.frame.minY >= 0 && $0.value.frame.minY < height }
                .min { a, b in
                    abs(a.value.frame.minY - b.value.frame.minY) > 8 ? a.value.frame.minY < b.value.frame.minY : a.value.frame.minX < b.value.frame.minX
                }?.key
            ?? first(in: layer)
    }
    /// The app's window, not the whole screen: in Split View and Stage Manager they differ
    /// (ux-review-0044 #9).
    private var windowSize: CGSize {
        UIApplication.shared.phoneScenes.compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows).first { $0.isKeyWindow }?.bounds.size ?? UIScreen.main.bounds.size
    }
    /// Nothing but the tab and pages pushed inside it is up (no popup or sheet).
    private var onTabPage: Bool { layers.dropFirst().allSatisfy(\.page) }
    /// The highlight is on an item that is not there (its page closed and the item it came back
    /// to never came back: an uninstalled game, a moved row). A cover of a grid that is only
    /// scrolled away is still there.
    private var onGhost: Bool {
        guard let focus else { return false }
        return items[focus] == nil && !grids.values.contains(where: { $0.ids.contains(focus) })
    }

    // MARK: Showing and moving

    @discardableResult func show() -> Bool {
        installTouchWatch()
        guard !shown else { return false }
        withAnimation(Self.animation) { shown = true }
        if focus == nil || items[focus!]?.layer != top.name { move(to: top.start.flatMap { items[$0] != nil ? $0 : nil } ?? first(in: top.name), scroll: true) }
        return true
    }
    func hide() {
        guard shown else { return }
        withAnimation(Self.animation) { shown = false }
    }
    func move(to id: String?, scroll: Bool = true) {
        pending = nil
        guard id != focus else { return }
        var instant = Transaction(); instant.disablesAnimations = true
        withTransaction(instant) { focus = id }
        if scroll, let id { scrollRequest.send(id) }
    }
    /// Highlights the first of `ids` that is on screen in the top layer, else the layer's first item.
    func move(toAny ids: [String]) {
        move(to: ids.first { items[$0]?.layer == top.name } ?? first(in: top.name))
    }
    /// The highlighted item should be on screen: pages with a scroll view scroll to it.
    let scrollRequest = PassthroughSubject<String, Never>()
    static var animation: Animation? { UIAccessibility.isReduceMotionEnabled ? nil : .easeOut(duration: 0.08) }

    /// The top-left item of a layer.
    func first(in layer: String) -> String? {
        items.filter { $0.value.layer == layer && $0.value.frame.width > 0 }
            .min { a, b in
                abs(a.value.frame.minY - b.value.frame.minY) > 8 ? a.value.frame.minY < b.value.frame.minY : a.value.frame.minX < b.value.frame.minX
            }?.key
    }

    /// The next item from the highlighted one in `direction`: inside a grid by its order
    /// (covers further down may not be drawn yet), else the nearest drawn item that way.
    func next(_ direction: String) -> String? {
        guard let focus else { return first(in: top.name) }
        // A cover scrolled out of a lazy grid is no longer drawn (its item is gone): its grid still knows where it is.
        let gridID = items[focus]?.grid ?? grids.first(where: { $0.value.ids.contains(focus) })?.key
        if let gridID, let grid = grids[gridID], let index = grid.ids.firstIndex(of: focus) {
            let columns = grid.columns
            var target: Int?
            switch direction {
            case "left": if index % columns > 0 { target = index - 1 }
            case "right": if index % columns < columns - 1, index + 1 < grid.ids.count { target = index + 1 }
            case "up": if index >= columns { target = index - columns }
            case "down":
                if index + columns < grid.ids.count { target = index + columns }
                // The last row is short: the last cover, when the row below has any.
                else if index / columns < (grid.ids.count - 1) / columns { target = grid.ids.count - 1 }
            default: break
            }
            if let target { return grid.ids[target] }
            // Out of the grid: the nearest item that is not one of its covers.
            guard let current = items[focus] else { return nil }
            return nearest(from: current.frame, direction: direction, skip: Set(grid.ids))
        }
        guard let current = items[focus] else { return first(in: top.name) }
        return nearest(from: current.frame, direction: direction, skip: [])
    }

    /// The nearest item in the top layer that lies `direction` from `from`: mostly straight
    /// ahead, a little to the side when nothing is.
    func nearest(from: CGRect, direction: String, skip: Set<String>) -> String? {
        // The console look's rails (FluxScreens.swift, ids "fx-..."): between a rail row and the page
        // beside it Left and Right also take an item that does not line up, when none does.
        var best: (String, CGFloat)?
        var loose: (String, CGFloat)?
        let fromRail = focus?.hasPrefix("fx-") ?? false
        for (id, item) in items where item.layer == top.name && !skip.contains(id) && id != focus && item.frame.width > 0 {
            let f = item.frame
            let ahead: CGFloat, side: CGFloat
            switch direction {
            case "down": guard f.minY >= from.maxY - 4 else { continue }; ahead = f.minY - from.maxY; side = gap(f.minX, f.maxX, from.minX, from.maxX)
            case "up": guard f.maxY <= from.minY + 4 else { continue }; ahead = from.minY - f.maxY; side = gap(f.minX, f.maxX, from.minX, from.maxX)
            case "right": guard f.minX >= from.maxX - 4 else { continue }; ahead = f.minX - from.maxX; side = gap(f.minY, f.maxY, from.minY, from.maxY)
            case "left": guard f.maxX <= from.minX + 4 else { continue }; ahead = from.minX - f.maxX; side = gap(f.minY, f.maxY, from.minY, from.maxY)
            default: continue
            }
            // Left and right stay in the row: an item with no overlap at all is skipped.
            if direction == "left" || direction == "right", side > 0 {
                if id.hasPrefix("fx-") != fromRail {
                    let score = max(0, ahead) + side * 3
                    if loose == nil || score < loose!.1 { loose = (id, score) }
                }
                continue
            }
            let score = max(0, ahead) + side * 3
            if best == nil || score < best!.1 { best = (id, score) }
        }
        return best?.0 ?? loose?.0
    }
    /// How far apart two spans are (0 when they overlap).
    private func gap(_ a0: CGFloat, _ a1: CGFloat, _ b0: CGFloat, _ b1: CGFloat) -> CGFloat {
        if a1 < b0 { return b0 - a1 }
        if b1 < a0 { return a0 - b1 }
        return 0
    }

    /// LT/RT: about a screen up or down.
    func jump(down: Bool) -> String? {
        guard let focus else { return first(in: top.name) }
        let gridID = items[focus]?.grid ?? grids.first(where: { $0.value.ids.contains(focus) })?.key
        if let gridID, let grid = grids[gridID], let index = grid.ids.firstIndex(of: focus) {
            let rows = max(2, Int((windowSize.height * 0.7) / max(items[focus]?.frame.height ?? 200, 120)))
            let step = grid.columns * rows
            let target = down ? min(grid.ids.count - 1, index + step) : max(0, index - step)
            return grid.ids[target]
        }
        guard let current = items[focus] else { return first(in: top.name) }
        let height = windowSize.height * 0.8
        let point = CGPoint(x: current.frame.midX, y: current.frame.midY + (down ? height : -height))
        return items.filter { $0.value.layer == top.name && $0.value.frame.width > 0 && (down ? $0.value.frame.midY > current.frame.midY : $0.value.frame.midY < current.frame.midY) }
            .min { hypot($0.value.frame.midX - point.x, $0.value.frame.midY - point.y) < hypot($1.value.frame.midX - point.x, $1.value.frame.midY - point.y) }?.key
    }

    // MARK: Commands

    func handle(_ command: String) {
        presses += 1
        // In a session only the starting screen is Madeira's, and never under the Session menu
        // (its own A and B; an A there must not press Stop behind it).
        let model = LibraryModel.shared
        guard Self.enabled, model.current == nil || model.startingScreen, !model.menu else { return }
        // First-run setup covers the library: no command acts on what is behind it (the old
        // library's commands had the same guard).
        guard !OnboardingModel.shared.presented else { return }
        // The first press of a direction or A only brings the highlight back (where it was).
        // A layer with nothing to highlight (a store game's sheet) takes A as its own accept.
        if command == "accept", let accept = top.accept, !items.values.contains(where: { $0.layer == top.name }) {
            accept(); return
        }
        let moves = ["up", "down", "left", "right", "accept", "pageUp", "pageDown"]
        if moves.contains(command), show() { return }
        // A or Menu on an item that is gone did nothing until a move or a touch (ux-review-0044 #3):
        // the press puts the highlight somewhere real first, as the first press after a touch does.
        // (The directions already start from the layer's first item; B is the layer's own.)
        if command == "accept" || command == "menu", onGhost {
            move(to: home(layer: top.name, page: layers.count == 1 ? page : nil), scroll: true)
            LogStore.shared.log("[pad-highlight] re-homed from a gone item")
            return
        }
        // (run-badge-grid) Y (sent as "add") on an item or a layer with a Y of its own; else Search below.
        if command == "add" {
            if let focus, let item = items[focus], item.layer == top.name, item.alt {
                show(); action.send((focus, .alt)); return
            }
            if let alt = top.alt { show(); alt(); return }
        }
        switch command {
        case "up", "down", "left", "right":
            if PadDpadRows.on, command == "left" || command == "right" {
                // A held direction repeats every 0.1 s: opening or leaving a page takes a fresh press,
                // so a held left does not close page after page, nor a held right change the new page.
                let repeated = lastSide.0 == command && Date().timeIntervalSince(lastSide.1) < 0.4
                lastSide = (command, Date())
                // Left toward the console look's rail still goes there, not into the row's value.
                if command == "left", let id = next(command), id.hasPrefix("fx-") { move(to: id); return }
                // A slider, switch or choice row: left and right change it, as on a console's settings.
                if let focus, let item = items[focus], item.layer == top.name, item.adjust {
                    action.send((focus, command == "left" ? .decrease : .increase)); return
                }
                if let id = next(command) { move(to: id); return }
                // Nothing that way: right opens the highlighted row's page, left goes back a page.
                if repeated { return }
                if command == "right", let focus, let item = items[focus], item.layer == top.name, item.opens {
                    action.send((focus, .press))
                } else if command == "left", top.page, let back = top.back {
                    back()
                }
                return
            }
            if let id = next(command) { move(to: id) }
        case "pageUp", "pageDown":
            if let id = jump(down: command == "pageDown") { move(to: id) }
        case "accept":
            // A cover just scrolled into view may not be drawn yet: it takes the press when it is.
            if let focus, items[focus]?.layer == top.name || grids.values.contains(where: { $0.ids.contains(focus) }) {
                action.send((focus, .press))
            }
        case "play":
            show()
            if let focus, let item = items[focus], item.layer == top.name, item.play { action.send((focus, .play)) }
            else { top.play?() }
        case "menu":
            if let focus, let item = items[focus], item.layer == top.name, item.menu { show(); action.send((focus, .menu)) }
        case "back":
            if let back = top.back { back() } else if layers.count == 1 { rootBack?() }
        case "previous", "next":
            // Over pages pushed in the tab too (Cameron, Test 6: LB/RB stuck on Settings and
            // Search with a page open there); never under a popup or sheet.
            if onTabPage { tabs?(command == "next" ? 1 : -1) }
        case "add", "search":
            if onTabPage { search?() }
        default: break
        }
    }

    // MARK: Touch

    /// Touching the screen hides the highlight: a recognizer on the window that never takes a touch.
    private var watching = false
    private func installTouchWatch() {
        guard !watching else { return }
        let window = UIApplication.shared.phoneScenes.compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows).first { $0.isKeyWindow }
        guard let window else { return }
        watching = true
        window.addGestureRecognizer(PadTouchWatch { PadHighlight.shared.hide() })
        // iOS 18 also routes a controller into UIKit's own focus: Madeira reads the pad itself.
        GamepadEventClaim.install(on: window)
    }
}

/// The layer names that are always there.
enum PadLayer {
    static let root = "root"
}

private struct PadLayerKey: EnvironmentKey { static let defaultValue = PadLayer.root }
private struct PadLayerAltKey: EnvironmentKey { static let defaultValue: (() -> Void)? = nil }
extension EnvironmentValues {
    /// (run-badge-grid) Y on the next layer in (PadLayerModifier reads it, and clears it inside).
    var padLayerAlt: (() -> Void)? {
        get { self[PadLayerAltKey.self] }
        set { self[PadLayerAltKey.self] = newValue }
    }
    /// The layer the views inside belong to (PadHighlight).
    var padLayer: String {
        get { self[PadLayerKey.self] }
        set { self[PadLayerKey.self] = newValue }
    }
}

/// The value after `current` in `values` (the first again after the last): A on a choice row
/// steps to its next option, as the controller cannot open the system's menu.
func padNext<T: Equatable>(_ values: [T], after current: T) -> T {
    guard let first = values.first else { return current }
    guard let index = values.firstIndex(of: current) else { return first }
    return values[(index + 1) % values.count]
}

/// Sees every touch on the window and fails at once, so taps, scrolls and buttons are untouched.
final class PadTouchWatch: UIGestureRecognizer {
    private let touched: @MainActor () -> Void
    init(_ touched: @escaping @MainActor () -> Void) {
        self.touched = touched
        super.init(target: nil, action: nil)
        cancelsTouchesInView = false
        delaysTouchesBegan = false
        delaysTouchesEnded = false
    }
    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        MainActor.assumeIsolated { touched() }
        state = .failed
    }
}

/// A PadItem's last frame on screen, and whether it is on screen now. (Apple's tab bar keeps
/// the other tabs' pages alive while they are hidden: their items must not register again or
/// take a press meant for an item with the same id on the open tab.)
final class PadLastFrame { var frame: CGRect = .zero; var visible = false }

/// An item the highlight can reach: its ring, its place on screen, and what A, X and Menu do.
struct PadItem: ViewModifier {
    let id: String
    var cornerRadius: CGFloat = 16
    var grid: String? = nil
    var play: (() -> Void)? = nil
    var menu: (() -> Void)? = nil
    /// (run-badge-grid) What Y does on this item; nil: Y is the layer's (Search).
    var alt: (() -> Void)? = nil
    /// The item is a capsule or a circle (buttons, pills, chips): the outline is a capsule around it.
    var capsule = false
    /// Where the outline sits: negative is a gap outside the item (the usual 4 pt), 0 is on its own
    /// edge (a tab inside the tab bar, so it stays inside the bar), positive is inside it (a row in a
    /// card, so it follows the card's curve instead of poking out). Its corners are always
    /// `cornerRadius - inset`, which keeps it concentric with the item.
    var inset: CGFloat = -4
    /// D-pad left (-1) and right (+1) change the item's value (PadDpadRows).
    var adjust: ((Int) -> Void)? = nil
    /// The item opens a page: D-pad right opens it (PadDpadRows).
    var opens = false
    let press: () -> Void
    @Environment(\.padLayer) private var layer
    /// Its last place: a page that comes back (a pushed page closed) is not measured again
    /// when nothing moved, so it registers again from here. (A box: keeping it redraws nothing while scrolling.)
    @State private var last = PadLastFrame()
    /// This item has the highlight. Each item follows only its own yes/no, not the whole
    /// PadHighlight: a move or a tab switch redraws the one or two items that changed, not every
    /// item in every tab and pushed page (Cameron, Test 6: tab switching got laggy over time).
    @State private var on = false
    func body(content: Content) -> some View {
        content
            // (stock-apple) Apple's focus look, one style per kind (Apple rulebook 13.22, 13.25): a list
            // row lights up as a whole row; a cover (a picture that fills its cell) lifts with its ring (below).
            .background {
                if StockApple.on, on, StockApple.isRow(capsule: capsule, grid: grid, inset: inset) {
                    RoundedRectangle(cornerRadius: max(0, cornerRadius - inset), style: .continuous)
                        .fill(StockApple.ring.opacity(0.18))
                        .padding(inset)
                        .allowsHitTesting(false)
                }
            }
            .overlay {
                // Every outline is concentric with its item (Apple's rule; Cameron, Nov 9: "make sure things
                // line up"): the same shape, moved out or in by `inset`, corners changed by the same amount.
                Group {
                    if capsule {
                        Capsule().strokeBorder(StockApple.ring, lineWidth: 3)
                    } else {
                        RoundedRectangle(cornerRadius: max(0, cornerRadius - inset), style: .continuous)
                            .strokeBorder(StockApple.ring, lineWidth: 3)
                    }
                }
                .padding(inset)
                // (stock-apple) A row shows the whole-row light only, no ring as well.
                .opacity(on && !(StockApple.on && StockApple.isRow(capsule: capsule, grid: grid, inset: inset)) ? 1 : 0)
                .allowsHitTesting(false)
            }
            .modifier(StockAppleLift(on: on, cover: grid != nil))
            .zIndex(on ? 1 : 0)
            .onGeometryChange(for: CGRect.self) { $0.frame(in: .global) } action: { frame in
                last.frame = frame
                guard last.visible else { return }
                PadHighlight.shared.register(id, .init(frame: frame, layer: layer, play: play != nil, menu: menu != nil, grid: grid, alt: alt != nil,
                                                        owner: ObjectIdentifier(last), adjust: adjust != nil, opens: opens))
            }
            .onAppear {
                last.visible = true
                if last.frame != .zero {
                    PadHighlight.shared.register(id, .init(frame: last.frame, layer: layer, play: play != nil, menu: menu != nil, grid: grid, alt: alt != nil,
                                                            owner: ObjectIdentifier(last), adjust: adjust != nil, opens: opens))
                }
            }
            .onDisappear {
                last.visible = false
                PadHighlight.shared.unregister(id, owner: ObjectIdentifier(last))
            }
            .id(id)
            .onReceive(PadHighlight.shared.$focus.combineLatest(PadHighlight.shared.$shown)
                .map { [id] focus, shown in shown && focus == id }.removeDuplicates()) { on = $0 }
            .onReceive(PadHighlight.shared.action) { pressed in
                guard pressed.0 == id, last.visible else { return }
                switch pressed.1 {
                case .press: press()
                case .play: play?()
                case .menu: menu?()
                case .alt: alt?()
                case .decrease: adjust?(-1)
                case .increase: adjust?(1)
                }
            }
    }
}

/// A screen or sheet over the others: its items form the top layer while it is up.
struct PadLayerModifier: ViewModifier {
    let name: String
    var start: String?
    let back: (() -> Void)?
    var play: (() -> Void)? = nil
    var accept: (() -> Void)? = nil
    var page = false
    /// (run-badge-grid) Y on the layer (PadHighlight.Layer.alt), set from outside with
    /// .padLayerAlt; the layers inside this one (its sheets and popups) do not get it.
    @Environment(\.padLayerAlt) private var alt
    /// This view's own layer (two pages with one layer name can be up in different tabs).
    @State private var token = UUID()
    func body(content: Content) -> some View {
        content
            .environment(\.padLayer, name)
            .environment(\.padLayerAlt, nil)
            .onAppear { PadHighlight.shared.push(name, start: start, back: back, play: play, accept: accept, token: token, page: page, alt: alt) }
            .onDisappear { PadHighlight.shared.leave(name, token: token) }
    }
}

/// Keeps the highlighted item on screen in a scroll view.
struct PadScrollFollow: ViewModifier {
    let reader: ScrollViewProxy
    /// Items that scroll the page all the way up, to the view with this id (a game page's Play:
    /// its cover above it shows too).
    var toTop: Set<String> = []
    var topID = "pad-top"
    func body(content: Content) -> some View {
        content.onReceive(PadHighlight.shared.scrollRequest) { id in
            withAnimation(PadHighlight.animation) {
                if toTop.contains(id) { reader.scrollTo(topID, anchor: .top) } else { reader.scrollTo(id, anchor: .center) }
            }
        }
    }
}

extension View {
    /// A controller-reachable item (PadHighlight): `id` is unique on the screen.
    /// `when`: false leaves the view out of the highlight (a pill that only shows a state).
    /// `adjust`: D-pad left (-1) / right (+1) change the item's value; `opens`: D-pad right opens
    /// its page (PadDpadRows).
    @ViewBuilder func padItem(_ id: String, cornerRadius: CGFloat = 16, grid: String? = nil,
                              play: (() -> Void)? = nil, menu: (() -> Void)? = nil, alt: (() -> Void)? = nil, when: Bool = true, capsule: Bool = false,
                              inset: CGFloat = -4, adjust: ((Int) -> Void)? = nil, opens: Bool = false,
                              press: @escaping () -> Void) -> some View {
        if PadHighlight.enabled && when {
            modifier(PadItem(id: id, cornerRadius: cornerRadius, grid: grid, play: play, menu: menu, alt: alt, capsule: capsule, inset: inset,
                             adjust: adjust, opens: opens, press: press))
        } else { self }
    }
    /// A layer over the screens below (PadHighlight): `start` is its safe first item, `back` B.
    /// `page`: a page pushed inside a tab (LB/RB and Y still change tabs over it).
    @ViewBuilder func padLayer(_ name: String, start: String? = nil, back: (() -> Void)?, play: (() -> Void)? = nil,
                               accept: (() -> Void)? = nil, page: Bool = false) -> some View {
        if PadHighlight.enabled { modifier(PadLayerModifier(name: name, start: start, back: back, play: play, accept: accept, page: page)) } else { self }
    }
    /// (run-badge-grid) What Y does on the layer just inside this (put it right after .padLayer).
    func padLayerAlt(_ alt: (() -> Void)?) -> some View { environment(\.padLayerAlt, alt) }
    /// Scrolls to the highlighted item (inside a ScrollViewReader).
    @ViewBuilder func padScrollFollow(_ reader: ScrollViewProxy, toTop: Set<String> = []) -> some View {
        if PadHighlight.enabled { modifier(PadScrollFollow(reader: reader, toTop: toTop)) } else { self }
    }
}

// MARK: - Sheets, Forms and store cards

/// iPadOS walks a Form with the controller through its own focus: one A on a cover opened the
/// game's page, then Controls and Gyro aim & turbo opened by themselves and the walk ended at the
/// bottom (Cameron, Wave 10, after the window's claim). While a controller is connected the
/// Form's list takes no system focus; touch, and Madeira's own commands, work as before.
struct PadNoSystemFocus: UIViewRepresentable {
    /// (pad-focus-hold) The app-wide one (every tab's stack, every sheet): it only holds the focus,
    /// it leaves the lists' own focus alone (a keyboard still walks them with no controller).
    var app = false
    func makeUIView(context: Context) -> Probe { let probe = Probe(); probe.app = app; return probe }
    func updateUIView(_ view: Probe, context: Context) {}

    /// Wave 12 (Cameron's log): the list's cells took the system focus even with allowsFocus
    /// off, and its blue fill walked under Madeira's highlight. So this view also holds the
    /// system focus itself while the highlight shows: it is focusable, draws nothing, takes the
    /// focus whenever it lands elsewhere in its window, and does not let a direction move it
    /// away. Touch hides the highlight and lets focus go.
    final class Probe: UIView {
        var app = false
        private var watch: NSObjectProtocol?
        /// (pad-focus-hold) A controller connected, or the highlight shown again, after this view was
        /// laid out: hold the focus then too, not only when the system's focus moves.
        private var connectWatch: NSObjectProtocol?
        private var shownSink: AnyCancellable?
        private static var appliedLogged = false
        private static var heldLogged = false
        override init(frame: CGRect) {
            super.init(frame: frame)
            isUserInteractionEnabled = false
            backgroundColor = .clear
            focusEffect = nil
        }
        required init?(coder: NSCoder) { nil }
        deinit {
            if let watch { NotificationCenter.default.removeObserver(watch) }
            if let connectWatch { NotificationCenter.default.removeObserver(connectWatch) }
        }
        private var holding: Bool {
            PadHighlight.enabled && PadHighlight.shared.shown && window != nil && !GCController.controllers().isEmpty
        }
        override var canBecomeFocused: Bool { holding }
        override func shouldUpdateFocus(in context: UIFocusUpdateContext) -> Bool {
            // (pad-focus-hold) A text field may always take the focus (Search's Type a Name, a sign-in
            // code): the keyboard must not drop because the holder keeps the focus.
            if PadFocusHold.on, context.nextFocusedItem is UITextInput { return super.shouldUpdateFocus(in: context) }
            if context.previouslyFocusedItem === self, holding { return false }
            return super.shouldUpdateFocus(in: context)
        }
        private func hold() {
            guard holding, let system = UIFocusSystem.focusSystem(for: self), system.focusedItem !== self else { return }
            // (pad-focus-hold) Not from a text field that has the focus (it is being typed in).
            if PadFocusHold.on, system.focusedItem is UITextInput { return }
            system.requestFocusUpdate(to: self)
            system.updateFocusIfNeeded()
            if !Self.heldLogged {
                Self.heldLogged = true
                LogStore.shared.log("[pad-highlight] system focus held off the rows while the highlight shows")
            }
        }
        override func didMoveToWindow() {
            super.didMoveToWindow()
            if let watch { NotificationCenter.default.removeObserver(watch); self.watch = nil }
            if let connectWatch { NotificationCenter.default.removeObserver(connectWatch); self.connectWatch = nil }
            shownSink = nil
            guard window != nil else { return }
            watch = NotificationCenter.default.addObserver(forName: UIFocusSystem.didUpdateNotification, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.hold() }
            }
            if PadFocusHold.on {
                connectWatch = NotificationCenter.default.addObserver(forName: .GCControllerDidConnect, object: nil, queue: .main) { [weak self] _ in
                    MainActor.assumeIsolated {
                        guard let self else { return }
                        if !self.app { self.apply() }
                        self.hold()
                    }
                }
                shownSink = PadHighlight.shared.$shown.removeDuplicates().filter { $0 }
                    .receive(on: DispatchQueue.main)
                    .sink { [weak self] _ in MainActor.assumeIsolated { self?.hold() } }
            }
            if app {
                DispatchQueue.main.async { [weak self] in self?.hold() }
                return
            }
            // The list is in the hierarchy once the Form's first layout ran.
            DispatchQueue.main.async { [weak self] in self?.apply(); self?.hold() }
        }
        private func applied(_ count: Int) {
            guard !Self.appliedLogged else { return }
            Self.appliedLogged = true
            LogStore.shared.log("[pad-highlight] a page's list takes no system focus (\(count))")
        }
        private func apply() {
            // (pad-focus-hold) Now that this view is there with no controller too: a keyboard alone
            // keeps walking the list; the list stops taking the focus once a controller connects.
            if PadFocusHold.on, GCController.controllers().isEmpty { return }
            // Inside a row: the list is an ancestor.
            var up = superview
            while let view = up {
                if let list = view as? UICollectionView {
                    list.allowsFocus = false; list.selectionFollowsFocus = false
                    applied(1)
                    return
                }
                up = view.superview
            }
            var ancestor = superview
            for _ in 0..<8 {
                guard let view = ancestor else { return }
                let found = Self.lists(in: view, depth: 5)
                if !found.isEmpty {
                    for list in found { list.allowsFocus = false; list.selectionFollowsFocus = false }
                    applied(found.count)
                    return
                }
                ancestor = view.superview
            }
        }
        static func lists(in view: UIView, depth: Int) -> [UICollectionView] {
            if let list = view as? UICollectionView { return [list] }
            guard depth > 0 else { return [] }
            return view.subviews.flatMap { lists(in: $0, depth: depth - 1) }
        }
    }
}

/// A sheet over the tabs (a store game's sheet, a Settings sheet): its own layer. B closes it
/// and A runs `accept` (its Install or Open), when it has one.
struct PadSheet: ViewModifier {
    let accept: (() -> Void)?
    @Environment(\.dismiss) private var dismiss
    func body(content: Content) -> some View {
        content
            .padFocusHold()
            .modifier(ClaimGamepadEvents())
            .padLayer("sheet", back: { dismiss() }, accept: accept)
            .onAppear { PadHighlight.shared.sheets += 1 }
            .onDisappear { PadHighlight.shared.sheets = max(0, PadHighlight.shared.sheets - 1) }
    }
}

/// A store's game card for the highlight: A presses it, as a tap does.
struct PadCardStyle: PrimitiveButtonStyle {
    let id: String
    let grid: Bool
    func makeBody(configuration: Configuration) -> some View {
        Group {
            if grid { Button(action: configuration.trigger) { configuration.label }.buttonStyle(LibraryCardButtonStyle()) }
            else { Button(action: configuration.trigger) { configuration.label }.buttonStyle(.plain) }
        }
        .padItem(id, cornerRadius: grid ? 16 : 12, press: configuration.trigger)
    }
}

extension View {
    /// A Form the system's focus must not walk while a controller is connected
    /// (PadNoSystemFocus): the game's pages.
    @ViewBuilder func padNoSystemFocus() -> some View {
        // (pad-focus-hold) Also when the controller connects after the page was built: the view only
        // holds while a controller is connected (Probe.holding), so it can always be there.
        if PadHighlight.enabled, GamepadInput.enabled, PadFocusHold.on || !GCController.controllers().isEmpty {
            background(PadNoSystemFocus().frame(width: 1, height: 1).allowsHitTesting(false))
        } else { self }
    }

    /// A sheet over the tabs: B closes it and A runs `accept` (PadSheet).
    func padSheet(accept: (() -> Void)? = nil) -> some View { modifier(PadSheet(accept: accept)) }
    /// (pad-focus-hold) iPadOS's own focus off every screen while Madeira's highlight shows: on iPad
    /// the controller also walks the system's focus, whose blue fill and ring moved apart from
    /// Madeira's white ring and gray row (Matrix, Nov 24: "one menu is selected Grey and the other
    /// is selected highlighted in Blue"). The page blocker (padNoSystemFocus) was on a few pages only.
    /// One holder per tab stack and per sheet (a sheet's focus is its own). env.MADEIRA_PAD_FOCUS_HOLD = 0: as before.
    @ViewBuilder func padFocusHold() -> some View {
        if PadFocusHold.on, PadHighlight.enabled, GamepadInput.enabled {
            background(PadNoSystemFocus(app: true).frame(width: 1, height: 1).allowsHitTesting(false))
        } else { self }
    }
}

// MARK: - Settings rows (settings-pad-rows)

/// (stock-apple, Nov 22 2026, Cameron: "I wanted the whole app basically just to look like Apple.")
/// Stage 1: the Library grid and the game page use Apple's stock parts (a large title, a segmented
/// control, grouped lists, plain prominent buttons), and the controller's highlight copies Apple's
/// focus look: covers lift with a ring, list rows light up as a whole row, buttons get a ring, all in
/// one color. Glass buttons drop their "interactive" press glow (suspected, unproven, source of the
/// yellow and green blobs in 0.2.84: Apple forums 816909, 826485).
/// env.MADEIRA_STOCK_APPLE = 0: everything as in 0.2.84. Read once.
/// (stock-apple) A highlighted cover lifts a little, with a shadow, as Apple's focused pictures do.
/// Nothing at all is added with the switch off or on a non-cover item (no shadow pass per row).
struct StockAppleLift: ViewModifier {
    let on: Bool
    let cover: Bool
    @ViewBuilder func body(content: Content) -> some View {
        if StockApple.on, cover {
            content
                .scaleEffect(on ? 1.05 : 1)
                .shadow(color: .black.opacity(on ? 0.5 : 0), radius: 14, y: 8)
                .animation(PadHighlight.animation, value: on)
        } else {
            content
        }
    }
}

/// (pad-pop-keep) A sub-page closing late never moves a highlight that is already on the page under it
/// (PadHighlight.pop). env.MADEIRA_PAD_POP_KEEP = 0: as in 0.2.84. Read once.
/// (pad-layer-keep) A page with another page pushed over it keeps its layer (PadHighlight.leave).
/// env.MADEIRA_PAD_LAYER_KEEP = 0: as in 0.2.87. Read once.
enum PadLayerKeep {
    static let on = MadeiraConfig.flag("MADEIRA_PAD_LAYER_KEEP")
}

enum PadPopKeep {
    static let on = MadeiraConfig.flag("MADEIRA_PAD_POP_KEEP")
}

/// (pad-focus-hold) See View.padFocusHold. Read once.
enum PadFocusHold {
    static let on = MadeiraConfig.flag("MADEIRA_PAD_FOCUS_HOLD")
}

enum StockApple {
    static let on = MadeiraConfig.flag("MADEIRA_STOCK_APPLE")
    /// Stage 2 (Nov 22 2026, Cameron's yes): the game page's rating as a list row, and the Stores,
    /// Settings and Downloads tabs as Apple's plain lists on a wide iPad too (no rail beside a stage).
    /// env.MADEIRA_STOCK_APPLE_2 = 0: as in 0.2.87. Needs stage 1 on. Read once.
    static let stage2 = on && MadeiraConfig.flag("MADEIRA_STOCK_APPLE_2")
    /// Stage 3 (Nov 22 2026, Cameron's pick "Spidy's design (B)"): game art behind the Library and the
    /// game page, one JIT and Memory+ button, smaller run marks, the Store tab as one list of every
    /// store's games, and "Why this rating" as a pushed page. Only the look changes; every feature
    /// stays reachable by touch and controller. env.MADEIRA_STOCK_APPLE_3 = 0: all of it off, as in
    /// 0.2.88. Needs stage 1 on. Read once. Each part below has its own switch too.
    static let stage3 = on && MadeiraConfig.flag("MADEIRA_STOCK_APPLE_3")
    /// Stage 4 (Nov 24 2026, Cameron: "for the stock Apple look, we never finished that?"): the starting
    /// screen, the store pages, first-time setup, Get Help, the rate card and the last custom pills as
    /// Apple's grouped lists and buttons. Only the look changes. env.MADEIRA_STOCK_APPLE_4 = 0: as in
    /// 0.2.99. Needs stage 1 on. Read once.
    static let stage4 = on && MadeiraConfig.flag("MADEIRA_STOCK_APPLE_4")
    /// env.MADEIRA_ART_HEADER = 0: no game art behind the Library and the game page.
    static let artHeader = stage3 && MadeiraConfig.flag("MADEIRA_ART_HEADER")
    /// env.MADEIRA_JIT_BOLT = 0: the Library keeps its two JIT and Memory+ pills.
    static let jitBolt = stage3 && MadeiraConfig.flag("MADEIRA_JIT_BOLT")
    /// env.MADEIRA_STORE_LIST = 0: the Store tab is the list of store pages again.
    static let storeList = stage3 && MadeiraConfig.flag("MADEIRA_STORE_LIST")
    /// env.MADEIRA_WHY_PAGE = 0: "Why this rating" opens as a sheet from the game page again.
    static let whyPage = stage3 && MadeiraConfig.flag("MADEIRA_WHY_PAGE")
    /// Settings › Appearance › Game art behind pages (on when never set).
    static let artKey = "madeiraArtBehindPages"
    /// Settings › Appearance › Names on covers (on when never set; a new install starts with it off).
    static let namesKey = "madeiraGridCoverNames"
    /// The ring's color: the label color (white in dark mode), the same on every screen; 0.2.84 used
    /// the accent color, which a tint above the item could change.
    static var ring: Color { on ? Color.primary : Color.accentColor }
    /// A list row: every row in Madeira's lists (padRow, NewLookLinkRow, the game page's rows) is
    /// tagged with inset -6; covers, cards and buttons use the usual -4, a tab in the tab bar 0.
    static func isRow(capsule: Bool, grid: String?, inset: CGFloat) -> Bool {
        !capsule && grid == nil && inset == -6
    }
}

/// Settings' pages (SettingsPageView) had a layer of their own but almost no items on it, so
/// past the Settings tab's list the highlight had nowhere to go and only B worked (Cameron, Nov
/// 21 2026: "when you get deep into setting the controller doesn't work the farther you get into
/// tabs"). Each row of those pages is now an item: A flips a switch, steps a picker to its next
/// choice, or presses a button or opens a link, as a tap does. env.MADEIRA_PAD_SETTINGS_ROWS = 0:
/// as in 0.2.81 (only Console look and Cover size). Read once.
enum PadSettingsRows {
    static let on = MadeiraConfig.flag("MADEIRA_PAD_SETTINGS_ROWS")
}

/// pad-pages (Cameron, Nov 22 2026, 0.2.83: "the D-pad doesn't work for [the sliders]" and "the
/// D-pad doesn't work to move in and out of settings"): on a slider, switch or choice row left and
/// right change it; with nothing to the right, right opens a row's page; with nothing to the left,
/// left goes back a page. env.MADEIRA_PAD_DPAD_ROWS = 0: left and right only move, as in 0.2.83. Read once.
enum PadDpadRows {
    static let on = MadeiraConfig.flag("MADEIRA_PAD_DPAD_ROWS")
}

/// Controller binds, Gyro aim & turbo and Mouse put their Reset on the page once (Library.swift
/// page(_:)): on the page's Sections it came out 5 to 7 times (Cameron, Nov 22 2026, 0.2.83).
/// env.MADEIRA_PAGE_TOOLBAR_ONCE = 0: as in 0.2.83. Read once.
enum PageToolbarOnce {
    static let on = MadeiraConfig.flag("MADEIRA_PAGE_TOOLBAR_ONCE")
}

/// The value `by` steps from `current` in `values`, held at the first and last (a value not in
/// `values` goes to the first).
func padStep<T: Equatable>(_ values: [T], from current: T, by: Int) -> T {
    guard let first = values.first else { return current }
    guard let index = values.firstIndex(of: current) else { return first }
    return values[min(values.count - 1, max(0, index + by))]
}

extension View {
    /// A Settings row the controller reaches (PadSettingsRows): A runs `press`.
    @ViewBuilder func padRow(_ id: String, when: Bool = true, adjust: ((Int) -> Void)? = nil, opens: Bool = false,
                             press: @escaping () -> Void) -> some View {
        // padRowFill: a button row's outline is the whole row, as on Settings' list (NewLookPadFix.ringMatch).
        if PadSettingsRows.on {
            padRowFill().padItem(id, cornerRadius: 12, when: when, inset: -6, adjust: adjust, opens: opens, press: press)
        } else { self }
    }
    /// A switch row: A flips it; left turns it off, right on (PadDpadRows).
    func padToggle(_ id: String, _ isOn: Binding<Bool>, when: Bool = true) -> some View {
        padRow(id, when: when, adjust: { let v = $0 > 0; if isOn.wrappedValue != v { isOn.wrappedValue = v } }) { isOn.wrappedValue.toggle() }
    }
    /// A picker row: A steps to the next of `values` (after the last, the first); left and right
    /// step back and on, stopping at the ends (PadDpadRows).
    func padPicker<T: Equatable>(_ id: String, _ selection: Binding<T>, _ values: [T], when: Bool = true) -> some View {
        padRow(id, when: when && !values.isEmpty, adjust: { let v = padStep(values, from: selection.wrappedValue, by: $0); if v != selection.wrappedValue { selection.wrappedValue = v } }) {
            selection.wrappedValue = padNext(values, after: selection.wrappedValue)
        }
    }
    /// A slider row: A steps to the next of `values` (after the last, the first; a value between
    /// two steps goes to the next step above it); left and right step down and up, stopping at the ends.
    func padSlider(_ id: String, _ value: Binding<Double>, _ values: [Double], when: Bool = true) -> some View {
        padRow(id, when: when && !values.isEmpty, adjust: { by in
            let now = value.wrappedValue
            let v = by > 0 ? (values.first(where: { $0 > now + 0.0001 }) ?? values[values.count - 1])
                           : (values.last(where: { $0 < now - 0.0001 }) ?? values[0])
            if abs(v - now) > 0.0001 { value.wrappedValue = v }  // at an end: no write
        }) {
            let now = value.wrappedValue
            value.wrappedValue = values.first(where: { $0 > now + 0.0001 }) ?? values[0]
        }
    }
    /// A slider over `range` (pad-pages): left and right move it by `step`, held repeats; A steps up
    /// by `step` and wraps to the bottom after the top.
    func padRange(_ id: String, _ value: Binding<Double>, in range: ClosedRange<Double>, step: Double, when: Bool = true) -> some View {
        padRow(id, when: when, adjust: { by in
            let now = value.wrappedValue
            let v = min(range.upperBound, max(range.lowerBound, now + Double(by) * step))
            if abs(v - now) > 0.0001 { value.wrappedValue = v }  // at an end: no write
        }) {
            let up = value.wrappedValue + step
            value.wrappedValue = up > range.upperBound + 0.0001 ? range.lowerBound : min(range.upperBound, up)
        }
    }
    /// A page pushed from a Settings page (Advanced › Logs, a log): B goes back a page, and the
    /// system focus stays off its list as on the Settings page under it.
    @ViewBuilder func padSettingsSubpage() -> some View {
        if PadSettingsRows.on { modifier(PadSettingsForm()).modifier(NewLookSettingsChrome()) } else { self }
    }
}

/// A Settings page's Form, as a game's pages are (Library.swift page(_:)): it scrolls to follow
/// the highlight, so rows below the screen are laid out and reachable, and the system's focus
/// stays off its rows while Madeira's highlight walks them (PadNoSystemFocus). Off with PadSettingsRows.
struct PadSettingsForm: ViewModifier {
    @ViewBuilder func body(content: Content) -> some View {
        if PadSettingsRows.on {
            ScrollViewReader { reader in content.padScrollFollow(reader) }.padNoSystemFocus()
        } else { content }
    }
}

// MARK: - Links inside a page's rows (pad-pages)

/// A page pushed by the controller from a row (padLink): the destination, shown by the page's
/// PadPushHost. Equal by id, so each push is a new page.
struct PadPushPage: Identifiable, Hashable {
    let id = UUID()
    let view: AnyView
    static func == (a: PadPushPage, b: PadPushPage) -> Bool { a.id == b.id }
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

/// How a row inside a page asks the page to push a destination.
final class PadPushBox: @unchecked Sendable {
    let push: (AnyView) -> Void
    init(_ push: @escaping (AnyView) -> Void) { self.push = push }
}

private struct PadPushKey: EnvironmentKey { static var defaultValue: PadPushBox? { nil } }
extension EnvironmentValues {
    /// The nearest page that can push a row's destination (PadPushHost), nil outside one.
    var padPush: PadPushBox? {
        get { self[PadPushKey.self] }
        set { self[PadPushKey.self] = newValue }
    }
}

/// On a page's Form (not inside its rows, where SwiftUI ignores a navigationDestination): pushes
/// what a padLink row inside asks for. A NavigationLink cannot be pressed from code, so a row with
/// one gets padLink and the controller's A or D-pad right opens the same page through here.
struct PadPushHost: ViewModifier {
    @State private var page: PadPushPage?
    @State private var box: PadPushBox?  // made once, so padLink rows are not redrawn each render
    @ViewBuilder func body(content: Content) -> some View {
        if PadSettingsRows.on {
            content
                .environment(\.padPush, box)
                .onAppear { if box == nil { let page = $page; box = PadPushBox { page.wrappedValue = PadPushPage(view: $0) } } }
                .navigationDestination(item: $page) { $0.view }
        } else {
            content
        }
    }
}

extension View {
    /// A NavigationLink row the controller can open (A, or D-pad right): pushes `destination`
    /// through the page's PadPushHost, with B back.
    func padLink<Destination: View>(_ id: String, when: Bool = true, @ViewBuilder _ destination: @escaping () -> Destination) -> some View {
        modifier(PadLinkRow(id: id, when: when, destination: destination))
    }
}

private struct PadLinkRow<Destination: View>: ViewModifier {
    let id: String
    let when: Bool
    let destination: () -> Destination
    @Environment(\.padPush) private var push
    func body(content: Content) -> some View {
        content.padRow(id, when: when && push != nil, opens: true) {
            push?.push(AnyView(destination().padSettingsSubpage()))
        }
    }
}
