//
//  RecommendedMergeView.swift
//  Madeira
//
//  recommended-merge: the library's "Madeira added recommended settings" question, Keep or
//  Undo, after RecommendedMerge.swift added missing lines to games that have a config of
//  their own. One question for all games waiting. It waits until no game, error or Get Help
//  question is showing, as SharedConfigsNotice does.
//

import SwiftUI

struct RecommendedMergeNotice: ViewModifier {
    @ObservedObject private var model = LibraryModel.shared
    @ObservedObject private var help = GetHelpCenter.shared
    @State private var asking: [RecommendedMerge.Added] = []
    private let ticker = Timer.publish(every: 2, on: .main, in: .common).autoconnect()
    @State private var tick = 0   // re-checks the shared-settings question, which is not observable

    private var title: String {
        guard let first = asking.first else { return "" }
        return asking.count == 1 ? String(format: L("Madeira added recommended settings to %@"), first.title)
                                 : String(format: L("Madeira added recommended settings to %ld games"), asking.count)
    }

    private var detail: String {
        let names = asking.prefix(3).map { $0.title }.joined(separator: ", ") + (asking.count > 3 ? ", ..." : "")
        let lines = asking.reduce(0) { $0 + $1.lines.count }
        return String(format: L("%@: %ld missing config line(s) were added at the end of the game's config. Your own lines were not changed. Undo removes exactly the added lines."), names, lines)
    }

    func body(content: Content) -> some View {
        content
            .background {
                Color.clear
                    .alert(title,
                           isPresented: Binding(get: { _ = tick; return !asking.isEmpty && model.error == nil && model.current == nil && help.open == nil
                                                    && help.offer == nil && help.fixAsk == nil && help.worksAsk == nil
                                                    && SharedConfigs.nextPending == nil },
                                                set: { _ in })) {
                        Button("Keep", role: .cancel) { finish(undo: false) }
                        Button("Undo") { finish(undo: true) }
                    } message: { Text(detail) }
            }
            .onReceive(ticker) { _ in if !asking.isEmpty { tick &+= 1 } }
            .onAppear(perform: next)
            .onReceive(NotificationCenter.default.publisher(for: RecommendedMerge.notification).receive(on: RunLoop.main)) { _ in next() }
    }

    private func next() { if asking.isEmpty { asking = RecommendedMerge.pending } }

    private func finish(undo: Bool) {
        let list = asking
        asking = []
        RecommendedMerge.answered(list, undo: undo)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { next() }
    }
}
