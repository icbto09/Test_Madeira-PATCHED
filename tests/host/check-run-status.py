#!/usr/bin/env python3
"""Host check for run-badge-grid fix1: the "Does it run?" data and "Why this rating" stay honest.

Usage: python3 tests/host/check-run-status.py [repo root]   (no Swift typecheck here)

1. Every key in app/Madeira/run-status.json names the game it is filed under: each steam:<id> is
   the title Steam's store gives that id (looked up Nov 22 2026, store.steampowered.com/api/appdetails),
   each title: key is the game's own title, no key is filed under two games.
2. Every game rated runsWithFixes has fix lines the app can show: Madeira's own list for it
   (GameRecommendations.swift: its Steam id, or a program name for a copy from another store) or
   hand lines in the data. RunStatus.swift never says "None for this game" beside Runs with fixes.
3. "latest: X" is not baked into the data: the app says it with its own build (runningBuild).
4. The pill is a Button with a 44 pt area, Y on the game page opens the sheet, VoiceOver says
   "<tier>. Why this rating", and the cover's long-press menu keeps its tier row.
5. run-status.json is what scripts/make-run-status.py writes from scripts/run-results.txt.
"""
import json, os, re, subprocess, sys, tempfile

root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", ".."))
fails = 0


def ok(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += (not cond)


def read(rel):
    with open(os.path.join(root, rel), encoding="utf-8") as f:
        return f.read()


# Steam store names (Nov 22 2026) for every steam: key, shortened to the title the data uses.
STEAM = {
    251570: "7 Days to Die", 107410: "Arma 3", 2141730: "Backrooms: Escape Together",
    200260: "Batman: Arkham City GOTY", 284160: "BeamNG.drive", 2406770: "Bodycam", 49520: "Borderlands 2",
    291550: "Brawlhalla", 2835570: "Buckshot Roulette", 42700: "Call of Duty: Black Ops",
    202970: "Call of Duty: Black Ops II", 212910: "Call of Duty: Black Ops II",  # store: "Black Ops II - Zombies"
    311210: "Call of Duty: Black Ops III", 10180: "Call of Duty: Modern Warfare 2 (2009)",
    231430: "Company of Heroes 2", 548430: "Deep Rock Galactic", 1671210: "DELTARUNE",
    1222140: "Detroit: Become Human", 1239080: "Door Kickers 2", 2135150: "Elin", 427520: "Factorio",
    22380: "Fallout: New Vegas", 3551340: "Football Manager 26", 3194360: "Formula Legends", 4000: "Garry's Mod",
    962130: "Grounded", 1030300: "Hollow Knight: Silksong", 1092790: "Inscryption", 8190: "Just Cause 2",
    2552450: "Kingdom Hearts III", 32440: "LEGO Star Wars: The Complete Saga", 1966720: "Lethal Company",
    860510: "Little Nightmares II", 2357570: "Overwatch 2", 1113000: "Persona 4 Golden", 108600: "Project Zomboid",
    1196590: "Resident Evil Village", 294100: "RimWorld", 632360: "Risk of Rain 2",
    1295660: "Sid Meier's Civilization VII", 2868840: "Slay the Spire 2", 413150: "Stardew Valley",
    1962700: "Subnautica 2", 440: "Team Fortress 2", 1167630: "Teardown", 105600: "Terraria",
    641990: "The Escapists 2", 391540: "Undertale", 1574820: "Until Then",
}

# Title keys that are another store's name for the game (Steam's store now calls it "Overwatch®" too).
TITLE_ALIASES = {"title:overwatch": "Overwatch 2"}


def own_title(key, title):
    return TITLE_ALIASES.get(key) == title or key[6:] == re.sub(r"\s*\((epic|gog|steam)\)$", "", title.lower())


data = json.loads(read("app/Madeira/run-status.json"))
games = data["games"]

# 1. keys name their game
owner = {}
for g in games:
    for k in g["keys"]:
        if k in owner:
            ok(False, f"key {k} is filed under {owner[k]!r} and {g['title']!r}")
        owner.setdefault(k, g["title"])
        if k.startswith("steam:"):
            want = STEAM.get(int(k[6:]))
            if want is None:
                ok(False, f"{k} ({g['title']}): add its Steam store name to STEAM in this check")
            elif want != g["title"]:
                ok(False, f"{k} is {want!r} on Steam, but run-status.json files it under {g['title']!r}")
        elif k.startswith("title:"):
            if not own_title(k, g["title"]):
                ok(False, f"{k} is not the title of {g['title']!r}")
steam_keys = [k for g in games for k in g["keys"] if k.startswith("steam:")]
ok(all(STEAM.get(int(k[6:])) == owner[k] for k in steam_keys),
   f"all {len(steam_keys)} steam keys map to their Steam title")
ok(len(owner) == sum(len(g["keys"]) for g in games), "no key is filed under two games")
ok(all(own_title(k, owner[k]) for k in owner if k.startswith("title:")),
   "every title key is its game's own title")
re_v = next((g for g in games if "steam:1196590" in g["keys"]), None)
ok(re_v is not None and re_v["title"] == "Resident Evil Village"
   and "MADEIRA_WG_64BIT" in json.dumps(re_v), "steam:1196590 = Resident Evil Village, the only game with the WG_64BIT row")
ok(sum("MADEIRA_WG_64BIT" in json.dumps(g) for g in games) == 1, "MADEIRA_WG_64BIT shows under one game only")

# 2. Runs with fixes has lines to show
recs = read("app/Madeira/GameRecommendations.swift")
rec_ids, rec_programs = set(), set()
for m in re.finditer(r"SteamTitle\(appIDs:\s*\[([\d,\s]*)\],\s*folders:[^\n]*\n\s*programs:\s*\[([^\]]*)\]", recs):
    ids = {int(x) for x in re.findall(r"\d+", m.group(1))}
    rec_ids |= ids
    if m.group(2).strip():
        rec_programs |= ids
for m in re.finditer(r"\b\w+AppIDs?\b[^=\n]*=\s*(\[[\d,\s]+\]|\d+)", recs):
    rec_ids |= {int(x) for x in re.findall(r"\d+", m.group(1))}
ok(len(rec_ids) > 50, f"read {len(rec_ids)} Steam ids with a list of their own from GameRecommendations.swift")
for g in games:
    if not any(r["tier"] == "runsWithFixes" for r in g["results"]):
        continue
    hand = g.get("handLines") or []
    for k in g["keys"]:
        if k.startswith("steam:"):
            covered = bool(hand) or int(k[6:]) in rec_ids
            why = "hand lines" if hand else "Madeira's list"
        else:
            # A copy from another store: its program must be in a list, or the lines are by hand.
            ids = [int(x[6:]) for x in g["keys"] if x.startswith("steam:")]
            covered = bool(hand) or any(i in rec_programs for i in ids)
            why = "hand lines" if hand else "a list's program"
        ok(covered, f"{g['title']} ({k}) is Runs with fixes and shows {why if covered else 'NO fix lines'}")
rs = read("app/Madeira/RunStatus.swift")
m = re.search(r"private func fixLines\(_ status: RunStatus\) -> String \{(.*?)\n    \}", rs, re.S)
body = m.group(1) if m else ""
ok('L("None for this game")' in body and re.search(r'status\.tier == \.runsWithFixes \? L\("Not in the app yet[^"]*"\) : L\("None for this game"\)', body),
   'fixLines says "None for this game" only when the tier is not Runs with fixes')
ok('L("Add by hand: %@")' in body and "byHand" in body, 'fixLines shows "Add by hand: <line>"')

# 3. latest comes from the running app
ok("latest:" not in json.dumps(data) and all("retestReason" not in g for g in games), "run-status.json has no baked-in latest: build")
ok(all(g.get("retestBuild") for g in games if g.get("retest")), "every Retest game names the build it was tested on")
ok("static let runningBuild" in rs and "BuildStamp.text" in rs, "runningBuild is read from the app's own build stamp")
ok(re.search(r"latest: %@\). Retest suggested\.\"\),\s*\n\s*status\.game\?\.retestBuild[^\n]*runningBuild\)", rs) is not None,
   "the Retest words fill latest with runningBuild")
ok("retestReason ??" not in rs, "the sheet no longer reads a stored retestReason")

# 4. tap target, Y, VoiceOver, long-press menu
pill = re.search(r"struct RunStatusPill: View \{(.*?)\n\}", rs, re.S).group(1)
ok("Button(action: why)" in pill and ".frame(minWidth: 44, minHeight: 44)\n            .contentShape(Rectangle())" in pill,
   "the pill is a Button with a 44 pt area")
ok('.accessibilityLabel(status.tier.word + ". " + L("Why this rating"))' in pill, 'VoiceOver label is "<tier>. Why this rating"')
ok(".padItem(padID, when: pad, capsule: true, press: why)" in pill, "A on the highlighted pill opens the sheet")
lib = read("app/Madeira/Library.swift")
ok(".padLayerAlt(RunBadge.enabled && entry.desktop != true ? { runWhy = true } : nil)" in lib, "Y on the game page opens the sheet")
# stock-apple-stage3: the same sheet with env.MADEIRA_WHY_PAGE = 0, else a pushed page, both from the page's entry.
ok(".sheet(isPresented: StockApple.whyPage ? .constant(false) : $runWhy) { RunStatusWhySheet(entry: entry) }" in lib
   and ".navigationDestination(isPresented: StockApple.whyPage ? $runWhy : .constant(false)) { RunStatusWhyPage(entry: entry) }" in lib,
   "the sheet (or the stage-3 page) is built from the page's own entry")
ok(lib.count("RunStatusPill(entry: entry) { runWhy = true }") == 2, "both game-page layouts have the pill")
ok('RunStatusPill(entry: game.entry, padID: "gr-run-status") { RunBadge.autoWhy = game.entry.id; open(game.entry) }' in rs,
   "the iPad header pill opens that game's page and its sheet")
ok("Button { RunBadge.autoWhy = game.entry.id; open(game.entry) } label: {\n                    Label(status.tier.word" in rs,
   "the cover's long-press menu keeps its tier row")
ok("Text(entry.title).font(.headline)" in rs, "the sheet names its game")

# 5. data matches the generator
with tempfile.TemporaryDirectory() as tmp:
    out = os.path.join(tmp, "run-status.json")
    r = subprocess.run([sys.executable, os.path.join(root, "scripts/make-run-status.py"), "--newest", data["newestBuild"],
                        "--core-changed", data["newestBuild"], "--out", out], capture_output=True, text=True)
    same = r.returncode == 0 and json.load(open(out))["games"] == games
    ok(same, "run-status.json matches make-run-status.py output for run-results.txt" + ("" if r.returncode == 0 else ": " + r.stderr.strip()))

print(f"{fails} failed")
sys.exit(1 if fails else 0)
