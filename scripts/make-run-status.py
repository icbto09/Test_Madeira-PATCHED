#!/usr/bin/env python3
"""Writes app/Madeira/run-status.json (the "Does it run?" status labels) from our own records.

usage: make-run-status.py --newest 0.2.82 --core-changed 0.2.82 [--results scripts/run-results.txt]
                          [--out app/Madeira/run-status.json] [--extra extra.json] [--check]

  --newest        the build this file ships in
  --core-changed  the newest build that changed Wine, FEX or DXMT (every game uses them):
                  a result tested before it gets the Retest flag
  --extra         optional JSON {"<first key>": {"sentry": "...", "reports": "..."}} with Sentry
                  crash counts and Get Help report counts in words, when someone has pulled them
  --check         only validate; exit 1 on any problem

Only proven results go in: every line of run-results.txt must name its source. A game with no
line is left out, and the app shows it as "Not tested yet". Nothing here guesses a tier.
"""
import argparse, json, re, sys, datetime
from pathlib import Path

TIERS = {"runsWell", "runsWithFixes", "runsWithProblems", "startsOnly", "doesntRun"}
DEVICES = {"iPhone", "iPad", "unknown"}
KEY = re.compile(r"^(steam:\d+|exe:[^,\s][^,]*\.exe|title:[^,]+)$")


def build_number(build):
    """0.2.N -> N; anything else (Wave 5, build 67, public 0.2.0) is older than every 0.2.x nightly."""
    m = re.fullmatch(r"0\.2\.(\d+)", build.strip())
    return int(m.group(1)) if m else -1


def parse(path):
    games, problems, hand = {}, [], []
    for n, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        f = [x.strip() for x in line.split(" | ")]
        if f[0] == "hand":
            # hand | <first key> | <config line> | <source>: a line the player adds by hand.
            if len(f) != 4 or not f[2] or not f[3] or f[3] == "-":
                problems.append(f"line {n}: hand lines are: hand | <first key> | <config line> | <source>"); continue
            hand.append((n, f[1].lower(), f[2]))
            continue
        if len(f) != 9:
            problems.append(f"line {n}: {len(f)} fields, want 9"); continue
        keys, title, device, tier, build, summary, source, last, first = f
        keys = [k.strip().lower() for k in keys.split(",") if k.strip()]
        bad = [k for k in keys if not KEY.match(k)]
        if not keys or bad: problems.append(f"line {n}: bad keys {bad or keys}")
        if device not in DEVICES: problems.append(f"line {n}: device {device!r}")
        if tier not in TIERS: problems.append(f"line {n}: tier {tier!r}")
        if not source or source == "-": problems.append(f"line {n}: no source (only proven results)")
        if not build or not summary: problems.append(f"line {n}: build and summary are needed")
        game = games.setdefault(keys[0], {"keys": [], "title": title, "results": []})
        for k in keys:
            if k not in game["keys"]: game["keys"].append(k)
        game["results"].append({"device": device, "tier": tier, "build": build, "summary": summary, "source": source})
        if last != "-": game["lastGood"] = last
        if first != "-": game["firstGood"] = first
    seen = {}
    for first_key, game in games.items():
        for k in game["keys"]:
            if k in seen and seen[k] != first_key:
                problems.append(f"key {k} names two games ({seen[k]}, {first_key})")
            seen[k] = first_key
    for n, key, text in hand:
        game = games.get(seen.get(key, ""))
        if game is None:
            problems.append(f"line {n}: hand line for {key}, which has no result"); continue
        lines = game.setdefault("handLines", [])
        if text in lines:
            problems.append(f"line {n}: hand line {text!r} is already there for {key}"); continue
        lines.append(text)
    return games, problems


def main():
    ap = argparse.ArgumentParser()
    root = Path(__file__).resolve().parent.parent
    ap.add_argument("--results", default=str(root / "scripts/run-results.txt"))
    ap.add_argument("--out", default=str(root / "app/Madeira/run-status.json"))
    ap.add_argument("--newest", required=True)
    ap.add_argument("--core-changed", required=True)
    ap.add_argument("--extra")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if build_number(a.newest) < 0 or build_number(a.core_changed) < 0:
        sys.exit("--newest and --core-changed must look like 0.2.N")

    games, problems = parse(a.results)
    extra = json.loads(Path(a.extra).read_text()) if a.extra else {}
    core = build_number(a.core_changed)
    for first_key, game in games.items():
        # Builds that are not 0.2.N (Wave 13, Test 16, build 67) all rank the same; on a tie the
        # later line in run-results.txt wins, so add newer results below older ones.
        newest = max(enumerate(game["results"]), key=lambda ir: (build_number(ir[1]["build"]), ir[0]))[1]
        tested = build_number(newest["build"])
        game["retest"] = tested < core
        if game["retest"]:
            # The app says the words, with its own build as "latest" (RunStatusStore.runningBuild).
            game["retestBuild"] = newest["build"]
        for field in ("sentry", "reports"):
            if extra.get(first_key, {}).get(field):
                game[field] = extra[first_key][field]

    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print(f"{len(games)} games, {sum(len(g['results']) for g in games.values())} results, "
          f"{sum(g['retest'] for g in games.values())} with Retest")
    if a.check:
        return
    out = {"version": 1, "generated": datetime.date.today().isoformat(), "newestBuild": a.newest,
           "games": sorted(games.values(), key=lambda g: g["title"].lower())}
    Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", a.out)


if __name__ == "__main__":
    main()
