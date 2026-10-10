#!/usr/bin/env python3
"""Print the ticket board, the tickets ready to start, and validate tickets.

  python3 tickets/board.py            board + tickets needing a human + ready list
  python3 tickets/board.py -m M0      only one milestone
  python3 tickets/board.py --next-id  next free TP- id
  python3 tickets/board.py --check    validate frontmatter and dependencies
  python3 tickets/board.py --waves    unfinished tickets grouped by dependency depth
"""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
COLUMNS = ["backlog", "in-progress", "blocked", "review", "has-errors", "done"]
REQUIRED = ["id", "title", "milestone", "area", "repo", "size", "depends_on"]
SIZES = {"S", "M", "L", "epic"}
NEEDS_HUMAN = {"decision", "macos", "windows", "person"}


def parse(path):
    text = path.read_text()
    match = re.match(r"---\n(.*?)\n---\n", text, re.S)
    if not match:
        raise ValueError(f"{path}: no frontmatter")
    meta = {}
    for line in match.group(1).splitlines():
        line = line.split(" #", 1)[0].rstrip()
        if not line.strip():
            continue
        key, _, value = line.partition(":")
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            value = [v.strip() for v in value[1:-1].split(",") if v.strip()]
        else:
            value = value.strip('"')
        meta[key.strip()] = value
    return meta


def load():
    tickets = {}
    for column in COLUMNS:
        for path in sorted((ROOT / column).glob("*.md")):
            meta = parse(path)
            meta["column"] = column
            meta["path"] = path
            tickets[meta["id"]] = meta
    return tickets


def ready(tickets):
    return [
        t for t in tickets.values()
        if t["column"] == "backlog"
        and t.get("size") != "epic"
        and all(tickets.get(d, {}).get("column") == "done" for d in t.get("depends_on", []))
    ]


def check(tickets):
    problems = []
    for t in tickets.values():
        for key in REQUIRED:
            if key not in t:
                problems.append(f"{t['id']}: missing {key}")
        if t.get("size") not in SIZES:
            problems.append(f"{t['id']}: size must be one of {sorted(SIZES)}")
        if "needs_human" in t and t["needs_human"] not in NEEDS_HUMAN:
            problems.append(f"{t['id']}: needs_human must be one of {sorted(NEEDS_HUMAN)}")
        if not t["path"].name.startswith(t["id"] + "-"):
            problems.append(f"{t['id']}: file name {t['path'].name} doesn't start with its id")
        for dep in t.get("depends_on", []):
            if dep not in tickets:
                problems.append(f"{t['id']}: depends on unknown {dep}")
        if t["column"] == "in-progress" and not (t.get("owner") and t.get("branch")):
            problems.append(f"{t['id']}: in progress without owner/branch")
    # dependency cycles
    state = {}

    def visit(tid, trail):
        if state.get(tid) == "done":
            return
        if state.get(tid) == "visiting":
            problems.append("cycle: " + " → ".join(trail + [tid]))
            return
        state[tid] = "visiting"
        for dep in tickets.get(tid, {}).get("depends_on", []):
            if dep in tickets:
                visit(dep, trail + [tid])
        state[tid] = "done"

    for tid in tickets:
        visit(tid, [])
    return problems


def waves(tickets):
    """Group unfinished tickets by the length of their longest chain of
    unfinished dependencies: everything in wave N can run in parallel once
    waves 0..N-1 are done."""
    depth = {}

    def visit(tid):
        if tid not in depth:
            open_deps = [d for d in tickets[tid].get("depends_on", [])
                         if d in tickets and tickets[d]["column"] != "done"]
            depth[tid] = 1 + max((visit(d) for d in open_deps), default=-1)
        return depth[tid]

    grouped = {}
    for tid, t in tickets.items():
        if t["column"] != "done":
            grouped.setdefault(visit(tid), []).append(t)
    return [grouped[k] for k in sorted(grouped)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--milestone")
    parser.add_argument("--next-id", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--waves", action="store_true")
    args = parser.parse_args()

    tickets = load()

    if args.waves:
        for n, wave in enumerate(waves(tickets)):
            print(f"wave {n}: " + ", ".join(
                f"{t['id']}{'*' if t['column'] == 'blocked' else ''}{'!' if t.get('needs_human') else ''}"
                for t in sorted(wave, key=lambda t: t["id"])))
        print("(* = blocked, ! = needs a human)")
        return 0

    if args.next_id:
        numbers = [int(t[3:]) for t in tickets if t.startswith("TP-")]
        print(f"TP-{max(numbers, default=0) + 1:03d}")
        return 0

    if args.check:
        problems = check(tickets)
        print("\n".join(problems) or "ok")
        return 1 if problems else 0

    shown = [t for t in tickets.values() if not args.milestone or t["milestone"] == args.milestone]
    for column in COLUMNS:
        items = [t for t in shown if t["column"] == column]
        print(f"\n{column.upper()} ({len(items)})")
        for t in items:
            extra = f"  [{t['owner']}]" if t.get("owner") else ""
            print(f"  {t['id']:8} {t['milestone']:5} {t['size']:5} {t['title']}{extra}")

    print("\nNEEDS HUMAN")
    for t in sorted(shown, key=lambda t: t["id"]):
        if t.get("needs_human") and t["column"] != "done":
            print(f"  {t['id']:8} {t['milestone']:5} {t['needs_human']:8} {t['title']}")

    print("\nREADY")
    for t in ready(tickets):
        if not args.milestone or t["milestone"] == args.milestone:
            print(f"  {t['id']:8} {t['milestone']:5} {t['size']:5} {t['title']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
