#!/usr/bin/env python3
"""Print the ticket board, the tickets ready to start, and validate tickets.

  python3 tickets/board.py            board + tickets needing a human + ready list
  python3 tickets/board.py -m M0      only one milestone
  python3 tickets/board.py --next-id  next free TP- id (--next-id KRN: next free KRN- id); sees ids
                                      on this checkout and on every local and remote branch
  python3 tickets/board.py --check    validate frontmatter and dependencies
  python3 tickets/board.py --waves    unfinished tickets grouped by dependency depth
"""

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
COLUMNS = ["backlog", "in-progress", "blocked", "review", "has-errors", "done"]
REQUIRED = ["id", "title", "milestone", "area", "repo", "size", "depends_on"]
SIZES = {"S", "M", "L", "epic"}
NEEDS_HUMAN = {"decision", "macos", "windows", "person"}
DESIGN_REF = re.compile(r"(.+)#([\w-]+)$")
RESIDUALS = "RESIDUAL-RISKS.md"


def gh_slug(heading):
    """A heading's anchor slug the way GitHub computes it."""
    s = heading.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s, flags=re.UNICODE)
    return s.replace(" ", "-")


def strip_fences(text):
    lines, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            lines.append(line)
    return "\n".join(lines)


def anchors_of(text):
    """A file's heading anchors as GitHub computes them: fenced code blocks
    hold no headings, and a repeated heading's anchor gets -1, -2, ..."""
    anchors, seen = set(), {}
    for m in re.finditer(r"^#{1,6}\s+(.+?)\s*$", strip_fences(text), re.M):
        slug = gh_slug(m.group(1))
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        anchors.add(slug if n == 0 else f"{slug}-{n}")
    return anchors


def ref_targets(root):
    """Files a `refs:` entry may point into, with each one's heading anchors."""
    heads = {}
    for rel in ["DESIGN.md", "PRD.md", RESIDUALS] + sorted(
        f"docs/design/{p.name}" for p in (root / "docs" / "design").glob("*.md")
    ):
        path = root / rel
        if not path.exists():
            continue
        heads[rel] = anchors_of(path.read_text())
    return heads


def requirement_ids(root):
    """The PRD's requirement ids, from the first column of its requirement
    tables; M0-M5 are milestones, not requirements."""
    text = (root / "PRD.md").read_text()
    return {m.group(1) for m in re.finditer(r"^\|\s*([A-Z]\d+)\s*\|", text, re.M)
            if not m.group(1).startswith("M")}


def residual_rows(root):
    """The residual-risks table's row ids."""
    text = (root / RESIDUALS).read_text()
    return {m.group(1) for m in re.finditer(r"^\|\s*(RR\d+)\s*\|", text, re.M)}


def check_ref(ref, heads, prd, rr):
    """Return an error message for an invalid `refs:` entry, or None."""
    if ref in prd:
        return None
    if re.fullmatch(r"RR\d+", ref):
        return None if ref in rr else "names no residual-risks row"
    target, sep, anchor = ref.partition("#")
    if target in ("DESIGN", "PRD"):
        target += ".md"
    if target not in heads:
        return "names neither a PRD requirement id, an RR row, nor a design file"
    if not sep:
        return "names a file without an anchor; a ref points at a heading"
    if anchor not in heads[target]:
        return "dangles"
    return None


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


def branch_ids(prefix):
    """Numbers of `prefix`-NNN ids used on any local or remote branch, from branch
    names (tp-061-slug) and from the ticket files each branch carries, so an id that
    only an open branch has is never handed out again."""
    def git(*args):
        try:
            out = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
        except OSError:
            return []
        return out.stdout.splitlines() if out.returncode == 0 else []

    pattern = re.compile(rf"(?:^|/){prefix}-(\d+)", re.I)
    numbers = set()
    for ref in git("for-each-ref", "--format=%(refname:short)", "refs/heads", "refs/remotes"):
        match = pattern.search(ref)
        if match:
            numbers.add(int(match.group(1)))
        for path in git("ls-tree", "-r", "--name-only", ref, "--", "tickets"):
            match = pattern.search(path)
            if match:
                numbers.add(int(match.group(1)))
    return numbers


def next_id(tickets, prefix):
    numbers = {int(t[len(prefix) + 1:]) for t in tickets if t.startswith(prefix + "-")}
    return f"{prefix}-{max(numbers | branch_ids(prefix), default=0) + 1:03d}"


def ready(tickets):
    return [
        t for t in tickets.values()
        if t["column"] == "backlog"
        and t.get("size") != "epic"
        and all(tickets.get(d, {}).get("column") == "done" for d in t.get("depends_on", []))
    ]


def check(tickets):
    problems = []
    heads = ref_targets(ROOT.parent)
    prd = requirement_ids(ROOT.parent)
    rr = residual_rows(ROOT.parent)
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
        for ref in t.get("refs", []):
            err = check_ref(ref, heads, prd, rr)
            if err:
                problems.append(f"{t['id']}: ref {ref} {err}")
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
    parser.add_argument("--next-id", nargs="?", const="TP", choices=["TP", "KRN"],
                        help="next free id of the series (TP by default; KRN ids are separate)")
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
        print(next_id(tickets, args.next_id))
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
