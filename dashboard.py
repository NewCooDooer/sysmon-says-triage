"""The Dashboard tab: one computer's history, or all computers at once. It only reads history and sends nothing."""

import json

import streamlit as st

import export
import history

# The portals' own words for "worth a look". No score threshold of our own: each portal decides.
FLAGGED = {"suspicious", "malicious", "Likely malware", "Definitely malware"}
KINDS = {"program": "Programs", "hash": "Program hashes", "domain": "Domains", "ip": "IP addresses"}


def compare(uploads, sightings):
    """What changed: items first seen in the latest upload, items not seen in it, and new items per upload."""
    latest = uploads[-1]
    new = [s for s in sightings if s["first_seen"] >= latest["first_event"]]
    gone = [s for s in sightings if s["last_seen"] < latest["first_event"]]
    per_upload = [sum(u["first_event"] <= s["first_seen"] <= u["last_event"] for s in sightings) for u in uploads]
    return new, gone, per_upload


def verdict(sighting, answers):
    """The portal's newest label for this item, or "" if no portal has checked it."""
    return answers.get(sighting["kind"], {}).get(sighting["value"], {}).get("label", "")


def why(sighting, answers):
    """The portal's own reasons for its newest verdict, in one line, or "" if no portal has checked it."""
    return "; ".join(answers.get(sighting["kind"], {}).get(sighting["value"], {}).get("reasons", []))


def table(items, answers, programs):
    """Items as rows for a table. A hash also names the program it belongs to, so the analyst knows what to look at."""
    return [{"Kind": s["kind"], "Value": s["value"], "Program": programs.get(s["value"], ""),  # only a hash is a key
             "Portal's verdict": verdict(s, answers), "Why": why(s, answers),
             "First seen": s["first_seen"][:16], "Last seen": s["last_seen"][:16], "Uploads": s["uploads"]}
            for s in items]


def mine(changed, sightings):
    """Only the changed verdicts of values this computer has seen."""
    seen = {(s["kind"], s["value"]) for s in sightings}
    return [c for c in changed if (c["kind"], c["value"]) in seen]


def newly_flagged(changed):
    """The changes that turned a verdict into a flagged one: once judged clean, now worth a look."""
    return [c for c in changed if c["now"]["label"] in FLAGGED and c["before"]["label"] not in FLAGGED]


def change_table(changed):
    """Changed verdicts as rows: before, now and why, and the context: which computers saw the value, and when last."""
    def said(answer):
        return f"{answer['label']} (score {answer['score']}, {answer['checked_at'][:10]})"
    return [{"Kind": c["kind"], "Value": c["value"], "Before": said(c["before"]), "Now": said(c["now"]),
             "Why now": "; ".join(json.loads(c["now"]["reasons"])),  # the portal's reasons for the new verdict
             "Seen on": ", ".join(f"{s['computer']} (last {s['last_seen'][:16]})" for s in history.seen_on(c["kind"], c["value"]))}
            for c in changed]


def show_table(rows):
    """Draw rows as a table. Where there is a "Why" column, rows are taller, so its long text wraps instead of being
    cut off. An empty cell (such as "New in latest log" for a first upload) shows as blank, not "None"."""
    wraps = [name for name in ("Why", "Why now") if rows and name in rows[0]]
    narrow = [name for name in ("Value", "Program") if wraps and name in rows[0]]  # long values wrap too, to make room
    widths = {name: 520 for name in wraps} | {name: "medium" for name in narrow}
    st.dataframe(rows, hide_index=True, placeholder="", row_height=96 if wraps else None,  # 96 pixels: about four lines
                 column_config={name: st.column_config.TextColumn(width=width) for name, width in widths.items()})


def offer(content, whole, inside, file_name):
    """A download button, but only if no name is left as a whole name; otherwise say which (on this screen only)."""
    if whole:
        st.error("Not safe to share, so there is no download. These names are still in it: " + ", ".join(whole))
        return
    st.download_button(f"Download {file_name}", content, file_name=file_name, on_click="ignore")  # ignore: no rerun
    st.caption("Self-check passed: no name from the local key is left in it as a whole name. The key stays on this computer.")
    if inside:
        st.warning("Please check by hand: these names also appear inside longer words (examples from the file): "
                   + "; ".join(f'"{name}" in "...{example}..."' for name, example in inside.items()))


def computer_rows(answers, changed):
    """One row per computer, most flagged first: which computer to open first."""
    rows = []
    for name in history.computers():
        uploads, sightings = history.uploads_of(name), history.sightings_of(name)
        rows.append({"Computer": name, "Uploads": len(uploads), "Latest log": uploads[-1]["first_event"][:16],
                     "Flagged": sum(verdict(s, answers) in FLAGGED for s in sightings),
                     "Verdicts changed": len(mine(changed, sightings)),
                     "New in latest log": len(compare(uploads, sightings)[0]) if len(uploads) > 1 else None})
    return sorted(rows, key=lambda row: -row["Flagged"])


def fleet(items, answers):
    """Flagged items on more than one computer, most widespread first; and programs, domains and IPs that only one
    computer has, flagged first, then newest. Rare is worth a look: attacks hide on few machines, normal is on most."""
    spread = sorted((i for i in items if i["computers"] > 1 and verdict(i, answers) in FLAGGED),
                    key=lambda i: -i["computers"])
    rare = sorted((i for i in items if i["computers"] == 1 and i["kind"] in ("program", "domain", "ip")),
                  key=lambda i: i["first_seen"], reverse=True)  # newest first...
    rare.sort(key=lambda i: verdict(i, answers) not in FLAGGED)  # ...then flagged first, newest first within each
    return spread, rare


def overview_table(items, answers, programs):
    """Items from every computer as rows, with how many computers have each and which ones."""
    return [{"Kind": i["kind"], "Value": i["value"], "Program": programs.get(i["value"], ""),
             "Portal's verdict": verdict(i, answers), "Why": why(i, answers),
             "Computers": i["computers"], "Seen on": i["names"],
             "First seen": i["first_seen"][:16], "Last seen": i["last_seen"][:16]} for i in items]


def show_overview(names, answers):
    """All computers at once: which to open first, what is flagged on several, and what only one has."""
    changed, items, programs = history.changes(), history.prevalence(), {}
    for name in names:
        programs |= history.programs_of(name)  # |= adds one dictionary into another
    rows = computer_rows(answers, changed)
    spread, rare = fleet(items, answers)

    cards = st.columns(4)
    cards[0].metric("Computers", len(names), border=True)
    cards[1].metric("Uploads", sum(row["Uploads"] for row in rows), border=True)
    cards[2].metric("Flagged items", sum(verdict(i, answers) in FLAGGED for i in items), border=True)
    cards[3].metric("Verdicts changed", len(changed), border=True)
    st.space("medium")
    with st.container(border=True):
        st.subheader("Computers, most flagged first")
        show_table(rows)
    st.space("medium")
    with st.container(border=True):
        st.subheader("Flagged on several computers")
        st.caption("A spread, not a one-off: one verdict, several machines.")
        if spread:
            show_table(overview_table(spread, answers, programs))
        else:
            st.write("Nothing flagged is on more than one computer.")
    st.space("medium")
    with st.container(border=True):
        st.subheader("Only on one computer")
        st.caption("Normal software is on most machines; something only one computer has is worth a look. "
                   "Flagged first, then newest.")
        with st.expander(f"Programs, domains and IP addresses only one computer has ({len(rare)})"):
            show_table(overview_table(rare, answers, programs))


def show():
    """Draw the Dashboard tab."""
    names = history.computers()
    if not names:
        st.info('No history yet: add a Sysmon log in the "Add a log" tab.')
        return
    answers = {kind: history.latest_answers(kind) for kind in ("ip", "domain", "hash")}
    computer = st.selectbox("Computer", (["All computers"] if len(names) > 1 else []) + names)
    if computer == "All computers":
        show_overview(names, answers)
        return
    uploads, sightings = history.uploads_of(computer), history.sightings_of(computer)
    new, gone, per_upload = compare(uploads, sightings)
    programs = history.programs_of(computer)
    first = len(uploads) == 1

    cards = st.columns(len(KINDS) + 1)
    cards[0].metric("Uploads", len(uploads), border=True)
    for card, (kind, label) in zip(cards[1:], KINDS.items()):
        added = sum(s["kind"] == kind for s in new)
        card.metric(label, sum(s["kind"] == kind for s in sightings), delta=None if first else f"{added} new",
                    delta_color="off", delta_arrow="off", border=True)  # grey and no arrow: new is neither good nor bad
    st.caption(f"Latest log: {uploads[-1]['first_event'][:16]} to {uploads[-1]['last_event'][:16]} (UTC).")

    flagged = [s for s in sightings if verdict(s, answers) in FLAGGED]
    st.space("medium")
    with st.container(border=True):  # a framed box per section
        st.subheader("Flagged by the portals")
        if flagged:
            st.badge(f"{len(flagged)} flagged", color="red")
            show_table(table(flagged, answers, programs))
        else:
            st.badge("Nothing flagged", color="green")
            st.caption("Only items a portal has checked can be flagged; checking happens in the \"Add a log\" tab.")

    changed = mine(history.changes(), sightings)
    st.space("medium")
    with st.container(border=True):  # a framed box per section
        st.subheader("Verdicts that changed")
        if newly_flagged(changed):
            st.badge(f"{len(newly_flagged(changed))} now flagged", color="red")
        if changed:
            show_table(change_table(changed))
        else:
            st.write('No verdict has changed. Older verdicts are checked again in the "Re-check" tab.')

    st.space("medium")
    with st.container(border=True):  # a framed box per section
        st.subheader("New in the latest upload")
        st.caption("Seen on this computer for the first time in its latest log: no earlier upload had it. A launch is "
                   "\"parent program -> program\"; launches are never looked up, so they have no verdict.")
        if first:
            st.write("This is the first upload for this computer, so everything is new.")
        else:
            show_table(table(new, answers, programs))

    st.space("medium")
    with st.container(border=True):  # a framed box per section
        st.subheader("Gone quiet")
        st.caption("Seen in earlier uploads, but not in the latest one.")
        if gone:
            show_table(table(gone, answers, programs))
        else:
            st.write("Nothing has gone quiet.")

    st.space("medium")
    with st.container(border=True):  # a framed box per section
        st.subheader("Trends across uploads")
        dates = [u["first_event"][5:16] for u in uploads]  # [5:16]: "12-13 10:26", short enough to fit under a bar
        counts = [json.loads(u["counts"]) for u in uploads]
        by_type = {"Upload": dates}  # one column per event type, one row per upload
        for event_type in sorted({t for c in counts for t in c}):
            by_type[event_type] = [c.get(event_type, 0) for c in counts]
        left, right = st.columns(2)
        left.caption("Events per type, per upload")
        left.bar_chart(by_type, x="Upload")
        right.caption("New items per upload: a jump means something changed")
        right.bar_chart({"Upload": dates, "New items": per_upload}, x="Upload")

    st.space("medium")
    with st.container(border=True):  # a framed box per section
        st.subheader("Share-safe report")
        st.caption("This computer's dashboard as an HTML file, with internal names replaced by stand-ins. A download only: "
                   "nothing is sent.")
        found = export.find_in_history(computer, sightings)
        for name in names:  # every computer in history, because "Seen on" can name another one
            export.add(found, name, "COMPUTER")
        summary = {"Uploads": len(uploads)} | {label: sum(s["kind"] == kind for s in sightings) for kind, label in KINDS.items()}
        sections = [("Summary", [summary]), ("Flagged by the portals", table(flagged, answers, programs)),
                    ("Verdicts that changed", change_table(changed)),
                    ("New in the latest upload", table(new, answers, programs)),
                    ("Gone quiet", table(gone, answers, programs))]
        title = f"{computer}: latest log {uploads[-1]['first_event'][:16]} to {uploads[-1]['last_event'][:16]} (UTC)"
        offer(*export.share_safe_report(title, sections, found), "share-safe-report.html")
