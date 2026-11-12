"""The Dashboard tab: one computer's history at a glance. It only reads history; nothing here sends anything."""

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


def table(items, answers):
    """Items as rows for a table."""
    return [{"Kind": s["kind"], "Value": s["value"], "Portal's verdict": verdict(s, answers),
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
    """Changed verdicts as rows: before, now, and the context: which computers saw the value, and when last."""
    def said(answer):
        return f"{answer['label']} (score {answer['score']}, {answer['checked_at'][:10]})"
    return [{"Kind": c["kind"], "Value": c["value"], "Before": said(c["before"]), "Now": said(c["now"]),
             "Seen on": ", ".join(f"{s['computer']} (last {s['last_seen'][:16]})" for s in history.seen_on(c["kind"], c["value"]))}
            for c in changed]


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


def show():
    """Draw the Dashboard tab."""
    names = history.computers()
    if not names:
        st.info('No history yet: add a Sysmon log in the "Add a log" tab.')
        return
    computer = st.selectbox("Computer", names)
    uploads, sightings = history.uploads_of(computer), history.sightings_of(computer)
    new, gone, per_upload = compare(uploads, sightings)
    answers = {kind: history.latest_answers(kind) for kind in ("ip", "domain", "hash")}
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
            st.dataframe(table(flagged, answers), hide_index=True)
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
            st.dataframe(change_table(changed), hide_index=True)
        else:
            st.write('No verdict has changed. Older verdicts are checked again in the "Re-check" tab.')

    st.space("medium")
    with st.container(border=True):  # a framed box per section
        st.subheader("New in the latest upload")
        if first:
            st.write("This is the first upload for this computer, so everything is new.")
        else:
            st.dataframe(table(new, answers), hide_index=True)

    st.space("medium")
    with st.container(border=True):  # a framed box per section
        st.subheader("Gone quiet")
        st.caption("Seen in earlier uploads, but not in the latest one.")
        if gone:
            st.dataframe(table(gone, answers), hide_index=True)
        else:
            st.write("Nothing has gone quiet.")

    st.space("medium")
    with st.container(border=True):  # a framed box per section
        st.subheader("Trends across uploads")
        dates = [u["first_event"][:16] for u in uploads]
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
        sections = [("Summary", [summary]), ("Flagged by the portals", table(flagged, answers)),
                    ("Verdicts that changed", change_table(changed)), ("New in the latest upload", table(new, answers)),
                    ("Gone quiet", table(gone, answers))]
        title = f"{computer}: latest log {uploads[-1]['first_event'][:16]} to {uploads[-1]['last_event'][:16]} (UTC)"
        offer(*export.share_safe_report(title, sections, found), "share-safe-report.html")
