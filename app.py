"""The page. Start it from the project folder with:  streamlit run app.py

Streamlit runs this whole file again, from top to bottom, every time the page changes (a file is chosen, a button is clicked).
"""

import csv
import json
import os
import tempfile
from collections import Counter

import streamlit as st

import dashboard
import export
import gate
import hashes
import history
import portals
import read_log

# The page background: faint gold grid lines every 22 pixels over a dark glow. Streamlit's theme allows only one solid
# colour, so this is a small style rule; .stApp is Streamlit's name for the whole page (stable while the version is pinned).
BACKGROUND = """<style>
.stApp { background:
    repeating-linear-gradient(0deg, rgba(212,175,55,0.07) 0 1px, transparent 1px 22px),
    repeating-linear-gradient(90deg, rgba(212,175,55,0.07) 0 1px, transparent 1px 22px),
    radial-gradient(circle at 50% 0%, #1f1a0a 0%, #000 70%);
  background-attachment: fixed; }
.stApp header { background: transparent; }
</style>"""

@st.cache_data  # remember the answer for the same file, so the log is read once, not on every rerun
def load(file_bytes):
    """Read an uploaded log. The reading library needs a file on disk, so the upload is written to a temporary file first."""
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as temp:
        temp.write(file_bytes)
    try:
        return read_log.read_events(temp.name)
    finally:
        os.remove(temp.name)  # "finally" runs even if reading failed, so the copy never stays behind


def show_list(title, items):
    """A folded section with one item per line, so long lists do not fill the page."""
    with st.expander(f"{title} ({len(items)})"):
        st.text("\n".join(items) if items else "none in this log")


def gate_rows(summary, events):
    """One row per address and name: what it is, whether it may leave this computer, and why."""
    rows = []
    for ip in summary["addresses"]:
        allowed, reason = gate.may_send_ip(ip)
        rows.append({"kind": "IP address", "value": ip, "allowed": allowed, "reason": reason})
    for name, answers in read_log.name_answers(events).items():
        allowed, reason = gate.may_send_name(name, answers)
        rows.append({"kind": "Domain name", "value": name, "allowed": allowed, "reason": reason})
    for item in hashes.queue(events):  # a program's SHA-256 says nothing about the computer, so it may always be sent
        reason = "fails: " + ", ".join(item["failed"]) if item["failed"] else "looks ordinary: waits for the second button"
        rows.append({"kind": "File hash", "value": item["value"], "allowed": True, "reason": reason,
                     "program": item["program"], "waits": not item["failed"]})
    return rows


def result_row(found):
    """One lookup result as a table row, in the portal's own words."""
    if found["status"] == "answered":
        return {"Kind": found["portal"], "Value": found["value"], "Portal's verdict": found["label"],
                "Score (0 = least risk)": found["score"], "Checked": found.get("checked_at", "just now"),
                "Why": "; ".join(found["reasons"])}
    return {"Kind": found["portal"], "Value": found["value"], "Portal's verdict": f"not looked up ({found['status']})",
            "Score (0 = least risk)": None, "Checked": None, "Why": found["message"]}


ASK = {"IP address": portals.ask_ip, "Domain name": portals.ask_domain, "File hash": portals.ask_hash}


def look_up(rows, failed="failed"):
    """Ask the right portal about each row, save each answer in history, keep the failures (under the name `failed`, so
    each tab keeps its own), then draw the page again."""
    st.session_state[failed] = []
    bar = st.progress(0.0, text="Asking the portals (a new domain can take a minute; each hash waits for VirusTotal)...")
    table_spot = st.empty()  # a placeholder that is redrawn after every answer, so results appear as they arrive
    found_now = []
    for done, row in enumerate(rows, start=1):
        found = ASK[row["kind"]](row["value"])  # ASK[...] is the function for this kind; (row["value"]) calls it
        history.save_answer(found)
        found_now.append(found)
        if found["status"] != "answered":
            st.session_state[failed].append(found)
        bar.progress(done / len(rows), text=f"{done} of {len(rows)} looked up")
        table_spot.table([result_row(f) for f in found_now])
    st.rerun()  # the new verdicts now come from history


def show_recheck():
    """The Re-check tab: ask the portals again about values already checked once, because their verdicts change."""
    names = {"ip": "IP address", "domain": "Domain name", "hash": "File hash"}  # history's kinds, as the page names them
    known = {kind: history.latest_answers(kind) for kind in names}
    if not any(known.values()):
        st.write('Nothing has been checked yet: the first verdicts come from the "Add a log" tab.')
        return
    oldest = min(found["checked_at"] for answers in known.values() for found in answers.values())
    st.write(f"History has verdicts for {len(known['ip'])} IP addresses, {len(known['domain'])} domain names and "
             f"{len(known['hash'])} file hashes. The oldest was checked {oldest[:16].replace('T', ' ')} (UTC).")
    kinds = st.multiselect("What to re-check", list(names), default=["ip", "domain"], format_func=names.get)
    rows = sorted(({"kind": names[kind], "value": value, "checked_at": found["checked_at"]}
                   for kind in kinds for value, found in known[kind].items()), key=lambda row: row["checked_at"])
    st.caption("Only values sent once before are sent again, oldest checks first. The IP and DNS portals keep their own "
               "short-term caches, so a re-check soon after the last one may get the same answer back.")
    slow = sum(row["kind"] == "File hash" for row in rows)
    if slow:
        st.caption(f"{slow} hashes, about {slow * portals.GAP['VirusTotal'] // 60 + 1} minutes: VirusTotal allows 4 a minute.")
    can_ask = all(portals.is_ready(portal) for portal in portals.URLS)
    if not can_ask:
        st.info("Start the three portals to re-check.")
    if st.button(f"Re-check {len(rows)}", disabled=not can_ask or not rows):
        look_up(rows, failed="recheck_failed")
    if st.session_state.get("recheck_failed"):
        st.warning("Not re-checked this time; their older verdicts stay:")
        st.table([result_row(found) for found in st.session_state["recheck_failed"]])

    st.subheader("Verdicts that changed")
    changed = history.changes()
    if dashboard.newly_flagged(changed):
        st.badge(f"{len(dashboard.newly_flagged(changed))} now flagged", color="red")
    if changed:
        st.dataframe(dashboard.change_table(changed), hide_index=True)
    else:
        st.write("No verdict has changed yet: each value's newest two answers have the same label.")


def show_sent():
    """The sent record as a table, newest first: every value that ever left this computer, and when."""
    if not portals.SENT_RECORD.exists():
        st.write("Nothing has been sent yet.")
        return
    with open(portals.SENT_RECORD, newline="") as file:
        rows = list(csv.DictReader(file))  # one dictionary per line, keyed by the header
    st.write(f"{len(rows)} values sent. Each was written here before it was sent.")
    st.dataframe(rows[::-1], hide_index=True)  # [::-1]: the list reversed, so the newest is first


st.set_page_config(page_title="Sysmon Says Triage", layout="wide")
st.html(BACKGROUND)
st.title("Sysmon Says Triage")
dashboard_tab, upload_tab, recheck_tab, sent_tab = st.tabs(["Dashboard", "Add a log", "Re-check", "What was sent"])
with dashboard_tab:
    dashboard.show()
with recheck_tab:
    show_recheck()
with sent_tab:
    show_sent()
with upload_tab:  # last, because st.stop() below ends the whole run when no log is chosen
    st.write("Choose a Sysmon log (.evtx). It is read on this computer; nothing leaves it until you press the lookup button.")

    upload = st.file_uploader("Sysmon log", type=["evtx"])
    if upload is None:
        st.stop()  # nothing chosen yet: stop here, and Streamlit shows the page so far
    if st.session_state.get("log_id") != upload.file_id:  # a different log: forget the previous log's lookups
        st.session_state["log_id"] = upload.file_id
        st.session_state["failed"] = []
        st.session_state["history"] = None

    events = load(upload.getvalue())
    if not events:
        st.warning("This file has no Sysmon events in it.")
        st.stop()
    if st.session_state["history"] is None:  # once per chosen file, because Streamlit reruns this script on every click
        st.session_state["history"] = history.add_upload(upload.getvalue(), events)
        st.rerun()  # run the page again, so the Dashboard tab (drawn first) includes this log

    summary = read_log.summarize(events)
    st.subheader("What we learned from this log")
    left, middle, right = st.columns(3)
    left.metric("Sysmon events", summary["events"])
    middle.metric("Computers", len(summary["computers"]))
    right.metric("Programs that started", len(summary["programs"]))
    st.caption(f"From {summary['first']} to {summary['last']} (UTC). "
               f"Hash types Sysmon recorded: {', '.join(summary['hash_types']) or 'none'}.")
    st.table({"Event type": list(summary["by_type"]), "Count": list(summary["by_type"].values())})
    show_list("Computers", summary["computers"])
    show_list("Programs that started", summary["programs"])

    st.subheader("History")
    for computer, found in st.session_state["history"].items():
        if found["already"]:
            st.write(f"**{computer}:** this file is already in history, so nothing was added ({found['uploads']} uploads so far).")
        elif found["first"]:
            st.write(f"**{computer}:** first upload for this computer, so everything is new.")
        else:
            counts = Counter(kind for kind, value in found["new"])
            st.write(f"**{computer}:** upload {found['uploads']}. New since earlier uploads: "
                     + (", ".join(f"{kind} {n}" for kind, n in counts.items()) or "nothing") + ".")
            show_list(f"New for {computer}", [f"{kind}: {value}" for kind, value in found["new"]])

    st.subheader("Share-safe copy of this log")
    st.write("The events as a JSON file, with computer names, user names, internal names, private addresses and account "
             "IDs replaced by stand-ins such as COMPUTER-1. A download only: nothing is sent.")
    free_text = st.checkbox("Include command lines and clipboard text")
    if free_text:
        st.warning("Command lines can hold things no rule recognises, such as a password typed as an argument. They are "
                   "scrubbed of known names only, and the self-check can only prove that known names are gone.")
    dashboard.offer(*export.share_safe_log(events, free_text), "share-safe-log.json")  # *: its three results as three inputs
    with st.expander("The key: which stand-in is which name (stays on this computer)"):
        key = json.loads(export.KEY_FILE.read_text())
        st.table([{"Stand-in": standin, "Original": original} for original, standin in sorted(key.items(), key=lambda kv: kv[1])])

    st.subheader("The three portals")
    ready = {portal: portals.is_ready(portal) for portal in portals.URLS}
    st.write(" · ".join(f"{portal} portal: {'running' if up else 'NOT running'}" for portal, up in ready.items()))

    st.subheader("Privacy gate: what may leave this computer")
    rows = gate_rows(summary, events)
    to_send = [row for row in rows if row["allowed"]]
    kept = [row for row in rows if not row["allowed"]]
    with st.expander(f"Will be sent to a portal ({len(to_send)})"):
        st.table([{"Kind": r["kind"], "Value": r["value"], "Why": r["reason"]} for r in to_send])
    with st.expander(f"Stays on this computer ({len(kept)})", expanded=True):
        st.table([{"Kind": r["kind"], "Value": r["value"], "Why": r["reason"]} for r in kept])

    answers = {"IP address": history.latest_answers("ip"), "Domain name": history.latest_answers("domain"),
               "File hash": history.latest_answers("hash")}
    checked = [answers[row["kind"]][row["value"]] for row in to_send if row["value"] in answers[row["kind"]]]
    unchecked = [row for row in to_send if row["value"] not in answers[row["kind"]] and not row.get("waits")]
    waiting = [row for row in to_send if row["value"] not in answers[row["kind"]] and row.get("waits")]

    st.subheader("Verdicts")
    st.write(f"{len(checked)} of {len(to_send)} already checked: their verdicts come from history, so they are not sent again.")
    if checked:
        st.table([result_row(found) for found in checked])

    can_ask = all(ready.values())
    if not can_ask:
        st.info("Start the three portals to look these up.")
    slow = sum(row["kind"] == "File hash" for row in unchecked)
    if slow:
        st.caption(f"{slow} hashes, about {slow * portals.GAP['VirusTotal'] // 60 + 1} minutes: VirusTotal allows 4 a minute. "
                   "Unusual programs come first.")
    label = f"Look up the {len(unchecked)} never checked" if unchecked else "Nothing new to look up"
    if st.button(label, disabled=not can_ask or not unchecked):
        look_up(unchecked)
    if waiting:
        with st.expander(f"Waiting: programs that look like ordinary Windows files ({len(waiting)})"):
            st.caption("Each passed all five checks: labelled Microsoft, inside the Windows folder, run under its own name, "
                       "not created during the log, and no network use.")
            st.table([{"Program": row["program"], "SHA-256": row["value"]} for row in waiting])
        if st.button(f"Look up the {len(waiting)} ordinary ones too", disabled=not can_ask):
            look_up(waiting)
    if st.session_state["failed"]:
        st.warning("Not looked up this time; they will be tried again next time:")
        st.table([result_row(found) for found in st.session_state["failed"]])
    if portals.SENT_RECORD.exists():
        st.caption('Every value sent is listed, with the time and the portal, in the "What was sent" tab.')
