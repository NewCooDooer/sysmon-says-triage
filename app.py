"""The page. Start it from the project folder with:  streamlit run app.py

Streamlit runs this whole file again, from top to bottom, every time the page changes (a file is chosen, a button is clicked).
"""

import os
import tempfile
from collections import Counter

import streamlit as st

import gate
import history
import portals
import read_log


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
    return rows


def result_row(found):
    """One lookup result as a table row, in the portal's own words."""
    if found["status"] == "answered":
        return {"Kind": found["portal"], "Value": found["value"], "Portal's verdict": found["label"],
                "Score (0 = least risk)": found["score"], "Why": "; ".join(found["reasons"])}
    return {"Kind": found["portal"], "Value": found["value"], "Portal's verdict": f"not looked up ({found['status']})",
            "Score (0 = least risk)": None, "Why": found["message"]}


st.title("Sysmon Says Triage")
st.write("Choose a Sysmon log (.evtx). It is read on this computer; nothing leaves it until you press the lookup button.")

upload = st.file_uploader("Sysmon log", type=["evtx"])
if upload is None:
    st.stop()  # nothing chosen yet: stop here, and Streamlit shows the page so far
if st.session_state.get("log_id") != upload.file_id:  # a different log: forget the previous log's lookups
    st.session_state["log_id"] = upload.file_id
    st.session_state["results"] = []
    st.session_state["history"] = None

events = load(upload.getvalue())
if not events:
    st.warning("This file has no Sysmon events in it.")
    st.stop()
if st.session_state["history"] is None:  # once per chosen file, because Streamlit reruns this script on every click
    st.session_state["history"] = history.add_upload(upload.getvalue(), events)

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

can_ask = ready["ip"] and ready["domain"]
if not can_ask:
    st.info("Start the IP and domain portals to look these up.")
if st.button(f"Look up the {len(to_send)} addresses and names that may be sent", disabled=not can_ask or not to_send):
    st.session_state["results"] = []
    bar = st.progress(0.0, text="Asking the portals (a new domain name can take up to a minute)...")
    table_spot = st.empty()  # a placeholder that is redrawn after every answer, so results appear as they arrive
    for done, row in enumerate(to_send, start=1):
        found = portals.ask_ip(row["value"]) if row["kind"] == "IP address" else portals.ask_domain(row["value"])
        st.session_state["results"].append(found)
        bar.progress(done / len(to_send), text=f"{done} of {len(to_send)} looked up")
        table_spot.table([result_row(f) for f in st.session_state["results"]])
elif st.session_state["results"]:
    st.table([result_row(f) for f in st.session_state["results"]])
if st.session_state["results"]:
    st.caption(f"Every value sent is listed, with the time and the portal, in {portals.SENT_RECORD.name} (on this computer only).")
