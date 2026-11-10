"""The page. Start it from the project folder with:  streamlit run app.py

Streamlit runs this whole file again, from top to bottom, every time the page changes (a file is chosen, a button is clicked).
"""

import os
import tempfile

import streamlit as st

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


st.title("Sysmon Says Triage")
st.write("Choose a Sysmon log (.evtx). It is read on this computer only; nothing is sent anywhere at this stage.")

upload = st.file_uploader("Sysmon log", type=["evtx"])
if upload is None:
    st.stop()  # nothing chosen yet: stop here, and Streamlit shows the page so far

events = load(upload.getvalue())
if not events:
    st.warning("This file has no Sysmon events in it.")
    st.stop()

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
show_list("Domain names looked up", summary["domains"])
show_list("IP addresses contacted", summary["addresses"])
