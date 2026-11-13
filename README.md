# Sysmon Says Triage

A local web page that keeps a history of Sysmon logs per computer: it shows what is new or gone since earlier logs, re-checks
older file hashes, domain names and IP addresses with three lookup portals to catch threats after the fact, and exports a
scrubbed copy that is safe to share. Anything private stays on this computer. How it works: [design.md](design.md).

> Use it only with the three portal backends running on this computer, unchanged: [hash](https://github.com/gr-aleph/hash-enrich-2),
> [domain](https://github.com/NewCooDooer/ioc-simple-dns) and [IP](https://github.com/Bed-e/enrichment-portal-simple). Start each as its own README says.

## Set up

Needs Python 3 (developed on 3.14).

```bash
git clone https://github.com/NewCooDooer/sysmon-says-triage.git
cd sysmon-says-triage
python3 -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

An older copy used `python-evtx`: run `pip uninstall python-evtx` first, because on a Mac it and `evtx` share a folder.

## Run

```bash
streamlit run app.py
```

It prints its address. Open it and choose a Sysmon log (`.evtx`, up to 2 GB); the log is read on this computer only.

## Test

```bash
python -m pytest
```

No network needed. To also test a real log: `SAMPLE_LOG=/path/to/events.evtx python -m pytest`.
