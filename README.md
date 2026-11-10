# Sysmon Says Triage

A local web page that helps a SOC analyst work through a Sysmon log: it finds the file hashes, domain names and IP addresses
in the log, keeps anything private on this computer, and asks three lookup portals about the rest. How it works: [design.md](design.md).

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

## Run and test

Coming with the first code (milestone M1).
