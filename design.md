# Sysmon Says Triage: design

This file holds the goal, the architecture, what history keeps, the portal contracts we call, the data sources, the main
decisions with their reasons, and the milestones. Numbers from our code are in the code, not here. The history of each change
is in its pull request.

## Goal and scope

**The user:** a SOC analyst or team lead who receives Sysmon logs from the same computers over time.
**The situation:** each log is read once and forgotten; threat intelligence keeps changing afterwards; and logs can't be shared
outside because they are full of internal names.
**What they need to know:** what is new or gone on each computer since its earlier logs, whether anything once judged clean is
now known to be bad, and how to share findings without leaking anything.

Out of scope: a server of our own; changes to the portals; storing whole logs; forecasting; AI inside the tool.

## Architecture

```
events.evtx --> Sysmon Says Triage (Streamlit, this repo) --HTTP--> hash portal --> VirusTotal, MalwareBazaar, ThreatFox
                reads, gates, remembers, compares           --HTTP--> DNS portal  --> Google DNS, RDAP, crt.sh
                        |                                   --HTTP--> IP portal   --> Shodan InternetDB, RDAP, AbuseIPDB
                  history.db (local only)
```

- Four programs run on the analyst's computer: this app and the three portal backends, each started from its own folder, unchanged.
- This app is a **client** of the portals: it reads the log, decides what may leave (the privacy gate), and asks the portals.
- **What leaves the machine:** only the IP addresses, domain names and file hashes that pass the privacy gate, sent to the portals,
  which pass them to the outside services shown above. Command lines, user names, computer names, paths and registry entries never leave. A share-safe export is a local file; it leaves only if the analyst sends it.

## What history keeps

One local file, never in git:
- each upload: computer, date, time span, a file fingerprint, counts per event type;
- each indicator per computer: first seen, last seen, number of uploads;
- each portal answer, with the date it was checked (older answers kept).

## The portals we call (their contracts, unchanged)

| Lookup | Repository | Request | What we use from the answer |
|---|---|---|---|
| File hash | `gr-aleph/hash-enrich-2` | `GET /api/v1/hash/{hash}` (MD5, SHA-1 or SHA-256) | `verdict`: score 0-100, label `safe` / `suspicious` / `malicious`, reasons |
| Domain name | `NewCooDooer/ioc-simple-dns` | `GET /api/v1/domain/{name}` | `assessment`: average 0-100, one of five verdicts or `not_graded` |
| IP address | `Bed-e/enrichment-portal-simple` | `GET /api/ip/{ip}` (IPv4 only) | `verdict`: score 0-100, level `malicious` / `suspicious` / `no_known_bad` / `not_applicable` |

All three use 0 = least risk and 100 = most. The labels differ, so the app shows each portal's own label and never turns
"no known bad" into "safe". Readiness: the hash and DNS portals have a health route; the IP portal is asked about a private
address, which its contract answers without contacting any outside service. A refusal (400) or the IP portal's "every source
failed" (503) is shown as such, never as a verdict. Only a program's SHA-256 goes to the hash portal, never its IMPHASH, which
the portal would mistake for an MD5.

## Data sources: keys, limits and terms

This app needs no key: the portals hold their own. The input is a Sysmon log read locally. The limits that shape the design
belong to the portals' outside services (the providers' published figures, checked 2026-11-10):

| Service (portal) | Limit | Terms |
|---|---|---|
| VirusTotal (hash) | 4 requests a minute, 500 a day on the free tier | No commercial use |
| MalwareBazaar, ThreatFox (hash) | none published ("fair use") | Free key required |
| Google DNS, RDAP, crt.sh (DNS) | Google 1500 a second per client; RDAP 10 in 10 seconds; crt.sh none published | Google forbids caching past its cache header |
| Shodan InternetDB, RDAP, AbuseIPDB (IP) | AbuseIPDB 1,000 checks a day on the free tier | Non-commercial use |

## Main decisions

- **One Streamlit app plus plain Python files, no server of our own:** this app is a client of the portals; nobody needs to call it.
- **Nothing leaves the computer until the analyst presses the lookup button:** the page first shows what will be sent and what stays local, with the reason for each.
- **Only one function sends a value from the log, and it writes the value to the local sent record before sending it:** nothing can be sent without being recorded.
- **Requests towards the same outside service keep a minimum gap:** the IP and domain portals both reach rdap.org, and a burst of lookups made it refuse, which raised the portals' scores.
- **Privacy gate, six rules:** only public IP addresses are sent; a name without a dot, with an internal ending, or that resolved to a company-network address stays local (not 127.0.0.1 or 0.0.0.0, where dormant malware domains are parked); only hashes of programs are sent; everything sent is written to a local record.
- **Every rule works from the log itself, with no setup:** logs come from different organisations, and a fixed settings file would be wrong for every other one.
- **When a log lacks something, a rule fails towards checking more,** never towards hiding something.
- **A file waits only if it passes all five "ordinary file" checks:** Microsoft label, inside the Windows folder, run name matching its built-in original name, not created during the log, no network use. A fake must beat all five; failing one puts it in the first lookup, and the ordinary ones wait for a second button.
- **A file is never dropped because its connections looked clean:** malware often talks to trusted services.
- **No Claude or other AI inside the tool:** nothing private can reach it because it is not in the pipeline.
- **The page answers this computer only, Streamlit's usage statistics are off, and the font is served from this computer:** otherwise the page itself would send data out.
- **The gold grid background is one small style rule, not a Streamlit setting:** the theme allows only a solid colour. It uses Streamlit's internal page name, which is stable while the version is pinned; if it changes, the page falls back to plain black.
- **History is kept per computer, as Sysmon names it:** no setup, and organisations never mix.
- **The same file uploaded twice counts once,** recognised by its fingerprint.
- **First and last seen are the log's own event times, not the upload time:** they say when something happened.
- **Only indicators never checked before are looked up:** repeat uploads cost almost nothing, which also tames VirusTotal's limit.
- **A verdict belongs to the indicator, not the computer, and only real answers are saved:** one check covers every computer, and a failed lookup is simply tried again.
- **Retro-hunting runs when the analyst presses a button, not on a timer:** nothing leaves without a button press.
- **The dashboard interprets changes; it does not predict:** a few uploads can't support a forecast.
- **New means first seen in the latest log; gone quiet means last seen before it; flagged means a portal's own label says suspicious, malicious or likely or definitely malware,** with no score threshold of our own.
- **Share-safe export reuses the gate's rules, keeps the pseudonym key local, and refuses to export if any original name remains.**
- **Logs, history, the sent record and the pseudonym key never go into git.**

## Milestones

Each is done when its pull request is merged; the PR holds the evidence and the details.

- **M0 Design:** this file and a README; the repository exists.
- **M1 Read the log:** an `.evtx` file becomes plain events, and the page shows what was learned from the log; tests pass offline.
- **M2 Privacy gate, IP and domain lookups:** the three portals are checked for readiness, the gate decides what is sent, and the page shows the IP and domain verdicts and what was sent or kept local.
- **M3 Design update:** this file describes the history, retro-hunting and share-safe product.
- **M4 History:** every upload is added to the local history per computer, and the page shows which indicators are new.
- **M5 Dashboard:** what is new, what has gone quiet and the trends across uploads, in the new look; only new indicators are looked up.
- **M6 File hashes:** new program hashes are looked up through the hash portal, ordered by the five "ordinary file" checks.
- **M7 Retro-hunting:** older indicators are re-checked on request, and every changed verdict is shown with its context.
- **M8 Share-safe export:** scrubbed events and the dashboard report; the pseudonym key stays local and the self-check passes.
- **M9 Demo and defence:** logs from a Windows machine, final documents and a rehearsed demo.
