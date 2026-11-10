# Sysmon Says Triage: design

This file holds the goal, the architecture, the portal contracts we call, the data sources, the main decisions with their
reasons, and the milestones. Numbers from our code are in the code, not here. The history of each change is in its pull request.

## Goal and scope

**The user:** a SOC analyst reviewing one Windows computer's Sysmon log (an `.evtx` file).
**The situation:** a log holds hundreds or thousands of events, and most are ordinary.
**What they need to know:** which programs did something worth a look, what those programs connected to or asked for,
and what the three lookups (file hash, domain name, IP address) say about them, within minutes, without anything private
leaving the machine.

Out of scope: a server or API of our own; any change to the three portals; several computers' logs at once; a rules engine;
Claude or any AI inside the tool; storing anything beyond a local lookup cache and a local record of what was sent.

## Architecture

```
events.evtx --> Sysmon Says Triage (Streamlit, this repo) --HTTP--> hash portal --> VirusTotal, MalwareBazaar, ThreatFox
                reads, filters, ranks, shows                --HTTP--> DNS portal  --> Google DNS, RDAP, crt.sh
                                                            --HTTP--> IP portal   --> Shodan InternetDB, RDAP, AbuseIPDB
```

- Four programs run on the analyst's computer: this app and the three portal backends, each started from its own folder, unchanged.
- This app is a **client** of the portals: it reads the log, decides what may leave (the privacy gate), and asks the portals.
- **What leaves the machine:** only the IP addresses, domain names and file hashes that pass the privacy gate, sent to the portals,
  which pass them to the outside services shown above. Command lines, user names, computer names, paths and registry entries never leave.

## The portals we call (their contracts, unchanged)

| Lookup | Repository | Request | What we use from the answer |
|---|---|---|---|
| File hash | `gr-aleph/hash-enrich-2` | `GET /api/v1/hash/{hash}` (MD5, SHA-1 or SHA-256) | `verdict`: score 0-100, label `safe` / `suspicious` / `malicious`, reasons |
| Domain name | `NewCooDooer/ioc-simple-dns` | `GET /api/v1/domain/{name}` | `assessment`: average 0-100, one of five verdicts or `not_graded` |
| IP address | `Bed-e/enrichment-portal-simple` | `GET /api/ip/{ip}` (IPv4 only) | `verdict`: score 0-100, level `malicious` / `suspicious` / `no_known_bad` / `not_applicable` |

All three use 0 = least risk and 100 = most. The labels differ, so the app shows each portal's own label and never turns
"no known bad" into "safe". Readiness: the hash and DNS portals have a health route; the IP portal is asked about a private
address, which its contract answers without contacting any outside service.

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
- **Privacy gate, six rules:** only public IP addresses are sent; a name without a dot, with an internal ending, or that resolved to a private address stays local; only hashes of programs are sent; everything sent is written to a local record.
- **Every rule works from the log itself, with no setup:** logs come from different organisations, and a fixed settings file would be wrong for every other one.
- **When a log lacks something, a rule fails towards checking more,** never towards hiding something.
- **Duplicate hashes are collapsed, and past answers are remembered locally:** one lookup per distinct file, and none for a file already checked.
- **A file waits only if it passes all five "ordinary file" checks:** Microsoft label, system folder, run name matching its built-in original name, existed before the log, never touched the network. A fake must beat all five; failing one sends it to the queue.
- **The queue is ranked:** dropped during the log and then run, then talked to the internet, then identity mismatches, then unusual folders. A bad IP or domain result moves the program behind it to the front.
- **A file is never dropped because its connections looked clean:** malware often talks to trusted services.
- **Results arrive as a live feed in batches:** the first batch is every file meeting a critical rule, capped in time; then the page offers the next batch with its estimated time. Nothing is skipped silently.
- **While waiting for VirusTotal's next slot, the app does the IP and domain lookups:** all three lookups progress together with no extra machinery.
- **No Claude or other AI inside the tool:** nothing private can reach it because it is not in the pipeline.
- **Logs, the lookup cache and the sent record never go into git.**

## Milestones

Each is done when its pull request is merged; the PR holds the evidence and the details.

- **M0 Design:** this file and a README; the repository exists.
- **M1 Read the log:** an `.evtx` file becomes plain events, and the page shows what was learned from the log; tests pass offline.
- **M2 Privacy gate, IP and domain lookups:** the three portals are checked for readiness, the gate decides what is sent, and the page shows the IP and domain verdicts and what was sent or kept local.
- **M3 File hashes:** the five checks, the ranked queue, the first batch as a live feed with progress, and the offer of the next batch.
- **M4 Context:** each finding is linked to the program behind it, with a view per program.
- **M5 Demo and documents:** a scenario log from a Windows machine, a pre-run cache for the demo, and final documents.
