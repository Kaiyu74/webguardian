# WebGuardian — Packet‑Level HTTP Intrusion Detection and Active Response

WebGuardian is a lightweight, Python‑based middlebox that inspects HTTP traffic directly from the wire, detects common web attack patterns (SQL injection, XSS, command injection, path traversal, etc.), and can actively terminate suspicious sessions by injecting TCP RST packets. It logs structured, explainable security events that are easy to route into dashboards or SIEM tooling.

This project is designed as a practical portfolio piece that demonstrates hands‑on web security, packet analysis, and active defense engineering.

## Features

- Real‑time HTTP inspection at layer 2 using Scapy
- Built‑in signatures for common web attacks (regex‑based, easy to extend)
- Optional active response: gracefully tears down flagged TCP sessions (RST)
- Structured JSONL event logs with timestamps, severity, and context
- Simple CLI with configurable HTTP ports and log path
- Self‑contained demo client for generating realistic attack probes

## Quick Start

Prerequisites:
- Python 3.8+
- Root/administrator privileges to capture and inject packets

Install dependencies:

```bash
pip install -r requirements.txt
```

Find your network interface (examples: `eth0`, `en0`, `wlan0`, `lo`/`lo0`):

```bash
# Linux
ip link show
# or macOS
ifconfig
```

Run WebGuardian (read‑only detection):

```bash
sudo python3 web_guardian_middlebox.py <iface> --ports 80 8080 8000 --log-path logs/webguardian_events.log
```

Enable active blocking (inject TCP RST to both endpoints):

```bash
sudo python3 web_guardian_middlebox.py <iface> --ports 8080 --block
```

Tip: For a local test target, you can run a simple HTTP server in another terminal:

```bash
# Example target on port 8080
python3 -m http.server 8080
```

## Demo: Generate Attack Traffic

Use the included demo client to send representative payloads and watch detections in real time:

```bash
# Send all demo payloads (SQLi, XSS, command injection, path traversal, etc.)
python3 demo_attack_client.py 127.0.0.1 8080 --payload all

# Or a single payload type
python3 demo_attack_client.py 127.0.0.1 8080 --payload xss
```

Console output will summarize detections; full JSON events are written to `logs/webguardian_events.log`.

## Event Logging (JSONL)

Each detection is recorded as a single JSON object per line, e.g.:

```json
{
  "timestamp": 1697599999.123,
  "signature": "SQL Injection",
  "severity": "high",
  "src": "10.0.0.5:53422",
  "dst": "10.0.0.10:8080",
  "http_summary": "GET /vuln?username=admin' OR 1=1-- HTTP/1.1",
  "raw_excerpt": "GET /vuln?username=admin' OR 1=1--\\nHost: ...",
  "blocked": true,
  "description": "Classic SQLi payload patterns attempting to bypass auth or extract schema data."
}
```

These logs are suitable for ingestion by tools like `jq`, Elastic, Splunk, or custom dashboards.

## Extending Detection

Signatures are defined as small, explainable regexes. To add a new one, edit `web_guardian_middlebox.py` and extend `DEFAULT_SIGNATURES`:

```python
from web_guardian_middlebox import HttpAttackSignature

DEFAULT_SIGNATURES.append(
    HttpAttackSignature(
        name="Open Redirect",
        pattern=r"/redirect\\?url=https?://",
        description="Potential open redirect parameter in URL.",
        severity="medium",
    )
)
```

Each signature includes a `name`, `pattern`, `description`, and `severity`. Matches generate events with clear, human‑readable context.

## How It Works

- Packet capture: sniffs IP/TCP packets and extracts HTTP payloads
- Heuristics: recognizes basic HTTP request/response shapes
- Detection: runs payloads through the configured signature set
- Response: optionally injects TCP RST packets to terminate sessions
- Observability: emits JSONL events and concise console summaries

## Safety and Ethics

- Use only on networks and systems you own or are explicitly authorized to test.
- Active blocking (`--block`) terminates live TCP connections; enable only in lab environments or with prior approval.
- TLS/HTTPS traffic is opaque to packet‑level inspection without decryption; this tool focuses on clear‑text HTTP.

## Project Structure

- `web_guardian_middlebox.py` — core engine and CLI
- `demo_attack_client.py` — helper to generate test traffic
- `requirements.txt` — Python dependencies

Additional scripts in the repository support broader networking experiments but are not required to run WebGuardian.

## Resume Highlights

- Built a packet‑level HTTP IDS with active response in Python
- Implemented pluggable regex signatures for common web attack classes
- Engineered TCP RST injection to safely tear down malicious sessions
- Produced structured, SIEM‑ready security telemetry with minimal dependencies

## Roadmap (Ideas)

- Optional PCAP capture for offline analysis and regression testing
- Tunable rule packs (e.g., OWASP Top 10 profiles) and false‑positive controls
- Basic HTTP parser hardening and richer request metadata extraction
- Optional HTTPS support via proxy integration or mirrored TLS termination

---

Questions or want suggested improvements? Open an issue or start a discussion.

