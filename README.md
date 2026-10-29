# subtriage

Finds a domain's subdomains, profiles them with low-noise checks, and ranks which ones a tester
should look at first. Each host gets the evidence behind its ranking and suggested next steps.

> **Only run active mode (`--authorized`) against domains you own or have written permission to
> test** (your own lab, a bug-bounty program's listed scope, or a signed engagement).
> Passive mode only queries public data sources.

## Pipeline

| Phase | Module | What it does |
|---|---|---|
| 1. Discovery | `subtriage/discovery.py` | Passive: crt.sh certificate transparency, HackerTarget, AlienVault OTX passive DNS. Active: async DNS brute force from a wordlist, with wildcard-DNS filtering. Records A and CNAME, and flags CNAMEs whose target no longer exists. |
| 2. Profiling | `subtriage/profiler.py` | One HTTP(S) GET per endpoint (status, title, server and framework headers), TCP checks on 14 admin/dev ports, takeover fingerprints for known cloud providers. |
| 3a. Heuristics | `subtriage/heuristics.py` | Rule-based score from naming conventions, page titles, exposed ports, status codes, version leaks and takeover signals. Runs offline. |
| 3b. AI triage | `subtriage/ai.py` | Sends the scored JSON to an LLM (Claude by default) with a senior-analyst system prompt. Returns ranked targets, the rationale, the attacker's view and next steps. |

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # only needed for the AI step
```

## Usage

```bash
# Passive only (safe on any domain): CT logs + passive DNS, heuristic ranking
.venv/bin/python -m subtriage example.com --no-ai

# Full run on an in-scope target, with JSON report
.venv/bin/python -m subtriage target.com --authorized -o report.json

# Bigger wordlist, custom resolvers, cheaper/faster AI pass
.venv/bin/python -m subtriage target.com --authorized \
    -w subdomains-top1million-5000.txt --resolvers 1.1.1.1,8.8.8.8 --effort low
```

If the AI call fails (no key, rate limit, refusal), the heuristic ranking and JSON report are
still produced.

## Swapping the LLM

The proposal leaves the LLM choice open. Only `ai.analyze()` talks to the model. To use another
provider, replace that one function and keep its return shape (`{"summary": str, "targets": [...]}`).

## Ideas for later phases

- More passive sources that need API keys (SecurityTrails, Shodan, VirusTotal)
- Screenshots of web endpoints (e.g. Playwright) for faster human review
- An HTML report
- Diffing against previous runs to flag newly appeared subdomains
