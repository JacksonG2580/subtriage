import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import heuristics, profiler
from .discovery import Resolver, discover

DEFAULT_WORDLIST = Path(__file__).with_name("wordlist.txt")
PRIORITY_COLORS = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"


def log(msg):
    print(msg, file=sys.stderr)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="subtriage",
        description="Discover subdomains, profile them, and prioritize what to test first.",
    )
    p.add_argument("domain", help="in-scope apex domain, e.g. example.com")
    p.add_argument("--authorized", action="store_true",
                   help="confirm you have written permission to test this domain; enables "
                        "DNS brute force, HTTP profiling and port checks (otherwise passive only)")
    p.add_argument("-w", "--wordlist", type=Path, default=DEFAULT_WORDLIST, help="subdomain wordlist for brute force")
    p.add_argument("--resolvers", help="comma-separated DNS resolvers (default: system)")
    p.add_argument("--dns-concurrency", type=int, default=100)
    p.add_argument("--http-concurrency", type=int, default=20)
    p.add_argument("--no-ai", action="store_true", help="skip the LLM step; heuristic ranking only")
    p.add_argument("--model", default=None, help="Claude model for analysis (default: claude-opus-5-5)")
    p.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"])
    p.add_argument("--ai-top", type=int, default=75, help="send only the N highest pre-scored hosts to the LLM")
    p.add_argument("-o", "--output", type=Path, help="write the full JSON report here")
    return p.parse_args(argv)


async def run_pipeline(args):
    domain = args.domain.lower().strip().rstrip(".")
    resolver = Resolver(args.resolvers.split(",") if args.resolvers else None, args.dns_concurrency)

    wordlist = None
    if args.authorized:
        wordlist = [w.strip().lower() for w in args.wordlist.read_text().splitlines()
                    if w.strip() and not w.startswith("#")]
    else:
        log("[i] Passive mode: no brute force, HTTP or port checks. Pass --authorized if you have permission.")

    records = await discover(domain, resolver, wordlist, log)
    if args.authorized:
        hosts = await profiler.profile_all(records, args.http_concurrency, log=log)
    else:
        hosts = profiler.dns_only(records)

    for host in hosts:
        host["risk"] = heuristics.score(host, domain)
    hosts.sort(key=lambda h: h["risk"]["score"], reverse=True)
    return domain, hosts


def print_heuristic_table(hosts, limit=40):
    print(f"\n=== Heuristic ranking (top {min(limit, len(hosts))} of {len(hosts)}) ===")
    for h in hosts[:limit]:
        r = h["risk"]
        color = PRIORITY_COLORS[r["priority"]]
        status = ",".join(str(w["status"]) for w in h["web"]) or "-"
        print(f"{color}{r['priority'].upper():7}{RESET} {r['score']:>4}  {h['host']}  [{status}]")
        for ind in r["indicators"][:4]:
            print(f"               - {ind}")


def print_ai_report(report):
    print("\n=== AI triage ===")
    print(report["summary"])
    for t in report["targets"]:
        color = PRIORITY_COLORS.get(t["priority"], "")
        print(f"\n{color}[{t['priority'].upper()}]{RESET} {t['host']}")
        print(f"  Why: {t['rationale']}")
        print(f"  Attacker's view: {t['attacker_perspective']}")
        for i, step in enumerate(t["next_steps"], 1):
            print(f"  {i}. {step}")


def main(argv=None):
    args = parse_args(argv)
    domain, hosts = asyncio.run(run_pipeline(args))
    print_heuristic_table(hosts)

    report = None
    if not args.no_ai and hosts:
        from . import ai  # imported lazily so --no-ai works without the anthropic package

        top = hosts[: args.ai_top]
        if len(hosts) > len(top):
            log(f"[i] Sending the top {len(top)} of {len(hosts)} hosts to the LLM (raise with --ai-top)")
        log(f"[*] Asking {args.model or ai.DEFAULT_MODEL} to prioritize...")
        try:
            report = ai.analyze(domain, top, model=args.model or ai.DEFAULT_MODEL, effort=args.effort)
            print_ai_report(report)
        except Exception as e:  # keep the heuristic results even if the API call fails
            log(f"[!] AI analysis failed: {type(e).__name__}: {e}")

    if args.output:
        args.output.write_text(json.dumps({
            "domain": domain,
            "generated": datetime.now(timezone.utc).isoformat(),
            "mode": "active" if args.authorized else "passive",
            "hosts": hosts,
            "ai_triage": report,
        }, indent=2))
        log(f"[+] Report written to {args.output}")


if __name__ == "__main__":
    main()
