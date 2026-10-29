"""Phase 1: subdomain discovery.

Passive sources (certificate transparency + public passive-DNS/threat-intel
APIs) never touch the target. The wordlist brute force sends DNS queries for
guessed names, so the CLI only runs it with --authorized.
"""

import asyncio
import random
import string

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

USER_AGENT = "subtriage/0.1 (authorized security assessment)"


# --- passive sources -------------------------------------------------------

async def _crtsh(client, domain):
    r = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=60)
    r.raise_for_status()
    names = set()
    for row in r.json():
        names.update(row.get("name_value", "").splitlines())
    return names


async def _hackertarget(client, domain):
    r = await client.get("https://api.hackertarget.com/hostsearch/", params={"q": domain})
    r.raise_for_status()
    if r.text.startswith("error") or "API count exceeded" in r.text:
        raise RuntimeError(r.text.strip()[:80])
    return {line.split(",")[0] for line in r.text.splitlines() if line}


async def _otx(client, domain):
    r = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    r.raise_for_status()
    return {e.get("hostname", "") for e in r.json().get("passive_dns", [])}


PASSIVE_SOURCES = {"crt.sh": _crtsh, "hackertarget": _hackertarget, "alienvault-otx": _otx}


def _normalize(name, domain):
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if name == domain or name.endswith("." + domain):
        return name
    return None


async def passive_enum(domain, log):
    """Return {hostname: set(source names)} from every passive source that answers."""
    found = {}
    async with httpx.AsyncClient(timeout=30, headers={"User-Agent": USER_AGENT}) as client:
        results = await asyncio.gather(
            *(fn(client, domain) for fn in PASSIVE_SOURCES.values()), return_exceptions=True
        )
    for source, result in zip(PASSIVE_SOURCES, results):
        if isinstance(result, Exception):
            log(f"  [!] {source} failed: {type(result).__name__}: {result}")
            continue
        count = 0
        for raw in result:
            name = _normalize(raw, domain)
            if name:
                found.setdefault(name, set()).add(source)
                count += 1
        log(f"  [+] {source}: {count} in-scope names")
    return found


# --- DNS resolution --------------------------------------------------------

class Resolver:
    def __init__(self, nameservers=None, concurrency=100, timeout=3.0):
        self._r = dns.asyncresolver.Resolver()
        if nameservers:
            self._r.nameservers = nameservers
        self._r.lifetime = timeout
        self._sem = asyncio.Semaphore(concurrency)

    async def query(self, name, rtype):
        """Records as strings; [] for no answer/timeout; None for NXDOMAIN."""
        async with self._sem:
            try:
                answer = await self._r.resolve(name, rtype)
            except dns.resolver.NXDOMAIN:
                return None
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                return []
            return [rr.to_text().rstrip(".") for rr in answer]

    async def resolve_host(self, name):
        a, cname = await asyncio.gather(self.query(name, "A"), self.query(name, "CNAME"))
        record = {"host": name, "a": a or [], "cname": cname or [], "dangling_cname": False}
        # A CNAME whose target no longer exists is the classic takeover setup.
        if record["cname"] and not record["a"]:
            record["dangling_cname"] = await self.query(record["cname"][-1], "A") is None
        return record

    async def wildcard_ips(self, domain):
        probes = [f"{''.join(random.choices(string.ascii_lowercase, k=16))}.{domain}" for _ in range(3)]
        results = await asyncio.gather(*(self.query(p, "A") for p in probes))
        return {ip for r in results if r for ip in r}


async def discover(domain, resolver, wordlist=None, log=print):
    """Passive enum + optional brute force, then resolve everything. Returns live records."""
    log("[*] Passive enumeration")
    candidates = await passive_enum(domain, log)
    candidates.setdefault(domain, set()).add("apex")

    wildcard = await resolver.wildcard_ips(domain)
    if wildcard:
        log(f"  [!] wildcard DNS detected ({', '.join(sorted(wildcard))}); brute-force hits on those IPs are dropped")

    if wordlist:
        log(f"[*] Active DNS brute force with {len(wordlist)} words")
        for word in wordlist:
            candidates.setdefault(f"{word}.{domain}", set()).add("bruteforce")

    log(f"[*] Resolving {len(candidates)} candidate names")
    records = await asyncio.gather(*(resolver.resolve_host(n) for n in candidates))

    live = []
    for record in records:
        if not record["a"] and not record["cname"]:
            continue
        sources = candidates[record["host"]]
        if wildcard and sources == {"bruteforce"} and set(record["a"]) <= wildcard:
            continue
        record["sources"] = sorted(sources)
        live.append(record)
    log(f"  [+] {len(live)} names resolve")
    return sorted(live, key=lambda r: r["host"])
