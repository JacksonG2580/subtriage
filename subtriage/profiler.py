"""Phase 2: low-noise service profiling of resolved hosts.

One GET per web endpoint (no crawling, no redirects followed) plus TCP connect
checks against a short list of non-standard ports.
"""

import asyncio
import re
import warnings

import httpx

from .discovery import USER_AGENT

# Non-standard ports that commonly expose admin/dev services.
EXTRA_PORTS = {
    2375: "docker-api", 3000: "grafana/node-dev", 5000: "flask/registry", 5601: "kibana",
    6443: "kubernetes-api", 8000: "http-dev", 8080: "http-alt", 8081: "http-alt",
    8443: "https-alt", 8888: "jupyter/http-alt", 9000: "php-fpm/sonarqube/portainer",
    9090: "prometheus/cockpit", 9200: "elasticsearch", 10250: "kubelet",
}

# Provider CNAME suffixes known to be takeover-prone when the resource is gone.
TAKEOVER_CNAMES = {
    "s3.amazonaws.com": "AWS S3", "s3-website": "AWS S3", "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk", "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku", "herokudns.com": "Heroku", "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure", "cloudapp.azure.com": "Azure", "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob", "azureedge.net": "Azure CDN", "fastly.net": "Fastly",
    "netlify.app": "Netlify", "ghost.io": "Ghost", "pantheonsite.io": "Pantheon",
    "zendesk.com": "Zendesk", "myshopify.com": "Shopify", "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket", "readme.io": "ReadMe", "wpengine.com": "WP Engine",
}

# Response-body strings providers show for unclaimed resources.
TAKEOVER_FINGERPRINTS = {
    "NoSuchBucket": "AWS S3",
    "There isn't a GitHub Pages site here": "GitHub Pages",
    "herokucdn.com/error-pages/no-such-app": "Heroku",
    "Fastly error: unknown domain": "Fastly",
    "The specified bucket does not exist": "Google Cloud Storage",
    "Repository not found": "Bitbucket",
    "Do you want to register": "WordPress.com",
    "project not found": "Surge",
    "Help Center Closed": "Zendesk",
}

INTERESTING_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "www-authenticate",
                       "location", "x-jenkins", "x-gitlab-meta", "x-drupal-cache", "set-cookie")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def takeover_provider(cnames):
    for cname in cnames:
        for suffix, provider in TAKEOVER_CNAMES.items():
            if suffix in cname:
                return provider
    return None


async def _port_open(host, port, timeout):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def _http_get(client, url):
    try:
        r = await client.get(url)
    except httpx.HTTPError:
        return None
    body = r.text[:200_000]
    title = _TITLE_RE.search(body)
    headers = {h: r.headers[h] for h in INTERESTING_HEADERS if h in r.headers}
    if "set-cookie" in headers:  # keep cookie names only; values are noise
        headers["set-cookie"] = ", ".join(c.split("=", 1)[0] for c in r.headers.get_list("set-cookie"))
    return {
        "url": url,
        "status": r.status_code,
        "title": " ".join(title.group(1).split())[:150] if title else None,
        "headers": headers,
        "length": len(r.content),
        "takeover_fingerprint": next((p for s, p in TAKEOVER_FINGERPRINTS.items() if s in body), None),
    }


async def _probe_web(client, host, port=None):
    """Try HTTPS then HTTP on a port; return the first response we get."""
    suffix = f":{port}" if port else ""
    for scheme in ("https", "http"):
        result = await _http_get(client, f"{scheme}://{host}{suffix}/")
        if result:
            return result
    return None


async def profile_host(record, client, sem, port_timeout=1.5):
    host = record["host"]
    async with sem:
        open_ports = []
        if record["a"]:  # nothing to connect to for a dangling CNAME
            checks = await asyncio.gather(*(_port_open(host, p, port_timeout) for p in EXTRA_PORTS))
            open_ports = [p for p, is_open in zip(EXTRA_PORTS, checks) if is_open]
        web = [w for w in await asyncio.gather(
            _probe_web(client, host), *(_probe_web(client, host, p) for p in open_ports)) if w]
    return {
        **record,
        "takeover_provider": takeover_provider(record["cname"]),
        "open_ports": [{"port": p, "guess": EXTRA_PORTS[p]} for p in open_ports],
        "web": web,
    }


async def profile_all(records, concurrency=20, timeout=8.0, log=print):
    log(f"[*] Profiling {len(records)} hosts (HTTP + {len(EXTRA_PORTS)} non-standard ports)")
    # Staging boxes routinely have self-signed/expired certs; we still want their banners.
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=timeout,
                                 headers={"User-Agent": USER_AGENT}) as client:
        return await asyncio.gather(*(profile_host(r, client, sem) for r in records))


def dns_only(records):
    """Profile shape for passive-only runs, so the analysis steps work unchanged."""
    return [{**r, "takeover_provider": takeover_provider(r["cname"]), "open_ports": [], "web": []}
            for r in records]
