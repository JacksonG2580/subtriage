"""Rule-based risk scoring. Works offline and gives the LLM a pre-ranked starting point."""

import re

# keyword -> (weight, what it suggests)
NAME_KEYWORDS = {
    "admin": (20, "administrative interface"), "phpmyadmin": (25, "database admin panel"),
    "jenkins": (20, "CI server"), "gitlab": (18, "source control"), "git": (12, "source control"),
    "ci": (10, "CI/CD"), "kibana": (18, "log dashboard"), "grafana": (15, "metrics dashboard"),
    "prometheus": (15, "metrics endpoint"), "elastic": (15, "Elasticsearch"), "swagger": (18, "API docs"),
    "dev": (15, "development environment"), "develop": (15, "development environment"),
    "staging": (15, "staging environment"), "stage": (12, "staging environment"),
    "stg": (12, "staging environment"), "test": (12, "test environment"), "qa": (12, "QA environment"),
    "uat": (12, "UAT environment"), "preprod": (12, "pre-production"), "sandbox": (12, "sandbox"),
    "internal": (15, "internal-only service"), "intranet": (15, "internal-only service"),
    "old": (10, "legacy/forgotten host"), "legacy": (10, "legacy/forgotten host"),
    "backup": (12, "backup host"), "bak": (10, "backup host"), "tmp": (8, "temporary host"),
    "demo": (8, "demo instance"), "beta": (8, "pre-release build"),
    "console": (12, "management console"), "dashboard": (12, "dashboard"), "manage": (12, "management UI"),
    "db": (12, "database"), "sql": (12, "database"), "ftp": (10, "file transfer"),
    "vpn": (10, "remote access"), "remote": (10, "remote access"), "rdp": (15, "remote desktop"),
    "citrix": (10, "remote access gateway"), "k8s": (15, "Kubernetes"), "kube": (15, "Kubernetes"),
    "registry": (15, "container/package registry"), "api": (8, "API"), "upload": (8, "file upload"),
    "sso": (8, "auth service"), "auth": (8, "auth service"), "jira": (10, "issue tracker"),
    "confluence": (10, "wiki"), "sonar": (12, "code quality server"), "monitor": (10, "monitoring"),
}

# substring in <title> -> (weight, indicator, next step)
TITLE_SIGNATURES = [
    ("phpmyadmin", 30, "phpMyAdmin login", "Check version for CVEs; test whether it's reachable without network restrictions."),
    ("jenkins", 25, "Jenkins", "Check if /script or /asynchPeople/ is reachable anonymously; note the version."),
    ("swagger", 20, "Swagger UI / API docs", "Enumerate the documented endpoints and test which ones work without auth."),
    ("api documentation", 15, "API documentation", "Map endpoints from the docs and test auth on each."),
    ("index of /", 20, "Directory listing", "Browse the listing for backups, configs, or source files."),
    ("kibana", 25, "Kibana", "Check whether dashboards/Discover load without auth (log data exposure)."),
    ("grafana", 18, "Grafana", "Check for anonymous access and the version; try the login page's default creds only if in scope."),
    ("gitlab", 15, "GitLab", "Check /explore for public projects and whether sign-up is open."),
    ("sonarqube", 18, "SonarQube", "Check for anonymous project browsing (leaks source and secrets)."),
    ("portainer", 25, "Portainer", "Container management UI: confirm auth is enforced and the instance is initialised."),
    ("rabbitmq", 18, "RabbitMQ management", "Management UI exposed: confirm it isn't using default guest credentials (if in scope)."),
    ("traefik", 15, "Traefik dashboard", "Dashboard leaks internal routes/services; review for internal hostnames."),
    ("webmin", 20, "Webmin", "Server admin panel: identify version and check for known CVEs."),
    ("apache tomcat", 15, "Tomcat", "Check whether /manager/html is reachable; note version."),
    ("whitelabel error page", 12, "Spring Boot", "Probe Spring actuator endpoints (/actuator, /actuator/env) for info leaks."),
    ("admin", 15, "Admin page", "Identify the product behind the admin page and look for auth weaknesses."),
    ("dashboard", 10, "Dashboard", "Identify the product; check what's visible before login."),
    ("login", 6, "Login page", "Identify the product; check for default credentials policy and verbose error messages."),
    ("sign in", 6, "Login page", "Identify the product; check for default credentials policy and verbose error messages."),
    ("welcome to nginx", 8, "Default nginx page", "Default page suggests an unfinished/forgotten host: fuzz for content paths."),
    ("apache2 default page", 8, "Default Apache page", "Default page suggests an unfinished/forgotten host: fuzz for content paths."),
    ("iis windows server", 8, "Default IIS page", "Default page suggests an unfinished/forgotten host: fuzz for content paths."),
    ("test page", 8, "Test page", "Test content in production: look for other leftover dev files."),
]

PORT_SIGNATURES = {
    2375: (40, "Docker API port open", "Check GET /version: an unauthenticated Docker API means host compromise."),
    10250: (35, "Kubelet port open", "Check whether /pods responds without auth."),
    6443: (20, "Kubernetes API port open", "Check what /version and /api return anonymously."),
    9200: (30, "Elasticsearch port open", "Check / and /_cat/indices for unauthenticated data access."),
    5601: (20, "Kibana port open", "Check whether Kibana loads without auth."),
    9090: (15, "Prometheus/Cockpit port open", "Check /targets and /api/v1/status/config for internal topology leaks."),
    8888: (15, "Jupyter/alt-HTTP port open", "If Jupyter, check for token-less notebook access (code execution)."),
}

VERSION_RE = re.compile(r"\d+\.\d+")


def _tokens(host, domain):
    sub = host[: -len(domain)].rstrip(".") if host.endswith(domain) else host
    return re.findall(r"[a-z]+", sub)


def score(profile, domain):
    """Return {score, priority, indicators, next_steps} for one profiled host."""
    points, indicators, steps = 0, [], []

    def add(weight, indicator, step=None):
        nonlocal points
        points += weight
        indicators.append(indicator)
        if step and step not in steps:
            steps.append(step)

    # Subdomain takeover: highest-value finding a recon tool can surface on its own.
    if profile.get("dangling_cname"):
        provider = profile.get("takeover_provider") or "unknown provider"
        add(55, f"CNAME -> {profile['cname'][-1]} does not resolve ({provider})",
            f"Possible subdomain takeover: check if the {provider} resource name can be claimed (verify only, don't claim without permission).")
    for web in profile.get("web", []):
        if web.get("takeover_fingerprint"):
            add(50, f"Unclaimed-resource page for {web['takeover_fingerprint']} at {web['url']}",
                f"Likely subdomain takeover via {web['takeover_fingerprint']}: confirm with the provider's docs.")

    seen = set()
    for token in _tokens(profile["host"], domain):
        for kw, (weight, meaning) in NAME_KEYWORDS.items():
            if kw not in seen and (token == kw or (len(kw) >= 4 and kw in token)):
                seen.add(kw)
                add(weight, f"name contains '{kw}' ({meaning})")
    if seen & {"dev", "develop", "staging", "stage", "stg", "test", "qa", "uat", "preprod", "sandbox"}:
        steps.append("Non-production naming: compare against prod for debug modes, verbose errors, test accounts, and exposed .git/.env files.")

    for port in profile.get("open_ports", []):
        sig = PORT_SIGNATURES.get(port["port"])
        if sig:
            add(*sig)
        else:
            add(8, f"port {port['port']} open ({port['guess']})",
                f"Identify the service on port {port['port']}: non-standard ports are often less hardened.")

    for web in profile.get("web", []):
        status, title = web["status"], (web.get("title") or "").lower()
        headers = web.get("headers", {})
        if status in (401, 403):
            add(8, f"{web['url']} returns {status} (something is behind auth)",
                "Auth-gated resource: identify the product and check for auth bypass via alternate paths/methods/hosts.")
        elif status >= 500:
            add(6, f"{web['url']} returns {status}", "Server errors: look for stack traces or debug output.")
        elif status == 200:
            points += 3
        for sig, weight, indicator, step in TITLE_SIGNATURES:
            if sig in title:
                add(weight, f"title '{web['title']}' -> {indicator}", step)
                break
        for h in ("server", "x-powered-by", "x-aspnet-version"):
            if h in headers and VERSION_RE.search(headers[h]):
                add(5, f"version disclosed in {h}: {headers[h]}",
                    "Version disclosed: look up known CVEs for that exact version.")
        if "x-jenkins" in headers:
            add(15, f"Jenkins header ({headers['x-jenkins']})", "Jenkins identified via header: check anonymous read access.")

    priority = "high" if points >= 50 else "medium" if points >= 25 else "low" if points >= 10 else "info"
    return {"score": points, "priority": priority, "indicators": indicators, "next_steps": steps}
