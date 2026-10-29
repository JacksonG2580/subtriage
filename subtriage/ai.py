"""Phase 3: LLM prioritization of the profiled hosts.

Uses Claude via the Anthropic SDK. Credentials come from ANTHROPIC_API_KEY
(or an `ant auth login` profile). Swap this module out if you pick another LLM;
the rest of the pipeline only depends on analyze() returning the schema below.
"""

import json

import anthropic

DEFAULT_MODEL = "claude-opus-5-5"

SYSTEM_PROMPT = """You are a senior penetration tester mentoring a junior analyst during an \
authorized external assessment. You will receive JSON describing subdomains discovered for the \
in-scope domain: DNS records, HTTP status codes, page titles, selected response headers, open \
non-standard ports, and a rule-based pre-score with the indicators that produced it.

Your job is triage: decide which hosts deserve the tester's time first and why.

- Rank by realistic attacker value, not by pre-score alone. Weigh combinations (e.g. a "dev" \
name plus a framework error page plus a version header is worth more than any one of them).
- Ground every claim in fields present in the data. If a signal is ambiguous (a 403 could be a \
WAF or a real admin panel), say so.
- Next steps must be concrete, low-impact verification actions a tester would do first \
(specific paths to request, what response would confirm the issue, what to look up). No \
destructive actions, no credential brute forcing, no claiming takeover resources.
- In "attacker_perspective", explain the reasoning an adversary would follow, in plain \
language, so a beginner learns to think that way.
- Leave out hosts with nothing notable; mention in the summary how many were skipped."""

RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "targets": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "priority": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "rationale": {"type": "string"},
                    "attacker_perspective": {"type": "string"},
                    "next_steps": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["host", "priority", "rationale", "attacker_perspective", "next_steps"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "targets"],
    "additionalProperties": False,
}


class AnalysisError(Exception):
    pass


def _compact(host):
    """Drop fields the model doesn't need, to keep the payload small."""
    return {
        "host": host["host"],
        "a": host["a"],
        "cname": host["cname"],
        "dangling_cname": host["dangling_cname"],
        "takeover_provider": host["takeover_provider"],
        "open_ports": host["open_ports"],
        "web": [{k: w[k] for k in ("url", "status", "title", "headers", "takeover_fingerprint")} for w in host["web"]],
        "prescore": host["risk"]["score"],
        "indicators": host["risk"]["indicators"],
    }


def analyze(domain, hosts, model=DEFAULT_MODEL, effort="medium"):
    payload = json.dumps({"domain": domain, "hosts": [_compact(h) for h in hosts]}, sort_keys=True)
    client = anthropic.Anthropic()
    with client.beta.messages.stream(
        model=model,
        max_tokens=32000,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",  # if the model declines, the API retries on a suitable fallback model
        system=SYSTEM_PROMPT,
        output_config={"effort": effort, "format": {"type": "json_schema", "schema": RESULT_SCHEMA}},
        messages=[{"role": "user", "content": f"Recon results for {domain}:\n{payload}"}],
    ) as stream:
        message = stream.get_final_message()

    if message.stop_reason == "refusal":
        raise AnalysisError("the model declined this request; use the heuristic ranking instead")
    if message.stop_reason == "max_tokens":
        raise AnalysisError("response hit max_tokens; rerun with fewer hosts (--ai-top)")
    text = next(b.text for b in message.content if b.type == "text")
    return json.loads(text)
