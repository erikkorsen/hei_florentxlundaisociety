import asyncio
import json
import os
from collections import defaultdict
from pathlib import Path

from models import (
    AnalyseRequest, AnalysisResponse, Category, Finding,
    GroupedFinding, Severity,
)

SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.PASS: 3}

# Load the AI content style guide once at import time
_STYLE_GUIDE_PATH = Path(__file__).resolve().parent.parent / "docs" / "AI_STYLE.md"
_STYLE_GUIDE = _STYLE_GUIDE_PATH.read_text() if _STYLE_GUIDE_PATH.exists() else ""

CATEGORY_GROUP_TITLES = {
    Category.PORTS: lambda n: f"{n} dangerous ports open",
    Category.SECRETS: lambda n: f"{n} sensitive files or paths exposed",
    Category.HEADERS: lambda n: f"{n} security headers missing",
    Category.DNS: lambda n: f"{n} email / DNS security issues",
    Category.ADMIN: lambda n: f"{n} admin panels exposed",
    Category.COOKIES: lambda n: f"{n} cookie security issues",
    Category.CORS: lambda n: f"{n} CORS policy issues",
    Category.SSL: lambda n: f"{n} SSL / TLS issues",
    Category.GITHUB: lambda n: f"{n} GitHub workflow issues",
    Category.FIREWALL: lambda n: f"{n} firewall issue(s)",
}

CATEGORY_PASS_TITLES = {
    Category.SECRETS: "No exposed secrets or credentials",
    Category.PORTS: "No dangerous ports open",
    Category.SSL: "SSL/TLS properly configured",
    Category.ADMIN: "No exposed admin panels",
    Category.HEADERS: "Security headers in place",
    Category.DNS: "Email & DNS security configured",
    Category.COOKIES: "Cookies properly secured",
    Category.CORS: "CORS policy configured correctly",
    Category.GITHUB: "GitHub workflows secure",
    Category.FIREWALL: "Firewall configured",
    Category.SUBDOMAINS: "No subdomain issues found",
    Category.BREACH: "No known data breaches",
}


def _group_findings(findings: list[Finding]) -> tuple[list[GroupedFinding], list[GroupedFinding], int]:
    issues = [f for f in findings if f.severity != Severity.PASS]
    passes = [f for f in findings if f.severity == Severity.PASS]

    by_cat: dict[Category, list[Finding]] = defaultdict(list)
    for f in issues:
        by_cat[f.category].append(f)

    groups: list[GroupedFinding] = []
    for cat, cat_findings in by_cat.items():
        cat_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        count = len(cat_findings)
        highest = cat_findings[0].severity

        if count == 1:
            title = cat_findings[0].title
            description = cat_findings[0].description
            fix = cat_findings[0].fix
        else:
            label_fn = CATEGORY_GROUP_TITLES.get(cat)
            title = label_fn(count) if label_fn else f"{count} {cat.value} issues"
            description = " · ".join(f.title for f in cat_findings)
            fix = cat_findings[0].fix  # use most severe finding's fix as default

        affected = list(dict.fromkeys(f.affected for f in cat_findings))

        groups.append(GroupedFinding(
            id=f"group_{cat.value}",
            severity=highest,
            title=title,
            description=description,
            affected=affected,
            fix=fix,
            category=cat,
            count=count,
            raw_ids=[f.id for f in cat_findings],
            likely_false_positive=False,
            plain_english="",
            business_impact="",
        ))

    groups.sort(key=lambda g: SEVERITY_ORDER.get(g.severity, 99))

    # Group passes by category
    pass_by_cat: dict[Category, list[Finding]] = defaultdict(list)
    for f in passes:
        pass_by_cat[f.category].append(f)

    pass_groups: list[GroupedFinding] = []
    for cat, cat_findings in pass_by_cat.items():
        count = len(cat_findings)
        title = CATEGORY_PASS_TITLES.get(cat, f"{cat.value} checks passed")
        description = " · ".join(f.title for f in cat_findings)

        pass_groups.append(GroupedFinding(
            id=f"pass_{cat.value}",
            severity=Severity.PASS,
            title=title,
            description=description,
            affected=[],
            fix="",
            category=cat,
            count=count,
            raw_ids=[f.id for f in cat_findings],
            likely_false_positive=False,
            plain_english="",
            business_impact="",
        ))

    return groups, pass_groups, len(passes)


async def _enrich_with_ai(
    target_url: str,
    github_url: str | None,
    groups: list[GroupedFinding],
    findings: list[Finding],
) -> tuple[str | None, list[str], list[GroupedFinding]]:
    api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTROPHIC_API_KEY")
    if not api_key or not groups:
        return None, [], groups

    # Build a lookup: category -> raw findings for that category
    findings_by_cat: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.severity != Severity.PASS:
            findings_by_cat[f.category.value].append(f)

    groups_data = []
    for g in groups:
        entry: dict = {
            "id": g.id,
            "category": g.category.value,
            "severity": g.severity.value,
            "title": g.title,
            "affected": g.affected,
            "fix": g.fix,
        }
        # Include individual findings so the AI can assess each one
        raw = findings_by_cat.get(g.category.value, [])
        if len(raw) > 1:
            entry["findings"] = [
                {
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "affected": f.affected,
                }
                for f in raw
            ]
        else:
            entry["description"] = g.description
        groups_data.append(entry)

    target_context = f"Target: {target_url}"
    if github_url:
        target_context += f"\nGitHub repo: {github_url}"

    prompt = f"""{target_context}

You are reviewing automated security scan results. Your job is to make these results ACCURATE and USEFUL — not to repeat what the scanner said, but to apply real-world judgment.

Follow this style guide for all text you write:
{_STYLE_GUIDE}

Scan findings (JSON):
{json.dumps(groups_data, indent=2)}

Your task:
1. Look at the actual affected URLs/hosts and finding details. Assess each finding for this specific target.
2. DEFAULT: Treat every finding as a real issue UNLESS you have concrete evidence it is not. A finding should only be marked as likely_false_positive if you can explain specifically why it does not apply to THIS site — not just because it "might" be intentional or "could" be behind a load balancer.
3. Examples of when likely_false_positive should be TRUE (you need this level of certainty):
   - The target is a well-known major platform (google.com, github.com, cloudflare.com) that is known to intentionally configure things this way
   - The finding contradicts other findings (e.g., flagging missing HTTPS when another finding confirms HTTPS is working)
4. Examples of when likely_false_positive should be FALSE (keep it as a real finding):
   - Missing security headers — these are almost always real issues regardless of site size
   - Open ports — unless you can name the specific reason this port should be open
   - Missing email security records — flag it, the site owner can decide if they send email
   - Any finding where you are unsure — default to treating it as real
5. Write a summary that tells the site owner what matters. Be direct about what needs attention.

Return ONLY valid JSON:
{{
  "summary": "3-5 sentences. What is the actual security posture of this site? Which findings are real concerns vs scanner noise? Be specific and honest — if the site looks well-maintained, say so. If there are genuine risks, be clear about what they are.",
  "priority_actions": ["Fix X — because Y", "Fix A — because B", "Fix C — because D"],
  "groups": [
    {{
      "id": "<same id from input>",
      "title": "<specific, accurate title for this finding>",
      "description": "<what this actually means for this site — reference the specific affected URLs/ports/headers. If it's likely not a real issue, explain why concretely>",
      "likely_false_positive": true or false,
      "plain_english": "<2-3 sentences explaining this problem to someone with zero technical knowledge. What is actually happening, in normal words? Use physical-world analogies when they help — like doors, locks, windows, mail. Do not use any technical terms without immediately explaining them.>",
      "business_impact": "<one sentence: what could realistically happen if this isn't addressed? Say 'Low risk — no action needed' if it's genuinely not a concern.>",
      "fix": "<Step-by-step instructions to fix this specific issue. Be concrete: name the exact header to add, the exact config line to change, the exact command to run. If there are multiple approaches (nginx vs Apache vs cloud), give the most common one. 2-4 sentences max.>"
    }}
  ]
}}

Rules:
- "priority_actions": exactly 3 items, ordered by risk (most dangerous first). Each one should name the specific problem and explain why it matters. No effort labels. If fewer than 3 real issues, use "No further action needed."
- Every group from input must appear in output with the same id
- Be specific — reference actual URLs, ports, headers from the data. Don't be generic.
- JSON only. No markdown fences, no text outside the JSON."""

    try:
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=api_key)

        msg = await asyncio.wait_for(
            client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=3000,
                messages=[{"role": "user", "content": prompt}],
            ),
            timeout=30,
        )

        raw = msg.content[0].text.strip()
        # Strip markdown fences if Claude adds them despite instructions
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        data = json.loads(raw)

        summary = data.get("summary") or None
        priority_actions = [str(a) for a in data.get("priority_actions", [])][:3]

        group_map = {g.id: g for g in groups}
        for g_data in data.get("groups", []):
            gid = g_data.get("id")
            if gid in group_map:
                original = group_map[gid]
                group_map[gid] = original.model_copy(update={
                    "title": g_data.get("title", original.title),
                    "description": g_data.get("description", original.description),
                    "likely_false_positive": bool(g_data.get("likely_false_positive", False)),
                    "plain_english": g_data.get("plain_english", ""),
                    "business_impact": g_data.get("business_impact", ""),
                    "fix": g_data.get("fix", original.fix),
                })

        enriched = sorted(group_map.values(), key=lambda g: SEVERITY_ORDER.get(g.severity, 99))
        return summary, priority_actions, enriched

    except Exception:
        return None, [], groups


async def analyse(request: AnalyseRequest) -> AnalysisResponse:
    issue_groups, pass_groups, pass_count = _group_findings(request.findings)
    summary, priority_actions, enriched_groups = await _enrich_with_ai(
        request.target_url, request.github_url, issue_groups, request.findings,
    )

    all_groups = list(enriched_groups) + pass_groups

    return AnalysisResponse(
        target_url=request.target_url,
        summary=summary,
        priority_actions=priority_actions,
        grouped_findings=all_groups,
        pass_count=pass_count,
        ai_powered=summary is not None,
        raw_findings=request.findings,
    )
