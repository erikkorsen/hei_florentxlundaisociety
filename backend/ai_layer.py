import asyncio
import json
import os
from collections import defaultdict

from models import (
    AnalyseRequest, AnalysisResponse, Category, Finding,
    GroupedFinding, Severity,
)

SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.PASS: 3}

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
    groups: list[GroupedFinding],
) -> tuple[str | None, list[str], list[GroupedFinding]]:
    api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTROPHIC_API_KEY")
    if not api_key or not groups:
        return None, [], groups

    groups_data = [
        {
            "id": g.id,
            "category": g.category.value,
            "severity": g.severity.value,
            "title": g.title,
            "description": g.description,
            "count": g.count,
        }
        for g in groups
    ]

    prompt = f"""You are a security analyst reviewing automated scan results for: {target_url}

Grouped findings (JSON):
{json.dumps(groups_data, indent=2)}

Instructions:
- Consider what kind of site this likely is based on the URL (major company, startup, local server, etc.)
- Some findings may be false positives or low-risk for this specific target (e.g. large companies like Google use alternative security mechanisms that generic scanners miss)

Return ONLY a valid JSON object with exactly these fields:
{{
  "summary": "4-5 sentences written for a non-technical person (think: business owner or founder, not a developer). Assess the overall security posture of the site. Explain why the site received the grade it did. Call out whether findings are genuine risks or likely scanner noise. Be direct, not alarmist.",
  "priority_actions": ["[Quick fix] most important easy fix", "[Moderate] second most important", "[Major] third most important"],
  "groups": [
    {{
      "id": "<same id from input, unchanged>",
      "title": "<rewritten title, contextual and specific>",
      "description": "<nuanced description — if this is likely a false positive or low risk for this target, explain why>",
      "likely_false_positive": true or false,
      "plain_english": "<explain this finding like you're talking to someone who doesn't know what a port, header, or SSL is. One sentence, no jargon, use everyday analogies.>",
      "business_impact": "<what's the worst realistic thing that could happen if this isn't fixed? One sentence.>"
    }}
  ]
}}

Rules:
- "priority_actions" must have exactly 3 items. Each item must begin with one of: [Quick fix], [Moderate], or [Major]. If fewer than 3 real issues exist, fill remaining slots with "[Quick fix] No further action needed."
- Every group from input must appear in "groups" output, same id
- Do not change "severity" — only title, description, likely_false_positive, plain_english, business_impact
- Respond with JSON only. No markdown, no explanation outside the JSON."""

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
                })

        enriched = sorted(group_map.values(), key=lambda g: SEVERITY_ORDER.get(g.severity, 99))
        return summary, priority_actions, enriched

    except Exception:
        return None, [], groups


async def analyse(request: AnalyseRequest) -> AnalysisResponse:
    issue_groups, pass_groups, pass_count = _group_findings(request.findings)
    summary, priority_actions, enriched_groups = await _enrich_with_ai(request.target_url, issue_groups)

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
