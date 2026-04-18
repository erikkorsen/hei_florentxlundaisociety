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


def _group_findings(findings: list[Finding]) -> tuple[list[GroupedFinding], int]:
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
        ))

    groups.sort(key=lambda g: SEVERITY_ORDER.get(g.severity, 99))
    return groups, len(passes)


async def _enrich_with_ai(
    target_url: str,
    groups: list[GroupedFinding],
) -> tuple[str | None, list[str], list[GroupedFinding]]:
    api_key = os.getenv("ANTHROPIC_API_KEY")
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
  "summary": "2-3 sentences. Plain English for a non-technical founder or developer. Assess the ACTUAL risk for this specific site. If findings appear to be scanner noise for a mature site, say so clearly. Be direct, not alarmist.",
  "priority_actions": ["most important fix", "second most important", "third"],
  "groups": [
    {{
      "id": "<same id from input, unchanged>",
      "title": "<rewritten title, contextual and specific>",
      "description": "<nuanced description — if this is likely a false positive or low risk for this target, explain why>",
      "likely_false_positive": true or false
    }}
  ]
}}

Rules:
- "priority_actions" must have exactly 3 items. If fewer than 3 real issues exist, fill remaining slots with "No further action needed."
- Every group from input must appear in "groups" output, same id
- Do not change "severity" — only title, description, likely_false_positive
- Respond with JSON only. No markdown, no explanation outside the JSON."""

    try:
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=api_key)

        msg = await asyncio.wait_for(
            client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}],
            ),
            timeout=20,
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
                })

        enriched = sorted(group_map.values(), key=lambda g: SEVERITY_ORDER.get(g.severity, 99))
        return summary, priority_actions, enriched

    except Exception:
        return None, [], groups


async def analyse(request: AnalyseRequest) -> AnalysisResponse:
    groups, pass_count = _group_findings(request.findings)
    summary, priority_actions, enriched_groups = await _enrich_with_ai(request.target_url, groups)

    return AnalysisResponse(
        target_url=request.target_url,
        summary=summary,
        priority_actions=priority_actions,
        grouped_findings=enriched_groups,
        pass_count=pass_count,
        ai_powered=summary is not None,
        raw_findings=request.findings,
    )
