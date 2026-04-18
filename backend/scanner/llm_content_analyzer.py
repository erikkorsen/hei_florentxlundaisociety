"""Use Haiku to analyze the content of an exposed file and describe what sensitive data it contains."""

import asyncio
import os


def _get_api_key() -> str | None:
    # Handle both the correct spelling and the common typo in the env file
    return os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTROPHIC_API_KEY")


async def analyze_exposed_file(path: str, content: str) -> str:
    """
    Send exposed file content to claude-haiku and get a plain-English
    description of what sensitive data was found.

    Returns an empty string if the API key is missing or the call fails.
    """
    api_key = _get_api_key()
    if not api_key or not content.strip():
        return ""

    # Truncate to keep costs low and latency short
    snippet = content[:3000]

    prompt = f"""You are a security analyst. An automated scanner found this file publicly accessible on a web server.

File path: {path}

File content (first 3000 chars):
---
{snippet}
---

In 1-3 sentences, describe exactly what sensitive data this file exposes and why it's dangerous. Be specific — name actual credential types, database names, API services, or configuration values you can see (but do NOT reproduce the actual secret values). If the file appears to be a false positive (e.g. empty, a demo/example file, or contains no real secrets), say so briefly.

Reply with only the description, no preamble."""

    try:
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=api_key)

        msg = await asyncio.wait_for(
            client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
            ),
            timeout=10,
        )
        result = msg.content[0].text.strip()
        return f" AI analysis: {result}"
    except Exception:
        return ""
