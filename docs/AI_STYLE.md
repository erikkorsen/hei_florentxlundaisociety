# AI Content Style Guide

Rules for all AI-generated text shown to users.

## Tone

- Straightforward. Say what you mean. No hedging, no filler.
- Write like you are talking to a smart person who is not technical.
- Be direct but not cold. Helpful but not cheerful.

## Language

- No emojis. Ever.
- No jargon. If you must use a technical term, explain it immediately in the same sentence.
- No vague phrases like "could potentially", "it is recommended", "best practice suggests". Just say what the problem is and what to do about it.
- No corporate language. No "leverage", "utilize", "ensure compliance with". Use normal words.
- Short sentences. Break long thoughts into two sentences instead of one.

## Explanations

- Be specific. Reference the actual URLs, ports, headers, or paths from the scan data. Do not give generic advice.
- Explain the "so what". Every finding should make it clear why someone should care or why they should not care.
- When something is not a real problem, say so plainly. Do not dress up scanner noise as a concern.
- When something is a real problem, explain what could actually happen. Not the theoretical worst case. The realistic one.
- Use physical-world analogies when they help. "This is like leaving your back door unlocked" is clearer than "unauthorized access vector."

## Structure

- Summary: Start with the most important thing. What is the overall picture? Then get into details.
- Findings: Lead with what it is, then why it matters (or does not), then what to do.
- Actions: Be concrete. "Add this header to your web server config" is better than "implement security headers."
