# Security Policy

admino can read your email, files, and calendar, so I take security issues
seriously. If you find one, please report it privately — don't open a public issue.

## Reporting a vulnerability

Go to the repository's **Security** tab and click **Report a vulnerability**. That
opens a private conversation with the maintainer.

Include what's needed to reproduce it — the steps, what happened, and why it matters.
A proof of concept helps.

## What to expect

I'll acknowledge your report within a few days, confirm whether it's a real problem,
and keep you posted until it's resolved. Glad to credit you once it's fixed, or keep
it anonymous if you'd rather. Please give me a chance to ship a fix before making it
public.

## What's most useful

admino runs on your own machine, so the most valuable reports are the ones that break
its own guarantees: permission bypasses, credentials leaking into logs or the audit
trail, escapes from the egress whitelist or container isolation, injection through LLM
output or tool arguments, and authentication bypasses on the API.
