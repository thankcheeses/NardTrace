# Future phase: Gmail integration (design only)

Status: **design, not implemented.** NardTrace currently works on `.eml` files and pasted headers only.

## Goal

Let the user pick one Gmail message and analyze it without downloading the `.eml` by hand.

## Principles

| Principle | Design decision |
|---|---|
| Least privilege | OAuth 2.0 with the single scope `https://www.googleapis.com/auth/gmail.readonly`. No send, modify, compose, or settings scopes. |
| Explicit choice | The user searches and **selects a specific message**. NardTrace never lists the inbox in the background, polls, or watches for new mail. |
| No sending | NardTrace never sends mail on the user's behalf. Abuse emails remain copy-ready text the user sends. |
| Local storage | The fetched raw message is stored as case evidence (SHA-256, custody log) exactly like an uploaded `.eml`. |
| Revocable | Tokens are stored encrypted at rest in the local data dir, with a "Disconnect Gmail" button that revokes the token at Google and deletes it locally. |

## Flow

1. User clicks **Connect Gmail** → standard OAuth consent (installed-app / loopback redirect, PKCE).
2. User types a Gmail search query (e.g. `from:billing subject:limited`); NardTrace calls
   `users.messages.list` with that query only, `maxResults=20`, and shows sender/subject/date.
3. User clicks one message → `users.messages.get?format=raw` → base64url-decoded bytes go through the
   **same** `analyze_email()` pipeline and evidence store as an upload. Custody log records
   `evidence.received` with source `gmail:<message id>`.
4. Nothing else is read. No labels are changed.

## Configuration (planned)

```
GOOGLE_OAUTH_CLIENT_ID=
GOOGLE_OAUTH_CLIENT_SECRET=
NARDTRACE_GMAIL_ENABLED=false
```

## Risks and mitigations

- *Token theft* → encrypted at rest, localhost-only binding (compose binds to 127.0.0.1), short-lived access tokens.
- *Scope creep* → scope is a constant in code and asserted in tests.
- *Accidental bulk access* → no "analyze all" action; one message per explicit click.
