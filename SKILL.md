---
name: ctfd-api
description: Work with any CTFd-platform CTF via its REST API (api/v1) as a player — list and read challenges, download attached files, submit flags (with correct handling of every attempt status incl. ratelimited), unlock hints, view scoreboard, poll notifications, manage own user/team and API tokens. Use whenever the user references a CTF running on CTFd (e.g. ctf.bug-makers.ru) or says "submit a flag", "list challenges", "show the scoreboard", "download the challenge files" for a CTFd instance. Generic across all CTFd hosts. Player-oriented.
license: MIT
compatibility: opencode
metadata:
  audience: ctf-players
  workflow: ctfd
---

# CTFd API Skill

Generic client for any CTFd (https://ctfd.io) instance REST API v1. All paths
below are relative to the instance base URL `<HOST>`
(e.g. `https://ctf.bug-makers.ru`). Works the same on every CTFd host.

A ready Python client + CLI is bundled at `./scripts/ctfd_client.py`. **Prefer
importing/calling it** over hand-rolled curl — it already handles auth headers,
the response envelope, pagination-aware data extraction, and 429 backoff.

## 0. Resolve instance + credentials

Ask the user (or read env) for:
- `<HOST>` — base URL of the CTFd instance.
- Auth: **API token** (recommended) OR username/password.

**API token is strongly preferred.** Get one via the UI
(*Settings → Access Tokens → Generate*) or via the API itself (see §tokens).
With a token you send two headers on every request and **CSRF is fully bypassed**:

```
Authorization: Token <ctfd_...value>
Content-Type: application/json
```

> Critical CTFd quirk: the token is recognized ONLY when the request is JSON
> (`Content-Type: application/json`). Without it the `Authorization` header is
> silently ignored. The bundled client sets both headers for you.

If only username/password is available: CTFd has **no `/api/v1/login`**. Login
is a form `POST /login` (fields `name`, `password`; `name` accepts username OR
email) that returns a `302` and a session cookie — no JSON, no token. Then a
CSRF nonce must be carried as the `CSRF-Token: <nonce>` header on every
state-changing request. Use `CTfdClient.from_userpass(...)` which does all of
this. Token auth is simpler — prefer it whenever possible.

## 1. Response envelope

```
success:   {"success": true, "data": <obj|list>, "meta": {"pagination": {...}}?}
error:     {"success": false, "errors": {"<field>": ["<msg>"]}}
```

The bundled client unwraps `data` automatically and raises `CTfdError` on
`success: false`. Paginated lists return up to ~50 items by default
(pass-through query params are supported, e.g. `list_challenges(category="Web")`).

## 2. Core PLAYER endpoints (no admin rights needed)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/challenges` | List challenges (id, name, category, value, solves, solved_by_me) |
| GET | `/api/v1/challenges/<id>` | Full challenge: description, connection_info, files (signed URLs), tags, hints |
| POST | `/api/v1/challenges/attempt` | **SUBMIT A FLAG** — body `{"challenge_id": N, "submission": "flag"}` |
| GET | `/api/v1/challenges/<id>/solves` | Who solved it (respects score freeze) |
| GET | `/api/v1/hints/<id>` | View hint (content only if unlocked) |
| POST | `/api/v1/unlocks` | Unlock hint/solution — body `{"type":"hints","target":<hint_id>}` (costs points) |
| GET | `/api/v1/scoreboard` | Full standings |
| GET | `/api/v1/scoreboard/top/<n>` | Top-N (1–50), optional `?bracket_id=` |
| GET | `/api/v1/users/me` | Current user + own place/score |
| GET | `/api/v1/users/me/solves` | Own solves |
| GET | `/api/v1/teams/me` | Own team (teams mode) |
| GET | `/api/v1/teams/me/solves` | Team solves |
| GET | `/api/v1/notifications?since_id=<id>` | Poll announcements |
| POST | `/api/v1/tokens` | Generate API token `{"expiration":"YYYY-MM-DD","description":"..."}` (shown once) |
| GET | `/api/v1/tokens` | List own tokens (value redacted) |
| DELETE | `/api/v1/tokens/<id>` | Revoke token |

## 3. Flag submission — handle EVERY response variant

`POST /api/v1/challenges/attempt` body `{"challenge_id": 5, "submission": "..."}`.
Response `data.status` is one of:

| status | Meaning | Action |
|--------|---------|--------|
| `correct` | Solved, points awarded | stop, report success |
| `incorrect` | Wrong flag; message may include tries-remaining if `max_attempts` set | try next hypothesis |
| `already_solved` | You/team already solved it | **do NOT retry** — idempotent |
| `partial` | Multi-flag challenge, some flags accepted | keep going for remaining flags |
| `ratelimited` | HTTP 429, anti-bruteforce triggered | wait the N seconds in `message`, then retry ONCE |
| `authentication_required` | HTTP 403, token/session expired | re-auth, then retry |
| `paused` | Admin paused the game | wait |

**NEVER hammer `/attempt`.** The client auto-parses the wait seconds from the
429 message and sleeps once before a single retry. Repeated wrong submissions
against a challenge with `max_attempts` + `lockout` behavior can **permanently
lock you out** of that challenge.

## 4. Downloading attached files

`GET /api/v1/challenges/<id>` → `data.files[]` are **already-signed URLs**.
Do NOT construct the signature yourself. Just GET each file URL with the same
session/token → raw bytes. The client's `download_file(url, dest_dir)` does this
and streams to disk (default `/tmp`).

## 5. Unlocking a hint (costs points!)

```
POST /api/v1/unlocks   {"type":"hints","target":<hint_id>}
```
- `400 {"score":["You do not have enough points..."]}` if you can't afford it.
- `400 {"target":["You've already unlocked this target"]}` if already unlocked (idempotent).
- Creates a negative `Award` (−cost) → your score drops by the hint cost.
- After unlocking, re-`GET /api/v1/hints/<id>` to read `content`.

`type:"solutions"` unlocks a challenge's official solution (if exposed).

## 6. Rate limits / 429

- `/challenges/attempt`: ~10 wrong submissions per 60s per (account, challenge).
  On 429 read `data.message` for the wait seconds; sleep, retry once.
- `/login`: 10 POST / 5s per IP (generic limiter → `{"code":429,"message":...}`).
- **No standard `X-RateLimit-*` headers.** Trust the JSON body.
- The client handles the attempt 429 automatically.

## 7. Recommended workflow (using the bundled client)

```python
import sys; sys.path.insert(0, "scripts")   # or copy ctfd_client.py next to your script
from ctfd_client import CTfdClient

ctfd = CTfdClient("https://ctf.example.com", token="ctfd_...")   # or from_env() / from_userpass(...)
chals = ctfd.list_challenges()                                   # cached list of all challenges
detail = ctfd.get_challenge(42)                                  # description, files, hints
for f in detail.get("files", []):
    ctfd.download_file(f, dest_dir="/tmp/chal42")                # signed URLs already valid
# ... solve the challenge, obtain the flag ...
verdict = ctfd.attempt(42, "BugCTF{example_flag}")               # {"status":"correct","message":"..."}
```

Or via CLI straight from Bash:
```
python scripts/ctfd_client.py challenges   --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py submit 42 "BugCTF{...}" --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py me --host "$CTFD_HOST" --token "$CTFD_TOKEN"
```

## 8. What is NOT covered (admin only — out of scope for a player)

Creating/editing/deleting challenges, flags, hints, files, tags, submissions,
awards, pages, configs, statistics, exports — all require `@admins_only`. This
skill intentionally exposes only player actions.
