---
name: ctfd-api
description: Work with any CTFd-platform CTF via its REST API (api/v1) as a player — list and read challenges, download attached files, submit flags (with correct handling of every attempt status incl. ratelimited), unlock hints, view scoreboard, poll notifications, manage own user/team and API tokens. Use whenever the user references a CTF running on CTFd (e.g. ctf.example.com) or says "submit a flag", "list challenges", "show the scoreboard", "download the challenge files" for a CTFd instance. Generic across all CTFd hosts. Player-oriented.
license: MIT
compatibility: opencode
metadata:
  audience: ctf-players
  workflow: ctfd
---

# CTFd API Skill

Generic client for any CTFd (https://ctfd.io) instance REST API v1. All paths
below are relative to the instance base URL `<HOST>`
(e.g. `https://ctf.example.com`). Works the same on every CTFd host.

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

> Critical CTFd quirk (token login requires JSON): the `tokens` before_request
> hook processes `Authorization: Token …` **only when `request.is_json` is
> true** — i.e. the request carries `Content-Type: application/json`. This
> applies to **all methods, including GET requests with no body**. Without it
> the token is silently NOT authenticated (the request proceeds anonymous →
> 403/redirect). Note CSRF is bypassed by the mere presence of the
> `Authorization` header (separate `csrf` hook), but that does you no good
> without the token actually logging you in. The bundled client sets both
> headers on the session for every request, so it always works.

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

## 3a. Auto-tracking of submissions (no manual log needed for the flag itself)

`attempt()` now side-effects automatically (best-effort, **never** blocks the
submission even if logging fails):

- appends a dated entry to the active challenge's `NOTES.md` tagged by verdict
  (`solved` / `failed` / `tried`) — **every** verdict is logged, not just
  `correct`: `incorrect` / `partial` / `ratelimited` attempts land in the
  journal too (tagged `failed` / `tried`), so a brute-force session will
  produce multiple entries — that's intentional, it's the audit trail;
- on `correct` / `already_solved` flips `solved: true` (+ `solved_at`) in the
  local `challenge.json` — this builds the back-mapping required by §4a
  (`<ws>/<category>/<slug>/challenge.json` ↔ challenge id ↔ solved status).
  Legacy `challenge.yaml` is read with fallback and migrated to `.json` on
  the next `init_challenge_workspace`.

This means the flag submission itself is always recorded. **Intermediate
steps** (hypotheses, tool runs, wrong guesses before the final attempt) still
require explicit `ctfd.log_attempt(...)` — only the agent knows those.

To reconcile local tracking with server truth (catches drift like
"22 local vs 25 server"):

```bash
python scripts/ctfd_client.py status          # offline-capable (no token = local-only)
python scripts/ctfd_client.py sync --dry-run  # preview
python scripts/ctfd_client.py sync            # backfill challenge.json from my_solves()
python scripts/ctfd_client.py sync --all      # scaffold ALL challenges (not only solved)
python scripts/ctfd_client.py download-challenge 42   # init ws + download all files
```

## 4. Downloading attached files

`GET /api/v1/challenges/<id>` → `data.files[]` are **already-signed URLs**.
Do NOT construct the signature yourself. Just GET each file URL with the same
session/token → raw bytes. The client's `download_file(url, dest_dir)` does this
and streams to disk (default `/tmp`).

## 4a. Persistent workspace — NEVER lose CTF work to a reboot

Challenge files, solve scripts, and the solution journal MUST live under a
**persistent** workspace that survives reboots — NOT `/tmp` (which the OS clears
on restart). A CTF weekend was once lost entirely because solve scripts in
`/tmp` were wiped by two reboots; this section prevents that.

Default location: `~/Downloads/ctf/<event>/<category>/<slug>/`.

```
~/Downloads/ctf/example-2026/web/login_page/
├── challenge.json      # CTFd metadata (id, name, host, solved) — back-mapping
├── description.md      # challenge statement from CTFd
├── attachments/        # downloaded challenge files (chal.zip, binaries, images)
├── scripts/            # self-authored solve scripts / exploits — RUN FROM HERE
└── NOTES.md            # running solution journal (append per attempt)
```

> `challenge.json` contains JSON (despite older CTFd-Skill versions naming it
> `challenge.yaml`). Legacy `challenge.yaml` is auto-migrated on the next
> `init_challenge_workspace`. The event-level snapshot
> `~/Downloads/ctf/<event>/.seen.json` (new-challenge ids + notification
> cursor) lives one level up, alongside the category folders.

> **Year-derivation caveat:** `<event>` is derived from the host as
> `<first-non-generic-label>-<current-year>` (e.g. `example-2026`). For a CTF
> played near a year boundary, or branded with a different year/season, set
> `CTFD_EVENT=<correct-slug>` explicitly — otherwise the workspace tree lands
> under a misnamed folder.

**Workspace discipline — follow on EVERY challenge:**

1. **First touch** — `ws = ctfd.init_challenge_workspace(detail)` BEFORE any
   download/analysis. No raw `curl`/`wget` into category-named folders.
2. **Every challenge file** — via `ctfd.download_file(f)` (lands in
   `ws/attachments/`). With no active workspace it warns to stderr and falls
   back to `/tmp` — that's a footgun, not the norm.
3. **Every solve script / exploit** — write to `ws/scripts/` and run it from
   there (`cd <ws>/scripts && python solve.py`). Ephemeral scratch (extracted
   binaries under RE, one-off probes) → `/tmp`; authored code → `scripts/`.
4. **Every hypothesis / tool run / attempt** — `ctfd.log_attempt(id, text,
   status)`. The flag solve is logged automatically by `attempt()` (§3a) —
   don't rely on that for intermediate steps.
5. **Before taking a new challenge** — `ctfd.list_challenges()`: the single
   "what's new" entry point — diffs new challenges against the
   `~/Downloads/ctf/<event>/.seen.json` snapshot and drains new
   `/notifications` (organizer hints/clarifications) with a classification
   tag. Challenges and hints land mid-event. Caveats: it's a **getter with
   side-effects** (writes `.seen.json` + a **second HTTP request** to
   `/notifications`); the **first** poll prints the newest 50 historical
   notifications (`c._notifications_first_limit`, default 50); the
   `hint`/`clarification`/`new`/`scoring`/`general` tag is a keyword
   heuristic, not 100%. For a quiet pass use `update_seen=False` and/or
   `poll_notifications=False`. **Do not** call it with a filter
   (`category=...`) before the first unfiltered call — the baseline stays
   incomplete and new-challenge detection is disabled.
6. **Resuming a session** (fresh start / after context compaction) — re-read
   `ws/NOTES.md` of the active challenge; periodically reconcile with
   `python scripts/ctfd_client.py status` (catches solve drift vs server).

```python
detail = ctfd.get_challenge(42)
ws = ctfd.init_challenge_workspace(detail)        # scaffold + description.md + NOTES header
# downloads now land in ws/attachments/ automatically:
for f in detail.get("files", []):
    ctfd.download_file(f)                         # dest_dir=None → ws/attachments
```

`event` slug auto-derives from host (`ctf.example.com` → `example-2026`);
override with `CTFD_EVENT=...` env var (see year-derivation caveat above).

**Anti-patterns** (exactly what caused past regressions — do NOT repeat):
- raw `curl`/`wget` into `crypto2`/`forensics3`/... folders instead of
  `init_challenge_workspace` → `<category>/<slug>/attachments/`;
- a single shared `NOTES.md` for the whole event instead of a per-challenge
  journal;
- folder names by category index (`crypto`, `crypto2`, `crypto3`) instead of
  the challenge slug — loses the folder ↔ id ↔ solved back-mapping;
- several different challenges dumped in one folder with no subdirectories;
- empty/junk directories left from extraction and brute-force loops — such
  scratch belongs in `/tmp` and should be cleaned up;
- `solve2.py`, `solve3.py`, `exploit_final.py` with no marker for the one
  that worked — mark the canonical solver in `NOTES.md`.

Only truly ephemeral scratch (one-off network probes, extracted binaries
under RE) goes to `/tmp`. All authored work (scripts, notes, downloads) goes
to the persistent workspace.

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
# list_challenges() — single "what's new" entry point: diffs new challenges
# vs .seen.json AND drains new /notifications (hints/clarifications). See §4a.
chals = ctfd.list_challenges()
detail = ctfd.get_challenge(42)                                  # description, files, hints
ws = ctfd.init_challenge_workspace(detail)                       # persistent workspace (§4a) — NOT /tmp
for f in detail.get("files", []):
    ctfd.download_file(f)                                        # → ws/attachments/ (signed URLs already valid)
# ... solve the challenge (use hexstrike_* tools — §7a); log EACH step to NOTES.md ...
ctfd.log_attempt(42, "SSRF confirmed, /flag readable via 127.0.0.1:5000", "tried")
verdict = ctfd.attempt(42, "flag{example_flag}")                 # {"status":"correct","message":"..."}
# attempt() AUTOMATICALLY logs the verdict to NOTES.md and, on correct, sets
# solved:true in challenge.json (§3a). ALL verdicts are logged (incl. incorrect).
# Manual log_attempt for the flag itself is no longer needed — only for
# intermediate steps (see checklist §4a).
```

Reconcile local tracking with server truth anytime (catches drift like
"22 local vs 25 server"):

```bash
python scripts/ctfd_client.py status          # offline-capable; local-only if no token
python scripts/ctfd_client.py sync --dry-run  # preview backfill
python scripts/ctfd_client.py sync            # rebuild challenge.json from my_solves()
```

Or via CLI straight from Bash:
```
python scripts/ctfd_client.py challenges   --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py submit 42 "flag{...}" --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py me --host "$CTFD_HOST" --token "$CTFD_TOKEN"
```

## 7a. HexStrike MCP tools — PREFER for offensive security work

During CTF solving, for any pentest/offensive task, **prefer the `hexstrike_*`
MCP tools over raw bash** (raw `nmap`/`sqlmap`/`gobuster`/...). HexStrike wraps
these with structured JSON I/O, caching, and guardrails, and each call registers
in its audit log. This instruction lives in the skill (which reloads on every
CTF session) and so **survives context compaction** — a CTF-weekend regression
(hexcalls dropped from 11% to 3% of tool use after compaction evicted tool
definitions from context) is exactly what this section prevents.

| CTF task | HexStrike tool |
|---|---|
| Port scan / host discovery | `hexstrike_port_scan(mode=fast\|full\|stealth\|udp)` |
| Subdomain enumeration | `hexstrike_subdomain_enum(source=passive\|active\|all)` |
| HTTP probe / tech-detect / crawl | `hexstrike_http_probe(mode=probe\|tech-detect\|crawl)` |
| Directory / vhost / fuzz | `hexstrike_directory_brute(mode=dir\|vhost\|fuzz)` |
| Vuln scan (nuclei/nikto/wpscan) | `hexstrike_web_vuln_scan(profile=generic\|cms\|wordpress)` |
| SQL injection | `hexstrike_sqlmap_scan` |
| Credential brute force | `hexstrike_hydra_attack` |
| Cloud / IaC / container audit | `hexstrike_cloud_audit(scope=aws\|k8s\|docker\|iac)` |
| Target reconnaissance overview | `hexstrike_analyze_target_intelligence` |
| Anything not covered above | `hexstrike_execute_command` (generic escape hatch) |

**Fall back to raw bash only when:**
- HexStrike lacks the specific tool, OR
- You need a one-off network probe (`curl`/`nc`) — run it from `/tmp` (one-off
  probes are fine in `/tmp`; all authored work stays in the persistent
  workspace, see §4a), OR
- You're doing local binary RE / forensics (`gdb`/`r2`/`binwalk` — stay in
  bash, on local files).

**Log each HexStrike run in the challenge journal** via
`ctfd.log_attempt(<id>, "ran hexstrike_port_scan(target, mode=full) → ports 22,80,8080", status="tried")`
so offensive work is traceable in `NOTES.md`.

## 8. What is NOT covered (admin only — out of scope for a player)

Creating/editing/deleting challenges, flags, hints, files, tags, submissions,
awards, pages, configs, statistics, exports — all require `@admins_only`. This
skill intentionally exposes only player actions.
