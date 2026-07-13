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

## 0a. Обязательный чек-лист воркспейса (НЕ ПРОПУСКАТЬ)

Регрессия на BroncoCTF 2026: скилл был установлен, но `init_challenge_workspace`
/ `log_attempt` ни разу не вызвались за весь уикенд — файлы сливались через
сырой `curl` в ad-hoc папки по имени категории, единый общий `NOTES.md` вёл
счётчик солвов с дрейфом (22 локально vs 25 на сервере), solve-скрипты
терялись. Этот чек-лист — обязательный порядок действий на каждую задачу.

**На каждое касание задачи ОБЯЗАТЕЛЬНО:**

1. **Первое касание** — `ws = ctfd.init_challenge_workspace(detail)` ДО любого
   скачивания/анализа. Никаких `curl`/`wget` в папки по имени категории.
2. **Каждый файл задачи** — через `ctfd.download_file(f)` (положит в
   `ws/attachments/`). `download_file` без активного воркспейса ругнётся в
   stderr и сохранит в `/tmp` — это футган, не норма.
3. **Каждый solve-скрипт / эксплойт** — писать в `ws/scripts/` и запускать
   оттуда (`cd <ws>/scripts`). Эфемерный scratch (распакованные бинарники под
   RE, разовые `curl`-пробы) — в `/tmp`, но авторский код — в `scripts/`.
4. **Каждая гипотеза / запуск тулзы / попытка** —
   `ctfd.log_attempt(id, text, status)`. Флаг-солв логируется автоматически
   (см. §3a) — на это не полагаться для промежуточных шагов.
5. **Перед взятием новой задачи** — `ctfd.list_challenges()`: единая точка
   «что нового» — автоматически diff'ит новые задачи против снапшота
   `~/Downloads/ctf/<event>/.seen.json` и сливает новые анонсы из
   `/notifications` (подсказки/уточнения организаторов) с тегом классификации.
   Организаторы публикуют задачи и постят подсказки по ходу ивента.
6. **Возобновление сессии** (новый запуск / после компактизации контекста) —
   перечитать `ws/NOTES.md` активной задачи; periodically сверяться через
   `python scripts/ctfd_client.py status` (ловит дрейф солвов vs сервер).

**АНТИПАТТЕРНЫ** (ровно то, что привело к регрессии — НЕ повторять):
- сырой `curl`/`wget` в папки `crypto2`/`forensics3`/... вместо
  `init_challenge_workspace` → `<category>/<slug>/attachments/`;
- общий `NOTES.md` на всё событие вместо per-challenge журнала;
- имена папок по номеру категории (`crypto`, `crypto2`, `crypto3`) вместо
  слага задачи — теряется back-mapping «папка ↔ id ↔ solved»;
- несколько разных задач в одной папке без подкаталогов;
- оставленные пустые/мусорные каталоги от распаковки (755 пустых `w*` и
  т.п.) — такой scratch должен идти в `/tmp` и зачищаться;
- solve-скрипты `solve2.py`, `solve3.py`, `exploit_final.py` без указания,
  какой из них сработал — помечайте каноничный в `NOTES.md`.

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
  (`solved` / `failed` / `tried`);
- on `correct` / `already_solved` flips `solved: true` (+ `solved_at`) in the
  local `challenge.yaml` — this builds the back-mapping that was missing on
  BroncoCTF 2026 (`<ws>/<category>/<slug>/challenge.yaml` ↔ challenge id ↔
  solved status).

This means the flag submission itself is always recorded. **Intermediate
steps** (hypotheses, tool runs, wrong guesses before the final attempt) still
require explicit `ctfd.log_attempt(...)` — only the agent knows those.

To reconcile local tracking with server truth (catches drift like
"22 local vs 25 server"):

```bash
python scripts/ctfd_client.py status          # offline-capable (no token = local-only)
python scripts/ctfd_client.py sync --dry-run  # preview
python scripts/ctfd_client.py sync            # backfill challenge.yaml from my_solves()
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
~/Downloads/ctf/nhnc-2026/web/login_page/
├── challenge.yaml      # CTFd metadata (id, name, host, solved) — back-mapping
├── description.md      # challenge statement from CTFd
├── attachments/        # downloaded challenge files (chal.zip, binaries, images)
├── scripts/            # self-authored solve scripts / exploits — RUN FROM HERE
└── NOTES.md            # running solution journal (append per attempt)
```

**On first touch of any challenge** (before downloading or attempting):
```python
detail = ctfd.get_challenge(42)
ws = ctfd.init_challenge_workspace(detail)        # scaffold + description.md + NOTES header
# downloads now land in ws/attachments/ automatically:
for f in detail.get("files", []):
    ctfd.download_file(f)                         # dest_dir=None → ws/attachments
```

**During solving:**
- Write every solve script / exploit to `ws/"scripts"` and **run it from there**
  (`cd <ws>/scripts && python solve.py`). Large/ephemeral output → `/tmp`.
- After each **intermediate** step (hypothesis, tool run, wrong guess) append:
  ```python
  ctfd.log_attempt(42, "SSRF in ReturnUrl confirmed; /flag readable via 127.0.0.1:5000", status="tried")
  ```
- The final **flag submission** is logged automatically by `attempt()` — no
  manual `log_attempt(..., "solved")` needed; it also flips `solved: true` in
  `challenge.yaml` (see §3a).
- `event` slug auto-derives from host (`nhnc.ic3dt3a.org` → `nhnc-2026`);
  override with `CTFD_EVENT=...` env var.

Only truly ephemeral scratch (one-off `curl` probes, extracted binaries under
RE) goes to `/tmp`. Self-authored work goes to the persistent workspace.

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
# list_challenges() — единая точка «что нового»: diff новых задач против .seen.json
# И слив новых анонсов из /notifications (подсказки/уточнения). См. §0a п.5.
chals = ctfd.list_challenges()
detail = ctfd.get_challenge(42)                                  # description, files, hints
ws = ctfd.init_challenge_workspace(detail)                       # persistent workspace (§4a) — NOT /tmp
for f in detail.get("files", []):
    ctfd.download_file(f)                                        # → ws/attachments/ (signed URLs already valid)
# ... solve the challenge (use hexstrike_* tools — §7a); log EACH step to NOTES.md ...
ctfd.log_attempt(42, "SSRF confirmed, /flag readable via 127.0.0.1:5000", "tried")
verdict = ctfd.attempt(42, "BugCTF{example_flag}")               # {"status":"correct","message":"..."}
# attempt() АВТОМАТИЧЕСКИ пишет солв в NOTES.md и ставит solved:true в challenge.yaml
# (§3a). Ручной log_attempt для самого флага больше не нужен — только для
# промежуточных шагов (см. чек-лист §0a).
```

Reconcile local tracking with server truth anytime (catches drift like
"22 local vs 25 server"):

```bash
python scripts/ctfd_client.py status          # offline-capable; local-only if no token
python scripts/ctfd_client.py sync --dry-run  # preview backfill
python scripts/ctfd_client.py sync            # rebuild challenge.yaml from my_solves()
```

Or via CLI straight from Bash:
```
python scripts/ctfd_client.py challenges   --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py submit 42 "BugCTF{...}" --host "$CTFD_HOST" --token "$CTFD_TOKEN"
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
- You need a one-off `curl`/`nc` probe (then `cd /tmp` first — never in `/home/kali` root), OR
- You're doing local binary RE / forensics (`gdb`/`r2`/`binwalk` — stay in bash, on local files).

**Log each HexStrike run in the challenge journal** via
`ctfd.log_attempt(<id>, "ran hexstrike_port_scan(target, mode=full) → ports 22,80,8080", status="tried")`
so offensive work is traceable in `NOTES.md`.

## 8. What is NOT covered (admin only — out of scope for a player)

Creating/editing/deleting challenges, flags, hints, files, tags, submissions,
awards, pages, configs, statistics, exports — all require `@admins_only`. This
skill intentionally exposes only player actions.
