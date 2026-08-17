# CTFd Skill

Навык (skill) для [opencode](https://opencode.ai), позволяющий агенту работать с
API любой CTF-платформы на движке **[CTFd](https://ctfd.io)** через единый
REST-интерфейс (`/api/v1`). Помогает участвовать в CTF: список задач, чтение
условий, скачивание файлов, подача флагов, разблокировка подсказок, просмотр
рейтинга и анонсов.

Скилл ориентирован на **игрока** (player): покрывает действия, доступные
обычному аккаунту, без администраторских эндпоинтов.

## Возможности

- Список и детальный просмотр челленджей (категории, баллы, число солвов, «решил ли я»)
- **Browser bridge (Cloudflare) — CDP-транспорт**: если инстанс за CF и
  прямой HTTP получает `403 Just a moment...`, клиент детектит
  challenge-страницу (`CloudflareBlocked`) и гоняет ВСЕ вызовы через
  реальную вкладку Chromium (`fetch` в контексте страницы, файлы — base64).
  Режимы `CTFD_BRIDGE`: `auto` (по умолчанию — прозрачно переключается при
  первом CF-ответе), `cdp` (только мост), `off`. Все фичи (autolog, 429,
  `.seen.json`, нотификации) работают и через мост
- **Скор-верификация после `correct`**: `attempt()` дёшево сверяет, что
  солв реально виден в `/users/me/solves` (истина в последней инстанции),
  и кладёт результат в `verdict["scored"]` — при заморозке скоринга
  `/challenges` врёт, и расхождение ловится сразу (`verify_score=False`
  отключает)
- **CLI: `--host`/`--token` принимаются и ДО, и ПОСЛЕ подкоманды** —
  `ctfd_client.py submit 42 'flag' --host ...` работает
- **CLI `events`**: список деревьев событий в базе воркспейсов — детектор
  «расползания» (параллельные `event-2026` vs `2026-event` от субагентов)
- **Канон для субагентов** (SKILL.md §7b): субагент, найдя флаг, сабмитит
  его сам немедленно одной CLI-командой и возвращает вердикт; ему
  передаются id/`CTFD_EVENT`/путь воркспейса; запретены side-effect вызовы
  и трата баллов
- **Подача флагов** с обработкой всех вариантов ответа
  (`correct` / `incorrect` / `already_solved` / `partial` / `ratelimited` / …)
  — возвращается `SubmitResult` (dict-совместимый объект с типизированными
  property `verdict.correct`, `verdict.already_solved`, `verdict.ratelimited`)
- **Авто-фиксация солвов**: `attempt()` сам дописывает результат в `NOTES.md`
  задачи (все вердикты, не только `correct`) и при `correct` ставит
  `solved: true` в `challenge.json` — счётчик решённых больше не
  разъезжается с сервером
- **Обнаружение новых задач и анонсов**: `list_challenges()` автоматически
  diff'ит новые задачи против снапшота `.seen.json` и сливает подсказки/
  уточнения из `/notifications` (с тегом `hint`/`clarification`/`new`/...)
  в stderr — организаторы публикуют задачи и постят подсказки по ходу ивента
- **Сверка с сервером**: CLI `status` (ловит дрейф солвов, оффлайн без токена)
  и `sync` (дозаполняет `challenge.json`/`description.md` из `my_solves`;
  `sync --all` — скаффолит вообще все задачи без воркспейса)
- Автоматический backoff при `429` (антибрутфорс CTFd) — клиент сам читает
  число секунд ожидания из ответа и делает один повтор
- **CSRF retry при 403**: при session-cookie авторизации клиент автоматически
  рефетчит свежий nonce и ретраит POST один раз (для token-авторизации не нужно)
- Скачивание приложенных файлов по уже подписанным URL
- **HTML → Markdown для `description.md`**: условие задачи приводится к
  читаемому Markdown (soft-dep на [`markdownify`](https://pypi.org/project/markdownify/),
  при отсутствии — встроенный regex-fallback)
- **Auto-extract `connection_info`**: если CTFd не заполнил поле явно,
  клиент извлекает `nc host port` / `ncat` / `ssh user@host` / URL из описания
  и сохраняет в `challenge.json`
- **Auto-unlock бесплатных хинтов** (`auto_unlock_free_hints=True` в
  `init_challenge_workspace`): хинты с `cost<=0` открываются автоматически,
  чтобы дать агенту максимум контекста без траты баллов (идея из
  [ctf-agent/pull_challenges.py](https://github.com/verialabs/ctf-agent)).
  Платные хинты НЕ трогаются.
- **Персистентный воркспейс** под каждую задачу (`~/Downloads/ctf/<event>/<category>/<slug>/`) — файлы, скрипты и журнал переживают ребуты (не `/tmp`)
- **Шаблоны `solve.py` по категориям**: при `init_challenge_workspace` в `scripts/`
  автоматически кладётся готовый скелет: pwn → `pwntools` + `remote(host,port)`,
  web → `requests`, crypto → `pycryptodome`/`gmpy2` подсказки, rev → `angr`/`r2`,
  forensics → `binwalk`/`volatility`, misc → универсальный stub. Шаблон
  генерируется один раз (idempotent — пользовательские правки не перезаписываются).
  Переопределить свои шаблоны можно в `~/.config/ctfd/templates/<category>.tmpl`.
- **`list_challenges(detail="full")`**: по умолчанию один запрос на список задач
  (быстро, даже на CTF со 100+ задачами). Опционально `detail="full"` параллельно
  догружает описания/файлы/хинты для каждой задачи через пул потоков — удобно
  для triage по всем условиям сразу (как `fetch_all_challenges` у ctf-agent).
- **Async-клиент** (`AsyncCTfdClient` на `httpx.AsyncClient`): зеркалит sync-API,
  но все HTTP-методы — coroutines. `list_challenges(detail="full")` использует
  `asyncio.gather` для максимально быстрого triage, `download_file` идёт
  параллельно. Workspace-методы делегируют в sync-impl через `asyncio.to_thread`.
  `httpx` — опциональная зависимость (lazy-import).
- **Журнал хода решения** `NOTES.md` — автодополнение датированных записей (гипотеза/попытка/результат)
- **Подсказка агенту предпочитать `hexstrike_*` MCP-тулы** для offsec-задач (переживает компактизацию контекста)
- Разблокировка подсказок и официальных решений (с учётом стоимости в баллах)
- Рейтинг, топ-N, свой профиль, профиль команды
- Поллинг анонсов организаторов (`since_id`)
- Управление собственными API-токенами (создание / список / отзыв)
- Авторизация **API-токеном** (рекомендуется) либо логин/паролем
- Работает с **любым** инстансом CTFd — не привязан к конкретной площадке

## Требования

- [opencode](https://opencode.ai) ≥ 2.x
- Python 3.8+
- [`requests`](https://pypi.org/project/requests/) — `pip install requests`
- [`markdownify`](https://pypi.org/project/markdownify/) — **опционально**;
  при установке HTML-описания задач конвертируются в Markdown точнее.
  Без неё используется встроенный regex-fallback.
- [`httpx`](https://pypi.org/project/httpx/) — **опционально**; только если
  используется `AsyncCTfdClient` для параллельных операций.
- [`websocket-client`](https://pypi.org/project/websocket-client/) —
  **опционально**; только для browser bridge (CDP-транспорт за Cloudflare).
  Понадобится Chromium, запущенный с `--remote-debugging-port=9222`.

Для разработки/тестов: `pip install -r requirements-dev.txt` (pytest, httpx, markdownify).

## Установка

Имя скилла в opencode — `ctfd-api`. Локальный целевой каталог **должен**
называться `ctfd-api` (совпадает с полем `name` в `SKILL.md`).

### Способ 1 — глобально (рекомендуется)

Скилл будет доступен во всех проектах текущего пользователя.

```bash
git clone https://github.com/Chumikov/CTFd-Skill ~/.config/opencode/skills/ctfd-api
```

### Способ 2 — в конкретный проект

Положите скилл рядом с репозиторием CTF, к которому он относится.

```bash
git clone https://github.com/Chumikov/CTFd-Skill .opencode/skills/ctfd-api
```

### Способ 3 — через `opencode.jsonc`

Если скилл лежит вне стандартных каталогов, укажите путь явно:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "skills": {
    "paths": ["/абсолютный/путь/к/ctfd-api"]
  }
}
```

### Способ 4 — вручную (без git)

Скачайте [архив репозитория](https://github.com/Chumikov/CTFd-Skill/archive/refs/heads/main.zip),
распакуйте его в `~/.config/opencode/skills/ctfd-api/`.

### Проверка

После установки запустите opencode — скилл `ctfd-api` появится в списке
доступных. Агент подгрузит его по запросу (например, при фразе
«подай флаг в задаче 42»).

## Настройка

Скилл ожидает два значения — хост инстанса и API-токен. Удобно вынести их в
переменные окружения:

```bash
export CTFD_HOST="https://ctf.example.com"
export CTFD_TOKEN="ctfd_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Токен создаётся в веб-интерфейсе: **Settings → Access Tokens → Generate**
(значение показывается один раз). Альтернативно — сгенерировать самим клиентом
(см. ниже).

## Использование

### Через агента opencode

Просто попросите естественным языком, например:

- «покажи список задач на ctf.example.com»
- «открой задачу 42 и скачай её файлы»
- «подай флаг `flag{demo}` в задаче 42»

Агент сам загрузит скилл и вызовет нужный метод.

### Напрямую из Python

```python
import sys
sys.path.insert(0, "scripts")
from ctfd_client import CTfdClient

c = CTfdClient.from_env()                       # читает CTFD_HOST / CTFD_TOKEN
print(c.list_challenges())                      # список задач (1 запрос, быстро)
# detail="full" — параллельно догружает описания/файлы/хинты (пул потоков):
chals_full = c.list_challenges(detail="full", max_workers=8)
detail = c.get_challenge(42)                    # условие, файлы, хинты
ws = c.init_challenge_workspace(detail)         # персистентный воркспейс (НЕ /tmp)
                                                # + scripts/solve.py готовый под категорию
# auto_unlock_free_hints=True — открыть хинты с cost<=0 без траты баллов:
# ws = c.init_challenge_workspace(detail, auto_unlock_free_hints=True)
for f in detail["files"]:
    c.download_file(f)                          # → ws/attachments/ (dest_dir=None по умолчанию)
c.log_attempt(42, "Начало решения", "hypothesis")  # запись в ws/NOTES.md
# ... решение (для offsec — prefer hexstrike_* тулам, см. SKILL.md §7a) ...
verdict = c.attempt(42, "flag{example}")        # SubmitResult (dict-compatible)
if verdict.correct:                             # property-access
    print("решено:", verdict.message)
print(verdict["status"])                        # backward-compat: dict-access
# attempt() сам логирует вердикт в NOTES.md и ставит solved:true в challenge.json
# (см. SKILL.md §3a). Ручной log_attempt(..., "solved") больше не нужен.
```

Async-вариант (`pip install httpx`):

```python
import asyncio
from ctfd_client import AsyncCTfdClient

async def main():
    async with AsyncCTfdClient.from_env() as c:
        # detail="full" использует asyncio.gather — быстро на больших CTF
        chals = await c.list_challenges(detail="full")
        await asyncio.gather(*[c.download_file(f) for f in chals[0]["files"]])
        verdict = await c.attempt(42, "flag{example}")
        print(verdict.correct, verdict.message)

asyncio.run(main())
```

Авторизация по паролю (если нет токена):

```python
c = CTfdClient.from_userpass("https://ctf.example.com", "username", "password")
```

### Через CLI

Глобальные `--host`/`--token` принимаются как до, так и после подкоманды.

```bash
python scripts/ctfd_client.py challenges                 --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py challenge 42               --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py submit 42 'flag{...}'        --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py me                         --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py scoreboard                 --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py top 10                     --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py hint 7                     --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py unlock-hint 7              --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py unlock-solution 7          --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py notifications --since-id 5 --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py gen-token --description "automation" --expiration 2026-12-31
python scripts/ctfd_client.py tokens
python scripts/ctfd_client.py revoke-token 3
python scripts/ctfd_client.py status          # сводка по воркспейсам + сверка с my_solves (оффлайн без --token)
python scripts/ctfd_client.py sync --dry-run  # превью дозаполнения из сервера
python scripts/ctfd_client.py sync            # создать/обновить challenge.json для серверных солвов
python scripts/ctfd_client.py sync --all      # создать scaffold для всех задач без воркспейса (не только решённых)
python scripts/ctfd_client.py download-challenge 42   # init ws + скачать все файлы задачи в attachments/
python scripts/ctfd_client.py events         # все деревья событий в ~/Downloads/ctf (детектор расползания)
```

### Хост за Cloudflare (browser bridge)

```bash
# 1. Браузер с remote debugging + вкладка с пройденным CF-челленджем и логином:
chromium --remote-debugging-port=9222 &
# 2. Клиент: мост с первого запроса...
CTFD_BRIDGE=cdp python scripts/ctfd_client.py challenges --host "$CTFD_HOST" --token "$CTFD_TOKEN"
#    ...или ничего не делать: режим auto (по умолчанию) переключится сам
#    при первом же CF-ответе.
```

Демо end-to-end сценария (только чтение по умолчанию):

```bash
python examples/solve_flow.py
python examples/solve_flow.py --show-id 42
python examples/solve_flow.py --submit-id 42 --flag 'flag{...}'
```

> `python examples/solve_flow.py --submit-id 42 --flag '...'` — подача флага
> выполняется только при явном указании `--submit-id` и `--flag`.

## Персистентный воркспейс

Чтобы файлы задач, solve-скрипты и журнал решения **не терялись при перезагрузке**
(однажды весь CTF-уикенд ушел в `/tmp`, очищенный ребутами), скилл создаёт под
каждую задачу персистентную структуру в `~/Downloads/ctf/`:

```
~/Downloads/ctf/<event>/<category>/<slug>/
├── challenge.json      # метаданные CTFd (id, name, host, solved) — back-mapping
├── description.md      # условие задачи
├── attachments/        # скачанные файлы (автоматически через download_file)
├── scripts/            # самописные solve-скрипты/эксплойты — запускать отсюда
└── NOTES.md            # журнал хода решения (append через log_attempt)
```

- `<event>` выводится из host инстанса (`ctf.example.com` → `example-2026`,
  `<label>-<текущий год>`); override через env `CTFD_EVENT` (обязательно для
  CTF у границы года или с другим брендингом).
- `challenge.json` содержит JSON (в старых версиях назывался `challenge.yaml` —
  читается с fallback и мигрируется при следующем `init_challenge_workspace`).
  Снимок события `~/Downloads/ctf/<event>/.seen.json` (id + курсор анонсов)
  лежит на уровень выше, рядом с папками категорий.
- `init_challenge_workspace(detail)` создаёт scaffold + `description.md` + заголовок `NOTES.md`
  (idempotent: повторный вызов сохраняет `solved`/`solved_at`/`created_at`).
  Опциональный параметр `auto_unlock_free_hints=True` открывает бесплатные
  хинты (`cost<=0`) сразу — максимум контекста агенту без траты баллов.
  Поле `connection_info` в `challenge.json` заполняется серверным значением,
  **либо** извлекается из описания задачи (regex по `nc`/`ncat`/`ssh`/URL).
  Само описание конвертируется из HTML в Markdown (через `markdownify` если
  установлен, иначе встроенным regex-fallback).
- `download_file(f)` без `dest_dir` складывает файлы в `attachments/`. Без
  активного воркспейса ругнётся в stderr и сохранит в `/tmp` (это нежелательный
  сценарий, не норма). При коллизии базового имени предупреждает о перезаписи.
- `log_attempt(challenge_id, entry, status)` дописывает датированную запись в
  `NOTES.md` (`status`: `hypothesis` / `tried` / `solved` / `failed`).
- `attempt()` возвращает `SubmitResult` (dict-совместимый): `verdict["status"]`
  для старого кода, `verdict.correct` / `.already_solved` / `.ratelimited` /
  `.message` — для нового. Автоматически логирует вердикт (все статусы) и
  при `correct`/`already_solved` ставит `solved: true` в `challenge.json`.
- `list_challenges()` **автоматически** детектит новые задачи (diff против
  `.seen.json`) и новые анонсы из `/notifications` (с тегом классификации).
  Состояние события хранится в `~/Downloads/ctf/<event>/.seen.json`. Это getter
  с side-effects (пишет `.seen.json` + второй HTTP к `/notifications`); первый
  опрос печатает newest 50 исторических анонсов. Для тихого обзора:
  `list_challenges(update_seen=False, poll_notifications=False)`. Не вызывайте
  с фильтром (`category=...`) до первого полного вызова — baseline останется
  неполным.

Эпемерный scratch (разовые `curl`-пробы, распакованные бинарники) по-прежнему
идёт в `/tmp`. Самописные скрипты — в `scripts/` воркспейса.

> **Шаблоны `solve.py` по категориям**: при `init_challenge_workspace` под
> задачу автоматически создаётся `scripts/solve.py` с готовым скелетом под
> её категорию (pwn → `pwntools`, web → `requests`, crypto → `pycryptodome`
> и т.д.). Шаблон создаётся один раз — пользовательские правки не
> перезаписываются. Переопределить: положить свой файл в
> `~/.config/ctfd/templates/<category>.tmpl` (или `.py`).

> **HexStrike-интеграция**: в `SKILL.md` (§7a) агенту предписано prefer'ить
> `hexstrike_*` MCP-тулы для offsec-задач — инструкция живёт в скилле и не
> вымывается компактизацией контекста.

## Безопасность

- **Не спамьте `submit`**. У CTFd есть антибрутфорс (~10 неверных сабмитов в
  минуту на пару аккаунт+задача → `429 ratelimited`) и per-challenge
  `max_attempts` с режимом `lockout` — можно **навсегда** закрыть себе задачу
  перебором. Клиент корректно отрабатывает `429`, но лишние неверные попытки
  всё равно пишутся в историю.
- Токен — это полноценный доступ к вашему аккаунту. Не коммитьте его и не
  выкладывайте в чаты.
- В CLI `--token <значение>` виден в списке процессов (`ps`) и истории оболочки.
  Предпочитайте переменную окружения `CTFD_TOKEN` (или `CTFD_HOST`/`CTFD_TOKEN`
  в `~/.bashrc`/`.zshrc` под `setopt HIST_IGNORE_SPACE` / `ignorespace`).
- `unlock-hint` списывает реальные баллы с вашего/командного счёта.

## Структура проекта

```
CTFd-Skill/
├── SKILL.md                 # тело навыка для opencode
├── scripts/
│   └── ctfd_client.py       # Python-клиент + CLI (sync + async)
├── examples/
│   └── solve_flow.py        # демо: список → скачать → флаг
├── tests/                   # pytest smoke-тесты (хелперы + воркспейс)
│   ├── test_smoke.py        #   чистые хелперы без HTTP
│   ├── test_workspace.py    #   init workspace, шаблоны, attempt с моками
│   └── test_bridge.py       #   CDP-мост, Cloudflare-детект, scored, events
├── requirements.txt         # runtime: requests
├── requirements-dev.txt     # dev: pytest, httpx, markdownify, websocket-client
├── README.md                # этот файл
├── LICENSE                  # MIT
└── .gitignore
```

## Разработка и тесты

```bash
pip install -r requirements-dev.txt
pytest tests/ -v             # 146 smoke-тестов (хелперы + воркспейс + мост, без HTTP)
pytest tests/test_smoke.py   # только чистые хелперы
pytest tests/test_bridge.py  # мост/CF/scored/events
```

Тесты не делают реальных HTTP-запросов: HTTP-слой мокается через
`monkeypatch`, файловые операции — через `tmp_path`. End-to-end smoke
демо против живого CTFd: `python examples/solve_flow.py`.

## Совместимость

CTFd 3.x, REST API v1. Логика клиента выведена из исходников CTFd (`master`),
без обращения к сторонним неофициальным эндпоинтам.

## Лицензия

[MIT](LICENSE).
