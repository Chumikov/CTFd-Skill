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
- **Подача флагов** с обработкой всех вариантов ответа
  (`correct` / `incorrect` / `already_solved` / `partial` / `ratelimited` / …)
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
- Скачивание приложенных файлов по уже подписанным URL
- **Персистентный воркспейс** под каждую задачу (`~/Downloads/ctf/<event>/<category>/<slug>/`) — файлы, скрипты и журнал переживают ребуты (не `/tmp`)
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
print(c.list_challenges())                      # список задач
detail = c.get_challenge(42)                    # условие, файлы, хинты
ws = c.init_challenge_workspace(detail)         # персистентный воркспейс (НЕ /tmp)
for f in detail["files"]:
    c.download_file(f)                          # → ws/attachments/ (dest_dir=None по умолчанию)
c.log_attempt(42, "Начало решения", "hypothesis")  # запись в ws/NOTES.md
# ... решение (для offsec — prefer hexstrike_* тулам, см. SKILL.md §7a) ...
verdict = c.attempt(42, "flag{example}")        # {"status": "correct", ...}
# attempt() сам логирует вердикт в NOTES.md и ставит solved:true в challenge.json
# (см. SKILL.md §3a). Ручной log_attempt(..., "solved") больше не нужен.
```

Авторизация по паролю (если нет токена):

```python
c = CTfdClient.from_userpass("https://ctf.example.com", "username", "password")
```

### Через CLI

```bash
python scripts/ctfd_client.py challenges                 --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py challenge 42               --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py submit 42 'flag{...}'        --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py me                         --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py scoreboard                 --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py top 10                     --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py hint 7                     --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py unlock-hint 7              --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py notifications --since-id 5 --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py gen-token --description "automation" --expiration 2026-12-31
python scripts/ctfd_client.py tokens
python scripts/ctfd_client.py revoke-token 3
python scripts/ctfd_client.py status          # сводка по воркспейсам + сверка с my_solves (оффлайн без --token)
python scripts/ctfd_client.py sync --dry-run  # превью дозаполнения из сервера
python scripts/ctfd_client.py sync            # создать/обновить challenge.json для серверных солвов
python scripts/ctfd_client.py sync --all      # создать scaffold для всех задач без воркспейса (не только решённых)
python scripts/ctfd_client.py download-challenge 42   # init ws + скачать все файлы задачи в attachments/
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
- `download_file(f)` без `dest_dir` складывает файлы в `attachments/`. Без
  активного воркспейса ругнётся в stderr и сохранит в `/tmp` (это нежелательный
  сценарий, не норма). При коллизии базового имени предупреждает о перезаписи.
- `log_attempt(challenge_id, entry, status)` дописывает датированную запись в
  `NOTES.md` (`status`: `hypothesis` / `tried` / `solved` / `failed`).
- `attempt()` **автоматически** логирует вердикт (все статусы, не только
  `correct`) и при `correct`/`already_solved` ставит `solved: true` в
  `challenge.json` — ручной `log_attempt` для самого флага не нужен, только
  для промежуточных шагов.
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
│   └── ctfd_client.py       # Python-клиент + CLI
├── examples/
│   └── solve_flow.py        # демо: список → скачать → флаг
├── README.md                # этот файл
├── LICENSE                  # MIT
└── .gitignore
```

## Совместимость

CTFd 3.x, REST API v1. Логика клиента выведена из исходников CTFd (`master`),
без обращения к сторонним неофициальным эндпоинтам.

## Лицензия

[MIT](LICENSE).
