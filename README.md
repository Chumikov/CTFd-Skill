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
- Автоматический backoff при `429` (антибрутфорс CTFd) — клиент сам читает
  число секунд ожидания из ответа и делает один повтор
- Скачивание приложенных файлов по уже подписанным URL
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

- «покажи список задач на ctf.bug-makers.ru»
- «открой задачу 42 и скачай её файлы»
- «подай флаг `BugCTF{demo}` в задаче 42»

Агент сам загрузит скилл и вызовет нужный метод.

### Напрямую из Python

```python
import sys
sys.path.insert(0, "scripts")
from ctfd_client import CTfdClient

c = CTfdClient.from_env()                       # читает CTFD_HOST / CTFD_TOKEN
print(c.list_challenges())                      # список задач
detail = c.get_challenge(42)                    # условие, файлы, хинты
for f in detail["files"]:
    c.download_file(f, dest_dir="/tmp/chal42")  # файлы уже с подписью
verdict = c.attempt(42, "BugCTF{example}")      # {"status": "correct", ...}
```

Авторизация по паролю (если нет токена):

```python
c = CTfdClient.from_userpass("https://ctf.example.com", "username", "password")
```

### Через CLI

```bash
python scripts/ctfd_client.py challenges                 --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py challenge 42               --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py submit 42 'BugCTF{...}'    --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py me                         --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py scoreboard                 --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py top 10                     --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py hint 7                     --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py unlock-hint 7              --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py notifications --since-id 5 --host "$CTFD_HOST" --token "$CTFD_TOKEN"
python scripts/ctfd_client.py gen-token --description "automation" --expiration 2026-12-31
python scripts/ctfd_client.py tokens
python scripts/ctfd_client.py revoke-token 3
```

Демо end-to-end сценария (только чтение по умолчанию):

```bash
python examples/solve_flow.py
python examples/solve_flow.py --show-id 42
python examples/solve_flow.py --submit-id 42 --flag 'BugCTF{...}'
```

> `python examples/solve_flow.py --submit-id 42 --flag '...'` — подача флага
> выполняется только при явном указании `--submit-id` и `--flag`.

## Безопасность

- **Не спамьте `submit`**. У CTFd есть антибрутфорс (~10 неверных сабмитов в
  минуту на пару аккаунт+задача → `429 ratelimited`) и per-challenge
  `max_attempts` с режимом `lockout` — можно **навсегда** закрыть себе задачу
  перебором. Клиент корректно отрабатывает `429`, но лишние неверные попытки
  всё равно пишутся в историю.
- Токен — это полноценный доступ к вашему аккаунту. Не коммитьте его и не
  выкладывайте в чаты.
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
