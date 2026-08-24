# CTFd Skill

Навык для [opencode](https://opencode.ai): агент работает с любым CTF на
движке [CTFd](https://ctfd.io) через его REST API — как обычный игрок.
Список задач, условия, файлы, подача флагов, подсказки, рейтинг, анонсы.

## Что умеет

- **Флаги**: сабмит с обработкой всех ответов CTFd (`correct`, `incorrect`,
  `already_solved`, `partial`, `ratelimited`…), авто-backoff на 429,
  предупреждение «этот флаг уже отправлялся и был неверен» до траты попытки.
- **Профили событий**: один раз сохранить host+токен в
  `~/.config/ctfd/profiles.json` — дальше просто `-p имя-события`.
- **Новое и приоритеты**: детект новых задач и анонсов организаторов;
  оффлайн-режим `challenges --offline --unsolved --sort value` без обращения
  к серверу.
- **Хинты**: перед покупкой показывает цену и счёт; покупка только с
  `--yes`, текст хинта — сразу в ответе.
- **Рейтинг**: `scoreboard --diff` — своя позиция ±, кто кого обогнал,
  вместо полных дампов.
- **Воркспейс под каждую задачу** (`~/Downloads/ctf/<событие>/<категория>/<слаг>/`):
  файлы, solve-скрипты (готовый `solve.py` под категорию задачи) и журнал
  `NOTES.md` переживают ребуты.
- **Файлы**: скачивание по подписанным URL с sha256-чексуммой.
- **Cloudflare**: если хост за CF — весь трафик прозрачно уходит через
  вкладку Chromium (CDP-мост), все фичи продолжают работать.
- **Понятные ошибки**: `401 — токен протух`, `403 — задача закрыта` и т.п.;
  автоповтор GET на сетевых сбоях/5xx (записи — никогда).
- Async-клиент (`httpx`) для параллельного triage больших CTF.

## Установка

```bash
git clone https://github.com/Chumikov/CTFd-Skill ~/.config/opencode/skills/ctfd-api
```

Или в конкретный проект: `.opencode/skills/ctfd-api`. Название папки должно
быть именно `ctfd-api`.

Зависимости: `pip install requests`. Опционально: `markdownify` (красивее
условия задач), `httpx` (async), `websocket-client` (CDP-мост).

## Настройка

Токен: в веб-интерфейсе CTFd → **Settings → Access Tokens → Generate**.

Профиль (рекомендуется, файл создаётся с правами 0600):

```bash
mkdir -p ~/.config/ctfd
cat > ~/.config/ctfd/profiles.json <<'EOF'
{
  "last": "demo",
  "profiles": {
    "demo": {"host": "https://ctf.example.com", "token": "ctfd_..."}
  }
}
EOF
```

Или просто переменные окружения: `CTFD_HOST` и `CTFD_TOKEN`.

## Использование

Через агента — естественным языком («покажи задачи», «подай флаг в 42»).
Напрямую:

```bash
python scripts/ctfd_client.py -p demo challenges        # список задач
python scripts/ctfd_client.py -p demo submit 42 'flag{...}'   # подать флаг
python scripts/ctfd_client.py challenges --new          # новые дропы
python scripts/ctfd_client.py challenges --offline --unsolved --sort value
python scripts/ctfd_client.py scoreboard --diff         # динамика рейтинга
python scripts/ctfd_client.py unlock-hint 7             # цена хинта
python scripts/ctfd_client.py unlock-hint 7 --yes       # купить хинт
python scripts/ctfd_client.py download-challenge 42     # воркспейс + файлы
python scripts/ctfd_client.py status                    # сверка с сервером
```

Из Python:

```python
import sys; sys.path.insert(0, "scripts")
from ctfd_client import CTfdClient

c = CTfdClient.from_env()                    # или CTfdClient(host, token=...)
detail = c.get_challenge(42)
ws = c.init_challenge_workspace(detail)      # ~/Downloads/ctf/... (не /tmp)
for f in detail["files"]:
    c.download_file(f)                       # → ws/attachments/
verdict = c.attempt(42, "flag{example}")
if verdict.correct:
    print("решено:", verdict.message)
```

Полная документация по API и рабочим процессам — в [SKILL.md](SKILL.md).

## Безопасность

- Не перебирайте флаги через `submit`: антибрутфорс CTFd + `max_attempts`
  могут закрыть задачу навсегда. Клиент предупредит о повторе неверного
  флага, но решение всегда за вами.
- Токен = полный доступ к аккаунту. Не коммитьте его; в CLI он виден в
  истории оболочки — предпочтительнее профиль или `CTFD_TOKEN`.
- `unlock-hint --yes` списывает реальные баллы.

## Тесты

```bash
pip install -r requirements-dev.txt
pytest tests/          # ~190 тестов, без HTTP (всё замокано)
```

## Лицензия

[MIT](LICENSE)
