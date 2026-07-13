#!/usr/bin/env python3
"""ctfd_client.py — легковесный клиент для REST API CTFd (v1).

Работает с любым инстансом CTFd (https://ctfd.io) от лица обычного игрока.
Поддерживает авторизацию API-токеном (рекомендуется; обходит CSRF) и
session-cookie через логин/пароль.

Использование как библиотека::

    from ctfd_client import CTfdClient
    c = CTfdClient("https://ctf.example.com", token="ctfd_...")
    print(c.attempt(42, "flag{...}"))

Использование как CLI::

    python ctfd_client.py challenges --host https://ctf.example.com --token ctfd_...
    python ctfd_client.py submit 42 "flag{...}" --host ... --token ...
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

__all__ = [
    "CTfdClient",
    "CTfdError",
    "RateLimited",
    "CTFD_HOST_ENV",
    "CTFD_TOKEN_ENV",
]

CTFD_HOST_ENV = "CTFD_HOST"
CTFD_TOKEN_ENV = "CTFD_TOKEN"
API_PREFIX = "/api/v1"

_SEC_RE = re.compile(r"(\d+)\s+seconds?", re.IGNORECASE)
_NONCE_PATTERNS = [
    re.compile(r'["\']csrfNonce["\']\s*[:=]\s*["\']([0-9a-f]+)["\']', re.IGNORECASE),
    re.compile(r'name=["\']nonce["\']\s+value=["\']([0-9a-f]+)["\']', re.IGNORECASE),
    re.compile(r'<meta[^>]+csrf[^>]+content=["\']([0-9a-f]+)["\']', re.IGNORECASE),
]

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Маппинг статуса вердикта CTFd -> метка журнала NOTES.md.
_STATUS_LOG: Dict[str, str] = {
    "correct": "solved",
    "already_solved": "solved",
    "incorrect": "failed",
    "partial": "tried",
    "ratelimited": "tried",
    "authentication_required": "tried",
    "paused": "tried",
}

# Классификация анонсов по ключевикам (нижний регистр). Порядок = приоритет.
_NOTIFY_KEYWORDS = [
    ("hint", ("hint", "подсказк")),
    ("clarification", ("clarif", "уточнен", "typo", "fix:", "исправлен",
                       "updated", "обновлён", "обновлен", "errata")),
    ("new", ("new challenge", "новая задач", "released", "published",
             "опубликован", "добавлен")),
    ("scoring", ("score", "freeze", "скор", "заморозк", "bonus", "бонус",
                 "penalt", "штраф")),
]

# Файлы метаданных воркспейса. Приоритет чтения — слева направо; при записи
# challenge.json старый challenge.yaml удаляется (миграция).
_META_FILES = ("challenge.json", "challenge.yaml")


class CTfdError(Exception):
    """Базовая ошибка клиента CTFd."""


class RateLimited(CTfdError):
    """Сервер заблокировал запрос по частоте, и повторная попытка исчерпана."""

    def __init__(self, message: str, retry_in: Optional[int] = None):
        super().__init__(message)
        self.retry_in = retry_in


class CTfdClient:
    """Клиент player-эндпоинтов инстанса CTFd."""

    # Сколько исторических анонсов печатать при первом опросе notifications
    # (когда курсора ещё нет). Перекрыть per-instance: c._notifications_first_limit = N.
    _notifications_first_limit: int = 50

    def __init__(
        self,
        host: str,
        token: Optional[str] = None,
        *,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ):
        self.host = host.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self._nonce: Optional[str] = None
        self._active_ws: Optional[Path] = None
        if token:
            # Авторизация токеном: заголовок Authorization + JSON Content-Type.
            # Запрос с Authorization полностью обходит CSRF.
            # Важно: токен распознаётся только при Content-Type: application/json.
            self.session.headers.update(
                {
                    "Authorization": f"Token {token}",
                    "Content-Type": "application/json",
                }
            )
        # При session-cookie авторизации Content-Type задаётся per-request
        # (json= для API-записей, form-urlencoded для формы логина).

    # ------------------------------------------------------------------
    #  Конструкторы
    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls, **kwargs: Any) -> "CTfdClient":
        """Создать клиент из переменных окружения CTFD_HOST / CTFD_TOKEN."""
        host = kwargs.pop("host", None) or os.environ.get(CTFD_HOST_ENV)
        token = kwargs.pop("token", None) or os.environ.get(CTFD_TOKEN_ENV)
        if not host:
            raise CTfdError(f"Хост не задан: укажите аргумент или ${CTFD_HOST_ENV}.")
        return cls(host, token=token, **kwargs)

    @classmethod
    def from_userpass(
        cls,
        host: str,
        name: str,
        password: str,
        *,
        timeout: float = 30.0,
    ) -> "CTfdClient":
        """Авторизоваться через форму /login и переиспользовать session-cookie.

        У CTFd нет эндпоинта /api/v1/login — вход выполняется POST-формой по
        адресу /login, которая устанавливает подписанную session-cookie. CSRF
        nonce затем берётся из cookie (старые версии CTFd) или скрапится со
        страницы (актуальные версии) и подставляется в заголовок CSRF-Token.
        Для автоматизации предпочтительнее токен (см. from_env / token=).
        """
        c = cls(host, token=None, timeout=timeout)
        c._bootstrap_nonce("/login")
        login_url = f"{c.host}/login"
        data: Dict[str, Any] = {"name": name, "password": password}
        if c._nonce:
            data["nonce"] = c._nonce
        r = c.session.post(
            login_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
            allow_redirects=False,
        )
        # 302 -> успех (редирект на /challenges); 200 -> снова форма (неверные данные).
        if r.status_code not in (301, 302):
            raise CTfdError(
                f"Не удалось войти (HTTP {r.status_code}). Проверьте учётные данные."
            )
        # Сессия пересоздана: обновляем nonce для последующих API-записей.
        c._nonce = c.session.cookies.get("nonce")
        if not c._nonce:
            page = c.session.get(f"{c.host}/challenges", timeout=timeout)
            c._nonce = cls._scrape_nonce(page.text)
        if not c._nonce:
            raise CTfdError(
                "Не удалось получить CSRF nonce после входа. Используйте API-токен."
            )
        return c

    # ------------------------------------------------------------------
    #  Низкоуровневый запрос
    # ------------------------------------------------------------------
    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        if not path.startswith("/"):
            path = "/" + path
        if path.startswith(API_PREFIX):
            return f"{self.host}{path}"
        return f"{self.host}{API_PREFIX}{path}"

    def _headers_for_write(self) -> Dict[str, str]:
        # CSRF-Token нужен только при session-cookie авторизации.
        if self._nonce and "Authorization" not in self.session.headers:
            return {"CSRF-Token": self._nonce}
        return {}

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        data: Optional[Any] = None,
        retry: bool = True,
        allow_404_none: bool = False,
    ) -> Any:
        url = self._url(path)
        kwargs: Dict[str, Any] = {"timeout": self.timeout, "headers": {}}
        if method.upper() in _WRITE_METHODS:
            kwargs["headers"].update(self._headers_for_write())
        if params:
            kwargs["params"] = params
        if json_body is not None:
            kwargs["json"] = json_body
        elif data is not None:
            kwargs["data"] = data

        try:
            r = self.session.request(method, url, **kwargs)
        except requests.RequestException as e:
            raise CTfdError(f"Ошибка запроса: {e}") from e

        if r.status_code == 429 and retry:
            wait = self._parse_retry_seconds(r)
            if wait:
                time.sleep(wait + 1)
                return self._request(
                    method,
                    path,
                    params=params,
                    json_body=json_body,
                    data=data,
                    retry=False,
                    allow_404_none=allow_404_none,
                )
            raise RateLimited(self._safe_text(r), retry_in=wait)

        if r.status_code == 404 and allow_404_none:
            return None
        if r.status_code == 401:
            raise CTfdError(f"Не авторизован (HTTP 401): {self._safe_text(r)}")
        if not r.ok:
            raise CTfdError(
                f"HTTP {r.status_code} {method} {path}: {self._safe_text(r)}"
            )

        if r.status_code == 204 or not r.content:
            return None
        ctype = r.headers.get("Content-Type", "")
        # Редирект на страницу входа (requests следует за 302 по умолчанию):
        # вместо молчаливого возврата HTML подняаем понятную ошибку авторизации.
        if "html" in ctype.lower() and "/login" in r.url.lower():
            raise CTfdError(
                "Требуется авторизация: запрос перенаправлен на страницу входа. "
                "Укажите действительный API-токен или выполните вход."
            )
        try:
            payload = r.json()
        except ValueError:
            if "html" in ctype.lower():
                raise CTfdError(
                    f"Ожидался JSON, получен HTML. final_url={r.url} "
                    "(вероятно, неавторизованный доступ или неверный путь)."
                )
            return r.content

        if isinstance(payload, dict) and "success" in payload:
            if not payload.get("success"):
                raise CTfdError(
                    f"Ошибка API: {json.dumps(payload.get('errors') or payload)[:500]}"
                )
            return payload.get("data", payload)
        return payload

    # ------------------------------------------------------------------
    #  Helpers для nonce / парсинг 429
    # ------------------------------------------------------------------
    def _bootstrap_nonce(self, page: str) -> None:
        self._nonce = self.session.cookies.get("nonce")
        if self._nonce:
            return
        try:
            html = self.session.get(
                f"{self.host}{page}", timeout=self.timeout
            ).text
            self._nonce = self._scrape_nonce(html)
        except requests.RequestException:
            self._nonce = None

    @staticmethod
    def _scrape_nonce(html: str) -> Optional[str]:
        for pat in _NONCE_PATTERNS:
            m = pat.search(html)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _parse_retry_seconds(response: requests.Response) -> Optional[int]:
        try:
            data = response.json()
        except ValueError:
            return None
        msg = ""
        if isinstance(data, dict):
            inner = data.get("data")
            if isinstance(inner, dict):
                msg = inner.get("message", "")
            if not msg:
                msg = data.get("message", "")
        m = _SEC_RE.search(msg or "")
        return int(m.group(1)) if m else None

    @staticmethod
    def _safe_text(response: requests.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            return response.text[:300]

    # ==================================================================
    #  Player-эндпоинты
    # ==================================================================
    def list_challenges(
        self,
        *,
        update_seen: bool = True,
        poll_notifications: bool = True,
        **filters: Any,
    ) -> List[Dict[str, Any]]:
        """Список челленджей (id, name, category, value, solves, solved_by_me).

        Заодно — единая точка «что нового»:

        - ``update_seen=True``: diff текущего списка против снапшота
          ``~/Downloads/ctf/<event>/.seen.json``. Новые с последней проверки
          задачи печатаются в stderr, снапшот обновляется. Первый полный
          (без фильтров) вызов seed'ит baseline с коротким сообщением;
          фильтрованный вызов до baseline не детектит новые (см. ``baselined``).
        - ``poll_notifications=True``: сливает новые анонсы из
          ``/notifications`` (since_id = курсор в ``.seen.json``), печатает
          каждый в stderr с тегом классификации
          (``hint``/``clarification``/``new``/``scoring``/``general``),
          обновляет курсор. Первый опрос показывает все существующие анонсы
          один раз (включая исторические подсказки), затем — только новые.

        Передайте ``update_seen=False`` / ``poll_notifications=False`` для
        «тихого» обзора (без записи состояния).
        """
        data = self._request("GET", "/challenges", params=filters or None)
        if update_seen or poll_notifications:
            # Одна загрузка и одно сохранение .seen.json на вызов (раньше
            # _diff_new_challenges и _poll_notifications сохраняли каждый).
            seen = self._load_seen()
            if update_seen:
                seen = self._diff_new_challenges(
                    data, filtered=bool(filters), seen=seen
                )
            if poll_notifications:
                seen = self._poll_notifications(seen)
            self._save_seen(seen)
        return data

    def get_challenge(self, challenge_id: int) -> Dict[str, Any]:
        """Полное условие: описание, connection_info, файлы, теги, хинты."""
        return self._request("GET", f"/challenges/{challenge_id}")

    def get_challenge_solves(self, challenge_id: int) -> List[Dict[str, Any]]:
        """Кто решил задачу (учитывает заморозку скоринга)."""
        return self._request("GET", f"/challenges/{challenge_id}/solves")

    def attempt(self, challenge_id: int, submission: str) -> Dict[str, Any]:
        """Подать флаг. Возвращает вердикт вида::

            {"status": "correct"|"incorrect"|"already_solved"|"partial"|
                       "ratelimited"|"authentication_required"|"paused"|...,
             "message": "..."}

        429 ratelimited обрабатывается автоматически (один повтор после ожидания
        числа секунд из сообщения).

        Побочные эффекты (best-effort, НИКОГДА не рвут сабмит):
        - автоматически дописывает запись в ``NOTES.md`` активной задачи;
        - при ``correct``/``already_solved`` выставляет ``solved: true`` в
          локальном ``challenge.yaml`` (back-mapping «папка ↔ id ↔ solved»).
        Если воркспейс для задачи не инициализирован — авто-лог тихо пропускается.
        """
        data = self._request(
            "POST",
            "/challenges/attempt",
            json_body={"challenge_id": challenge_id, "submission": submission},
        )
        if isinstance(data, dict) and "status" in data:
            self._autolog_attempt(challenge_id, submission, data)
            return data
        return {"status": "unknown", "data": data}

    def get_hint(self, hint_id: int, preview: bool = False) -> Dict[str, Any]:
        """Показать хинт (content виден только если хинт разблокирован)."""
        params = {"preview": "true"} if preview else None
        return self._request("GET", f"/hints/{hint_id}", params=params)

    def unlock(self, target_type: str, target_id: int) -> Any:
        """Разблокировать хинт или решение (списывает баллы).

        target_type: 'hints' или 'solutions'.
        """
        if target_type not in ("hints", "solutions"):
            raise ValueError("target_type должен быть 'hints' или 'solutions'")
        return self._request(
            "POST",
            "/unlocks",
            json_body={"type": target_type, "target": target_id},
        )

    def unlock_hint(self, hint_id: int) -> Any:
        return self.unlock("hints", hint_id)

    def unlock_solution(self, solution_id: int) -> Any:
        return self.unlock("solutions", solution_id)

    def scoreboard(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/scoreboard")

    def scoreboard_top(
        self, count: int = 10, bracket_id: Optional[int] = None
    ) -> Any:
        count = max(1, min(50, int(count)))
        params = {"bracket_id": bracket_id} if bracket_id is not None else None
        return self._request("GET", f"/scoreboard/top/{count}", params=params)

    def me(self) -> Dict[str, Any]:
        """Текущий пользователь + своё место/баллы."""
        return self._request("GET", "/users/me")

    def my_solves(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/users/me/solves")

    def my_fails(self) -> Any:
        return self._request("GET", "/users/me/fails")

    def my_awards(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/users/me/awards")

    def my_team(self) -> Dict[str, Any]:
        """Своя команда (режим teams)."""
        return self._request("GET", "/teams/me", allow_404_none=True)

    def my_team_solves(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/teams/me/solves")

    def notifications(self, since_id: Optional[int] = None) -> List[Dict[str, Any]]:
        params = {"since_id": since_id} if since_id is not None else None
        return self._request("GET", "/notifications", params=params)

    def download_file(self, url: str, dest_dir: Optional[str] = None) -> Path:
        """Скачать файл по URL из get_challenge()['files'].

        URL из CTFd — относительный путь вида ``/files/<hash>/<name>?token=...``
        (подпись уже встроена). При необходимости подставляем хост инстанса.

        ``dest_dir=None`` (по умолчанию) → активный воркспейс ``attachments/``
        (если задан через :meth:`init_challenge_workspace`), иначе ``/tmp``.
        """
        if dest_dir is None:
            if self._active_ws:
                dest_dir = str(self._active_ws / "attachments")
            else:
                print(
                    "[ctfd] WARNING: download_file без активного воркспейса — "
                    "файл сохранён в /tmp. Вызовите init_challenge_workspace(detail), "
                    "чтобы файлы шли в <ws>/attachments/ и отслеживались в журнале.",
                    file=sys.stderr,
                )
                dest_dir = "/tmp"
        if url.startswith("/"):
            url = f"{self.host}{url}"
        elif not url.startswith(("http://", "https://")):
            url = f"{self.host}/{url}"
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        name = (
            url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1] or "download.bin"
        )
        out = dest / name
        with self.session.get(url, stream=True, timeout=self.timeout) as r:
            r.raise_for_status()
            with open(out, "wb") as fh:
                for chunk in r.iter_content(8192):
                    fh.write(chunk)
        return out

    # -- персистентный CTF-воркспейс -------------------------------
    def init_challenge_workspace(
        self,
        challenge: Dict[str, Any],
        base: str = "~/Downloads/ctf",
    ) -> Path:
        """Создать персистентный воркспейс для задачи и вернуть путь.

        Структура::

            <base>/<event>/<category>/<slug>/
            ├── challenge.yaml      метаданные CTFd (id, name, host, ...)
            ├── description.md      условие задачи
            ├── attachments/        скачанные файлы
            ├── scripts/            самописные solve-скрипты (запускать отсюда)
            └── NOTES.md            журнал хода решения (append)

        ``event`` выводится из host (напр. ``nhnc.ic3dt3a.org`` → ``nhnc-2026``);
        override через env ``CTFD_EVENT``. Воркспейс переживает ребуты
        (по умолчанию в ``~/Downloads/ctf``).
        """
        base_path = Path(os.path.expanduser(base))
        event = os.environ.get("CTFD_EVENT") or self._derive_event_slug()
        category = self._slugify(str(challenge.get("category") or "misc"))
        name = challenge.get("name") or str(challenge.get("id") or "challenge")
        slug = self._slugify(name)
        ws = base_path / event / category / slug
        (ws / "attachments").mkdir(parents=True, exist_ok=True)
        (ws / "scripts").mkdir(parents=True, exist_ok=True)

        # Idempotency: сохраняем состояние решения существующего воркспейса.
        existing = self._read_meta(ws)
        created_at = existing.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%S")
        # solved никогда не регрессируем. Серверный solved_by_me поднимает в True,
        # но уже проставленный локально (autolog) не сбрасываем устаревшим detail.
        solved = bool(existing.get("solved")) or bool(challenge.get("solved_by_me"))
        meta: Dict[str, Any] = {
            "id": challenge.get("id"),
            "name": challenge.get("name"),
            "category": challenge.get("category"),
            "value": challenge.get("value"),
            "connection_info": challenge.get("connection_info"),
            "host": self.host,
            "event": event,
            "solved": solved,
            "created_at": created_at,
            "workspace": str(ws),
        }
        if solved and existing.get("solved_at"):
            meta["solved_at"] = existing["solved_at"]
        self._write_meta(ws, meta)  # пишет challenge.json, мигрирует старый .yaml
        desc = ws / "description.md"
        if not desc.exists():
            desc.write_text(
                challenge.get("description") or "(описание отсутствует)", encoding="utf-8"
            )
        notes = ws / "NOTES.md"
        if not notes.exists():
            notes.write_text(
                f"# {challenge.get('name', '?')} — журнал решения\n\n"
                f"event: {event} · category: {challenge.get('category')} · "
                f"id: {challenge.get('id')}\nhost: {self.host}\n\n"
                "Записи: `## [ISO-ts] status` → гипотеза/действие/результат.\n\n",
                encoding="utf-8",
            )

        self._active_ws = ws
        return ws

    def log_attempt(
        self,
        challenge_id: int,
        entry: str,
        status: Optional[str] = None,
        *,
        _silent: bool = False,
    ) -> Path:
        """Дописать датированную запись в ``NOTES.md`` задачи.

        ``status`` — короткая метка (``'hypothesis'``/``'tried'``/``'solved'``/
        ``'failed'``/...). Если активный воркспейс не задан, ищется по
        ``challenge_id`` в метаданных воркспейса; если не найден — запись
        теряется с предупреждением в stderr (если не ``_silent`` — используется
        авто-логом :meth:`_autolog_attempt`, чтобы не шуметь без воркспейса).
        """
        ws = self._active_ws or self._find_workspace_by_id(challenge_id)
        if ws is None:
            if not _silent:
                print(
                    f"[ctfd] log_attempt: воркспейс для challenge {challenge_id} "
                    f"не найден — запись потеряна",
                    file=sys.stderr,
                )
            return Path()
        self._active_ws = ws
        notes = ws / "NOTES.md"
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        head = f"## [{ts}] {status}" if status else f"## [{ts}]"
        with open(notes, "a", encoding="utf-8") as fh:
            fh.write(f"{head}\n{entry}\n\n")
        return notes

    @staticmethod
    def _slugify(text: str) -> str:
        """lowercase; не-буквы/цифры → ``_``; коллапс повторов; trim."""
        s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
        return s or "challenge"

    # -- чтение/запись метаданных воркспейса (challenge.json, с миграцией .yaml) -
    @staticmethod
    def _read_meta(ws: Path) -> Dict[str, Any]:
        """Прочитать метаданные воркспейса. Приоритет: challenge.json, затем
        устаревший challenge.yaml. Возвращает ``{}`` если ничего нет."""
        for name in _META_FILES:
            mf = ws / name
            if mf.exists():
                try:
                    return json.loads(mf.read_text(encoding="utf-8"))
                except Exception:
                    continue
        return {}

    @staticmethod
    def _write_meta(ws: Path, meta: Dict[str, Any]) -> None:
        """Записать challenge.json и удалить старый challenge.yaml (миграция)."""
        try:
            (ws / "challenge.json").write_text(
                json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            return
        yf = ws / "challenge.yaml"
        if yf.exists():
            try:
                yf.unlink()
            except OSError:
                pass

    def _derive_event_slug(self) -> str:
        """event-слаг из host: ``nhnc.ic3dt3a.org`` → ``nhnc-YYYY``.

        Первый не-generic label (skip www/ctf/chall/...) + текущий год.
        """
        from urllib.parse import urlparse

        host = urlparse(self.host).hostname or self.host
        labels = host.split(".")
        generic = {"www", "ctf", "chall", "challenge", "api"}
        cand = next(
            (l for l in labels if l.lower() not in generic and l),
            labels[0] if labels else "ctf",
        )
        cand = re.sub(r"[^a-z0-9]+", "_", cand.lower()).strip("_") or "ctf"
        return f"{cand}-{time.strftime('%Y')}"

    def _find_workspace_by_id(self, challenge_id: int) -> Optional[Path]:
        """Найти воркспейс по ``id`` в метаданных под папкой ТЕКУЩЕГО события.

        Scope ограничен ``~/Downloads/ctf/<event>/`` — CTFd-ные id per-instance
        (1..N), поэтому без фильтра по event два события с одинаковым id
        коллидировали бы (недетерминированный возврат первого попавшего).
        """
        base = Path(os.path.expanduser("~/Downloads/ctf"))
        event = os.environ.get("CTFD_EVENT") or self._derive_event_slug()
        root = base / event
        if not root.exists():
            return None
        for name in _META_FILES:
            for mf in root.rglob(name):
                try:
                    meta = json.loads(mf.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if meta.get("id") == challenge_id:
                    return mf.parent
        return None

    # ------------------------------------------------------------------
    #  Состояние события: .seen.json (новые задачи + курсор анонсов)
    # ------------------------------------------------------------------
    def _event_dir(self) -> Path:
        base = Path(os.path.expanduser("~/Downloads/ctf"))
        event = os.environ.get("CTFD_EVENT") or self._derive_event_slug()
        d = base / event
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _seen_path(self) -> Path:
        return self._event_dir() / ".seen.json"

    def _load_seen(self) -> Dict[str, Any]:
        p = self._seen_path()
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_seen(self, seen: Dict[str, Any]) -> None:
        seen.setdefault("event", os.environ.get("CTFD_EVENT") or self._derive_event_slug())
        seen.setdefault("host", self.host)
        seen["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        try:
            self._seen_path().write_text(
                json.dumps(seen, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            pass

    def _diff_new_challenges(
        self,
        chals: List[Dict[str, Any]],
        *,
        filtered: bool,
        seen: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Обновить ``seen`` (in-place + return) списком текущих id.

        Корректность при фильтре: ``ids`` хранится как **union** (когда-либо
        виденные), никогда не перезаписывается подмножеством отфильтрованного
        вызова. ``baselined`` фиксирует, что был полный (без фильтров) обзор —
        до этого «новые» не анонсируются (baseline ещё неполный).
        """
        ids_now = {int(c["id"]) for c in chals if c.get("id") is not None}
        known = set(seen.get("ids") or [])
        seen["ids"] = sorted(ids_now | known)
        if not seen.get("baselined"):
            if not filtered:
                seen["baselined"] = True
                print(
                    f"[ctfd] seeded .seen.json: {len(ids_now)} challenges baselined",
                    file=sys.stderr,
                )
            else:
                print(
                    "[ctfd] NOTE: list_challenges() с фильтром до baseline — "
                    "детект новых задач отключён. Вызовите list_challenges() "
                    "без фильтров для полного seed.",
                    file=sys.stderr,
                )
            return seen
        new_ids = sorted(ids_now - known)
        if new_ids:
            by_id = {int(c["id"]): c for c in chals}
            print(
                f"[ctfd] {len(new_ids)} NEW challenge(s) since "
                f"{seen.get('updated_at', '?')}:",
                file=sys.stderr,
            )
            for cid in new_ids:
                c = by_id.get(cid, {})
                print(
                    f"  [new] #{cid} \"{c.get('name', '?')}\" "
                    f"({c.get('category', '?')}, {c.get('value', '?')}pt) "
                    f"— solves={c.get('solves', 0)}",
                    file=sys.stderr,
                )
        return seen

    @staticmethod
    def _classify_notification(title: str, body: str) -> str:
        text = f"{title} {body}".lower()
        for tag, keywords in _NOTIFY_KEYWORDS:
            if any(k in text for k in keywords):
                return tag
        return "general"

    def _poll_notifications(self, seen: Dict[str, Any]) -> Dict[str, Any]:
        """Обновить ``seen`` (in-place + return) новыми анонсами.

        На первом опросе (cursor не задан) показывает все существующие анонсы
        один раз (включая исторические подсказки/уточнения), затем ставит
        курсор на max(id). Дальше — только новые.
        """
        since = seen.get("last_notification_id")
        first_run = since is None
        params = {"since_id": since} if since else None
        try:
            notes = self._request("GET", "/notifications", params=params) or []
        except CTfdError as e:
            print(f"[ctfd] notifications poll failed: {e}", file=sys.stderr)
            return seen
        if not notes:
            return seen
        to_show = notes
        if first_run and len(notes) > self._notifications_first_limit:
            # CTFd возвращает asc по id → последние = самые свежие.
            to_show = notes[-self._notifications_first_limit:]
            print(
                f"[ctfd] first notifications poll: {len(notes)} historical, "
                f"showing newest {len(to_show)} "
                f"({len(notes) - len(to_show)} older omitted — "
                f"`python scripts/ctfd_client.py notifications` to page)",
                file=sys.stderr,
            )
        for n in to_show:
            nid = n.get("id")
            title = (n.get("title") or "").strip()
            body = (n.get("body") or "").strip().replace("\n", " ")
            if len(body) > 160:
                body = body[:157] + "..."
            tag = self._classify_notification(title, body)
            line = f"[ctfd] NOTIFY #{nid} [{tag}]"
            if title:
                line += f" {title}"
            line += f": {body}" if body else ""
            print(line.rstrip(), file=sys.stderr)
        max_id = max(
            (n.get("id") for n in notes if n.get("id") is not None),
            default=None,
        )
        if max_id is not None:
            seen["last_notification_id"] = max_id
            seen.setdefault("ids", [])
        return seen

    # ------------------------------------------------------------------
    #  Авто-лог сабмитов + маркировка solved в метаданных воркспейса
    # ------------------------------------------------------------------
    def _autolog_attempt(
        self,
        challenge_id: int,
        submission: str,
        verdict_data: Dict[str, Any],
    ) -> None:
        """Best-effort запись попытки в NOTES.md + solved:true при корректе.

        Любая ошибка подавляется — журналирование НИКОГДА не блокирует сабмит.
        Делегирует запись в :meth:`log_attempt` (``_silent=True``), чтобы формат
        журнала был определён в одном месте.
        """
        try:
            status = verdict_data.get("status", "unknown")
            message = verdict_data.get("message", "")
            tag = _STATUS_LOG.get(status, "tried")
            preview = submission if len(submission) <= 80 else submission[:77] + "..."
            self.log_attempt(
                challenge_id, f"submit `{preview}` -> {status}: {message}", tag,
                _silent=True,
            )
            if status in ("correct", "already_solved"):
                ws = self._active_ws or self._find_workspace_by_id(challenge_id)
                if ws is not None:
                    self._mark_solved_meta(ws, True)
        except Exception:
            pass

    def _mark_solved_meta(self, ws: Path, solved: bool) -> None:
        """Поставить/снять ``solved`` (+ ``solved_at``) в challenge.json."""
        meta = self._read_meta(ws)
        if not meta:
            return
        meta["solved"] = bool(solved)
        meta["solved_at"] = time.strftime("%Y-%m-%dT%H:%M:%S") if solved else None
        self._write_meta(ws, meta)

    # ------------------------------------------------------------------
    #  Сводка по воркспейсам + сверка/синхронизация с сервером
    # ------------------------------------------------------------------
    def workspace_status(
        self,
        event: Optional[str] = None,
        base: str = "~/Downloads/ctf",
    ) -> Dict[str, Any]:
        """Локальная сводка по воркспейсам события + сверка с сервером.

        Сканирует ``<base>/<event>/**/{challenge.json,challenge.yaml}``, считает
        solved / in_progress и сверяет множество решённых с ``my_solves()`` —
        ловит дрейф вида «локально 22, сервер 25». Без токена работает оффлайн
        (поля server_* остаются пустыми).
        """
        base_path = Path(os.path.expanduser(base))
        event = event or os.environ.get("CTFD_EVENT") or self._derive_event_slug()
        root = base_path / event
        local: List[Dict[str, Any]] = []
        if root.exists():
            seen_dirs: set = set()
            for name in _META_FILES:
                for mf in root.rglob(name):
                    wd = mf.parent
                    if wd in seen_dirs:
                        continue
                    meta = self._read_meta(wd)
                    if meta:
                        local.append(meta)
                        seen_dirs.add(wd)
        solved_local = [m for m in local if m.get("solved")]
        in_progress = [m for m in local if not m.get("solved")]
        server_solved_ids: List[int] = []
        server_set: set = set()
        drift: List[int] = []
        local_unsolved_server_solved: List[int] = []
        try:
            server_solves = self.my_solves() or []
            server_solved_ids = sorted(
                {int(s["challenge_id"]) for s in server_solves if s.get("challenge_id")}
            )
            server_set = set(server_solved_ids)
            local_ids = {int(m["id"]) for m in local if m.get("id") is not None}
            drift = sorted(server_set - local_ids)
            # воркспейс есть, но локально solved:false, а сервер говорит решено —
            # sync это починил бы; показываем отдельно от drift.
            local_unsolved_server_solved = sorted(
                int(m["id"]) for m in local
                if m.get("id") is not None and not m.get("solved")
                and int(m["id"]) in server_set
            )
        except Exception as e:
            print(
                f"[ctfd] status: my_solves() failed ({e}) — server fields empty",
                file=sys.stderr,
            )
        return {
            "event": event,
            "root": str(root),
            "total_local": len(local),
            "solved_local": len(solved_local),
            "in_progress": len(in_progress),
            "server_solved": len(server_solved_ids),
            "drift_untracked_solves": drift,
            "local_unsolved_server_solved": local_unsolved_server_solved,
        }

    def sync_from_server(
        self,
        event: Optional[str] = None,
        dry_run: bool = False,
        all_challenges: bool = False,
    ) -> Dict[str, Any]:
        """Дозаполнить воркспейсы из серверной истины.

        По умолчанию (``all_challenges=False``) обрабатывает только решённые на
        сервере (``my_solves``): для каждого без локального воркспейса (или с
        ``solved: false``) создаёт/обновляет scaffold и выставляет ``solved: true``.

        При ``all_challenges=True`` scaffодит ВСЕ задачи без локального
        воркспейса (без авто-``solved``) — удобно для pre-populate в начале
        ивента. Возвращает ``{created, updated, skipped, errors}``.
        """
        result: Dict[str, Any] = {
            "created": [],
            "updated": [],
            "skipped": [],
            "errors": [],
            "dry_run": dry_run,
        }
        if all_challenges:
            try:
                chals = self.list_challenges(
                    update_seen=False, poll_notifications=False
                ) or []
            except Exception as e:
                result["errors"].append(f"list_challenges failed: {e}")
                return result
            for ch in chals:
                cid = ch.get("id")
                if cid is None:
                    continue
                try:
                    if self._find_workspace_by_id(cid) is not None:
                        result["skipped"].append(cid)
                        continue
                    if dry_run:
                        result["created"].append(cid)
                        continue
                    detail = self.get_challenge(cid)
                    self.init_challenge_workspace(detail)
                    result["created"].append(cid)
                except Exception as e:
                    result["errors"].append(f"#{cid}: {e}")
            return result
        try:
            server_solves = self.my_solves() or []
        except Exception as e:
            result["errors"].append(f"my_solves failed: {e}")
            return result
        solved_ids = sorted(
            {int(s["challenge_id"]) for s in server_solves if s.get("challenge_id")}
        )
        for cid in solved_ids:
            try:
                ws = self._find_workspace_by_id(cid)
                if ws is None:
                    if dry_run:
                        result["created"].append(cid)
                        continue
                    detail = self.get_challenge(cid)
                    ws = self.init_challenge_workspace(detail)
                    self._mark_solved_meta(ws, True)
                    self.log_attempt(cid, "synced from server: solved", "solved")
                    result["created"].append(cid)
                else:
                    meta = self._read_meta(ws)
                    if meta.get("solved"):
                        result["skipped"].append(cid)
                    else:
                        if dry_run:
                            result["updated"].append(cid)
                            continue
                        self._mark_solved_meta(ws, True)
                        result["updated"].append(cid)
            except Exception as e:
                result["errors"].append(f"#{cid}: {e}")
        return result

    # -- управление собственными API-токенами --------------------------
    def generate_token(
        self,
        expiration: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Создать API-токен. expiration — 'YYYY-MM-DD'. Значение показывается один раз."""
        body: Dict[str, Any] = {}
        if expiration:
            body["expiration"] = expiration
        if description:
            body["description"] = description
        return self._request("POST", "/tokens", json_body=body or None)

    def list_tokens(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/tokens")

    def revoke_token(self, token_id: int) -> None:
        self._request("DELETE", f"/tokens/{token_id}")


# ====================================================================
#  CLI
# ====================================================================
def _client_from_args(args: argparse.Namespace, allow_no_token: bool = False) -> CTfdClient:
    host = args.host or os.environ.get(CTFD_HOST_ENV)
    token = args.token or os.environ.get(CTFD_TOKEN_ENV)
    if not host:
        sys.exit(f"ошибка: требуется --host или ${CTFD_HOST_ENV}")
    if not token and not allow_no_token:
        sys.exit(
            f"ошибка: требуется --token или ${CTFD_TOKEN_ENV} "
            "(логин по паролю в CLI не поддерживается)"
        )
    return CTfdClient(host, token=token or None)


def _print(obj: Any) -> None:
    if isinstance(obj, (dict, list)):
        print(json.dumps(obj, ensure_ascii=False, indent=2))
    else:
        print(obj)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ctfd_client",
        description="Клиент для REST API CTFd (player-эндпоинты).",
    )
    p.add_argument("--host", help=f"базовый URL CTFd (или env ${CTFD_HOST_ENV})")
    p.add_argument("--token", help=f"API-токен (или env ${CTFD_TOKEN_ENV})")
    sub = p.add_subparsers(dest="cmd", required=True)

    lc = sub.add_parser("challenges", help="Список челленджей")
    lc.add_argument("--category")

    g = sub.add_parser("challenge", help="Детали задачи")
    g.add_argument("id", type=int)

    a = sub.add_parser("submit", help="Подать флаг")
    a.add_argument("id", type=int)
    a.add_argument("flag")

    sub.add_parser("me", help="Текущий пользователь")
    sub.add_parser("solves", help="Мои решения")
    sub.add_parser("scoreboard", help="Рейтинг")
    t = sub.add_parser("top", help="Топ-N рейтинга")
    t.add_argument("n", type=int, nargs="?", default=10)

    h = sub.add_parser("hint", help="Показать хинт")
    h.add_argument("id", type=int)
    hu = sub.add_parser("unlock-hint", help="Разблокировать хинт (стоимость в баллах)")
    hu.add_argument("id", type=int)

    dl = sub.add_parser("download", help="Скачать файл по URL")
    dl.add_argument("url")
    dl.add_argument("-o", "--out", default="/tmp")

    nt = sub.add_parser("notifications", help="Список анонсов")
    nt.add_argument("--since-id", type=int)

    sub.add_parser("tokens", help="Мои API-токены")
    gt = sub.add_parser("gen-token", help="Создать API-токен")
    gt.add_argument("--expiration", help="YYYY-MM-DD")
    gt.add_argument("--description")
    rt = sub.add_parser("revoke-token", help="Отозвать токен по id")
    rt.add_argument("id", type=int)

    st = sub.add_parser(
        "status",
        help="Сводка по воркспейсам события + сверка решённых с сервером",
    )
    st.add_argument("--event", help="slug события (по умолчанию выводится из host)")
    st.add_argument("--base", default="~/Downloads/ctf", help="база воркспейсов")

    sy = sub.add_parser(
        "sync",
        help="Дозаполнить challenge.json/description.md из сервера (по my_solves)",
    )
    sy.add_argument("--event", help="slug события")
    sy.add_argument("--dry-run", action="store_true", help="только показать, не записывая")
    sy.add_argument(
        "--all",
        action="store_true",
        help="scaffодить ВСЕ задачи без локального воркспейса (не только решённые)",
    )

    dc = sub.add_parser(
        "download-challenge",
        help="Скаффолдить воркспейс задачи и скачать все её файлы в attachments/",
    )
    dc.add_argument("id", type=int)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    cmd = args.cmd
    # status работает оффлайн (без токена) — только локальная сводка, без сверки.
    c = _client_from_args(args, allow_no_token=(cmd == "status"))

    if cmd == "challenges":
        flt = {"category": args.category} if args.category else None
        _print(c.list_challenges(**(flt or {})))
    elif cmd == "challenge":
        _print(c.get_challenge(args.id))
    elif cmd == "submit":
        _print(c.attempt(args.id, args.flag))
    elif cmd == "me":
        _print(c.me())
    elif cmd == "solves":
        _print(c.my_solves())
    elif cmd == "scoreboard":
        _print(c.scoreboard())
    elif cmd == "top":
        _print(c.scoreboard_top(args.n))
    elif cmd == "hint":
        _print(c.get_hint(args.id))
    elif cmd == "unlock-hint":
        _print(c.unlock_hint(args.id))
    elif cmd == "download":
        _print(str(c.download_file(args.url, args.out)))
    elif cmd == "notifications":
        _print(c.notifications(args.since_id))
    elif cmd == "tokens":
        _print(c.list_tokens())
    elif cmd == "gen-token":
        _print(c.generate_token(args.expiration, args.description))
    elif cmd == "revoke-token":
        c.revoke_token(args.id)
        _print({"revoked": args.id})
    elif cmd == "status":
        _print(c.workspace_status(event=args.event, base=args.base))
    elif cmd == "sync":
        _print(c.sync_from_server(
            event=args.event, dry_run=args.dry_run, all_challenges=args.all
        ))
    elif cmd == "download-challenge":
        detail = c.get_challenge(args.id)
        ws = c.init_challenge_workspace(detail)
        files = detail.get("files") or []
        paths = [str(c.download_file(f)) for f in files]
        _print({"workspace": str(ws), "files": len(files), "downloaded": paths})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
