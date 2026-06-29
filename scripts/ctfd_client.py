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


class CTfdError(Exception):
    """Базовая ошибка клиента CTFd."""


class RateLimited(CTfdError):
    """Сервер заблокировал запрос по частоте, и повторная попытка исчерпана."""

    def __init__(self, message: str, retry_in: Optional[int] = None):
        super().__init__(message)
        self.retry_in = retry_in


class CTfdClient:
    """Клиент player-эндпоинтов инстанса CTFd."""

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
    def list_challenges(self, **filters: Any) -> List[Dict[str, Any]]:
        """Список челленджей (id, name, category, value, solves, solved_by_me)."""
        return self._request("GET", "/challenges", params=filters or None)

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
        """
        data = self._request(
            "POST",
            "/challenges/attempt",
            json_body={"challenge_id": challenge_id, "submission": submission},
        )
        if isinstance(data, dict) and "status" in data:
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

    def download_file(self, url: str, dest_dir: str = "/tmp") -> Path:
        """Скачать файл по URL из get_challenge()['files'].

        URL из CTFd — относительный путь вида ``/files/<hash>/<name>?token=...``
        (подпись уже встроена). При необходимости подставляем хост инстанса.
        """
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
def _client_from_args(args: argparse.Namespace) -> CTfdClient:
    host = args.host or os.environ.get(CTFD_HOST_ENV)
    token = args.token or os.environ.get(CTFD_TOKEN_ENV)
    if not host:
        sys.exit(f"ошибка: требуется --host или ${CTFD_HOST_ENV}")
    if not token:
        sys.exit(
            f"ошибка: требуется --token или ${CTFD_TOKEN_ENV} "
            "(логин по паролю в CLI не поддерживается)"
        )
    return CTfdClient(host, token=token)


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
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    c = _client_from_args(args)
    cmd = args.cmd

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
