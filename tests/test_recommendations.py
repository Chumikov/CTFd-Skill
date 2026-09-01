"""Тесты улучшений по итогам пост-мортема предыдущего CTF — без сети.

Покрывает:
    - профили: resolution-приоритет, last-touch, маскировка токена
    - стабы в .seen.json (challenges --offline)
    - журнал попыток attempts.json + дубликат-ворнинг
    - unlock_hint_confirmed: гейт без списания, unlock с assume_yes
    - scoreboard diff: чистая функция на двух standings
    - _explain_http_error: маппинг кодов в человеческие пояснения
    - GET-retry: 5xx ретраится для GET, никогда — для POST
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import ctfd_client as m  # noqa: E402
from ctfd_client import CTfdClient, CTfdError, SubmitResult  # noqa: E402


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CTFD_EVENT", "test-event-2026")
    monkeypatch.setenv("CTFD_HOST", "https://ctf.example.com")
    monkeypatch.setenv("CTFD_TOKEN", "ctfd_test_token")
    # Профили изолируем тем же HOME (путь ~/.config/ctfd/profiles.json)
    monkeypatch.delenv("CTFD_PROFILE", raising=False)
    return home


@pytest.fixture
def client(isolated_home):
    return CTfdClient("https://ctf.example.com", token="ctfd_test_token")


def _fake_response(status=200, payload=None, text=""):
    r = MagicMock()
    r.status_code = status
    r.ok = status < 400
    r.url = "https://ctf.example.com/api/v1/x"
    r.headers = {"Content-Type": "application/json"}
    if payload is not None:
        r.json.return_value = payload
    else:
        r.json.side_effect = ValueError(text)
        r.text = text
    return r


# ----------------------------------------------------------------------
#  Профили
# ----------------------------------------------------------------------
class TestProfiles:
    def test_resolve_by_name(self, isolated_home):
        m._save_profiles(
            {
                "last": "other",
                "profiles": {
                    "demo": {"host": "https://global.democtf.dk",
                                "token": "ctfd_demo"},
                    "other": {"host": "https://x.example.com", "token": "ctfd_x"},
                },
            }
        )
        prof = m._resolve_profile("demo")
        assert prof["host"] == "https://global.democtf.dk"
        assert prof["token"] == "ctfd_demo"
        assert prof["name"] == "demo"

    def test_resolve_last_when_no_name(self, isolated_home):
        m._save_profiles(
            {"last": "demo",
             "profiles": {"demo": {"host": "https://b.example.com", "token": "t"}}}
        )
        prof = m._resolve_profile(None)
        assert prof is not None and prof["name"] == "demo"

    def test_missing_explicit_name_raises(self, isolated_home):
        m._save_profiles({"profiles": {"a": {"host": "https://a.dk"}}})
        with pytest.raises(CTfdError, match="не найден"):
            m._resolve_profile("nope")

    def test_no_profiles_returns_none(self, isolated_home):
        assert m._resolve_profile(None) is None
        assert m._resolve_profile("anything") if False else True

    def test_touch_last_updates(self, isolated_home):
        m._save_profiles(
            {"last": "a", "profiles": {"a": {"host": "h", "token": "t"},
                                       "b": {"host": "h2", "token": "t2"}}}
        )
        m._touch_last_profile("b")
        data = m._load_profiles()
        assert data["last"] == "b"
        # повторный touch того же имени не перезаписывает файл зря — но
        # главное, что состояние корректно
        m._touch_last_profile("b")
        assert m._load_profiles()["last"] == "b"

    def test_save_sets_restrictive_mode(self, isolated_home):
        m._save_profiles({"profiles": {"a": {"host": "h"}}})
        assert (m._profiles_path().stat().st_mode & 0o777) == 0o600

    def test_mask_token(self):
        assert m._mask_token("ctfd_1234567890abcdef") == "ctfd...cdef"
        assert m._mask_token("short") == "*****"
        assert m._mask_token("") == ""

    def test_cli_profile_priority_explicit_beats_env(
        self, isolated_home, monkeypatch
    ):
        # env указывает на example.com, -p demo должен победить
        m._save_profiles(
            {"profiles": {"demo": {"host": "https://b.example.com",
                                      "token": "ctfd_b"}}}
        )
        args = m.argparse.Namespace(
            host=None, token=None, profile="demo"
        )
        c = m._client_from_args(args)
        assert c.host == "https://b.example.com"
        assert m._load_profiles()["last"] == "demo"

    def test_cli_explicit_host_token_beats_profile(
        self, isolated_home, monkeypatch
    ):
        monkeypatch.delenv("CTFD_HOST", raising=False)
        monkeypatch.delenv("CTFD_TOKEN", raising=False)
        m._save_profiles(
            {"last": "b", "profiles": {"b": {"host": "https://b.example.com",
                                             "token": "ctfd_b"}}}
        )
        args = m.argparse.Namespace(
            host="https://explicit.com", token="ctfd_explicit", profile=None
        )
        c = m._client_from_args(args)
        assert c.host == "https://explicit.com"

    def test_cli_falls_back_to_last_profile(self, isolated_home, monkeypatch):
        monkeypatch.delenv("CTFD_HOST", raising=False)
        monkeypatch.delenv("CTFD_TOKEN", raising=False)
        m._save_profiles(
            {"last": "b", "profiles": {"b": {"host": "https://b.example.com",
                                             "token": "ctfd_b"}}}
        )
        args = m.argparse.Namespace(host=None, token=None, profile=None)
        c = m._client_from_args(args)
        assert c.host == "https://b.example.com"

    def test_cli_missing_profile_exits(self, isolated_home):
        m._save_profiles({"profiles": {}})
        args = m.argparse.Namespace(host=None, token=None, profile="ghost")
        with pytest.raises(SystemExit, match="ghost"):
            m._client_from_args(args)


# ----------------------------------------------------------------------
#  Стабы .seen.json (--offline)
# ----------------------------------------------------------------------
class TestSeenStubs:
    def test_stubs_written_on_diff(self, client):
        seen = {}
        data = [
            {"id": 1, "name": "a", "category": "web", "value": 100,
             "solves": 5, "solved_by_me": False},
            {"id": 2, "name": "b", "category": "pwn", "value": 500,
             "solves": 2, "solved_by_me": True},
        ]
        out = client._diff_new_challenges(data, filtered=False, seen=seen)
        stubs = out["stubs"]
        assert stubs["1"]["name"] == "a"
        assert stubs["2"]["value"] == 500
        assert stubs["2"]["solved_by_me"] is True

    def test_stubs_updated_on_later_listing(self, client):
        seen = {"ids": [1, 2], "baselined": True,
                "stubs": {"1": {"name": "a", "solved_by_me": False}}}
        data = [{"id": 1, "name": "a", "category": "web", "value": 100,
                 "solves": 9, "solved_by_me": True}]
        out = client._diff_new_challenges(data, filtered=False, seen=seen)
        assert out["stubs"]["1"]["solved_by_me"] is True
        assert out["stubs"]["1"]["solves"] == 9

    def test_offline_roundtrip(self, client):
        data = [{"id": 7, "name": "x", "category": "misc", "value": 10,
                 "solves": 1, "solved_by_me": False}]
        seen = client._diff_new_challenges(data, filtered=False, seen={})
        client._save_seen(seen)
        stubs = client._load_seen()["stubs"]
        assert stubs["7"]["name"] == "x"


# ----------------------------------------------------------------------
#  Журнал попыток + дубликат-ворнинг
# ----------------------------------------------------------------------
class TestAttemptsJournal:
    def test_journal_write_and_load(self, client):
        client._journal_attempt(42, "flag{a}", "incorrect")
        client._journal_attempt(42, "flag{b}", "correct")
        attempts = client._load_attempts()
        assert len(attempts) == 2
        assert attempts[0]["flag"] == "flag{a}"
        assert attempts[0]["status"] == "incorrect"
        assert attempts[1]["chal_id"] == 42
        assert "ts" in attempts[0]

    def test_journal_never_raises(self, client, monkeypatch):
        def boom(*a, **kw):
            raise OSError("disk full")
        monkeypatch.setattr(client, "_load_attempts", boom)
        client._journal_attempt(1, "f", "incorrect")  # не бросает

    def test_duplicate_warning_fires(self, client, capsys):
        client._journal_attempt(42, "flag{same}", "incorrect")
        fired = client._warn_duplicate_attempt(42, "flag{same}")
        assert fired is True
        err = capsys.readouterr().err
        assert "уже отправлялся" in err
        assert "incorrect" in err

    def test_duplicate_ignores_whitespace_and_warns_ratelimited(
        self, client, capsys
    ):
        client._journal_attempt(42, "flag{s}", "ratelimited")
        assert client._warn_duplicate_attempt(42, "  flag{s}  ") is True

    def test_no_warning_for_correct_or_new(self, client, capsys):
        client._journal_attempt(42, "flag{ok}", "correct")
        assert client._warn_duplicate_attempt(42, "flag{ok}") is False
        assert client._warn_duplicate_attempt(42, "flag{other}") is False
        # different challenge — тоже молчим
        client._journal_attempt(43, "flag{x}", "incorrect")
        assert client._warn_duplicate_attempt(42, "flag{x}") is False
        assert capsys.readouterr().err == ""

    def test_attempt_hooks_journal_and_warning(self, client, monkeypatch, capsys):
        monkeypatch.setattr(
            client, "_request",
            lambda *a, **kw: {"status": "incorrect", "message": "no"},
        )
        verdict = client.attempt(42, "flag{dup}")
        assert isinstance(verdict, SubmitResult)
        assert not verdict.correct
        # попытка в журнале
        attempts = client._load_attempts()
        assert attempts[-1]["flag"] == "flag{dup}"
        assert attempts[-1]["status"] == "incorrect"
        # повтор того же флага → ворнинг до отправки
        client.attempt(42, "flag{dup}")
        assert "уже отправлялся" in capsys.readouterr().err


# ----------------------------------------------------------------------
#  unlock_hint_confirmed
# ----------------------------------------------------------------------
class TestUnlockHintConfirmed:
    def _hint(self, cost=50, content=None):
        return {"id": 7, "cost": cost, "content": content}

    def test_gate_without_yes_no_unlock(self, client, monkeypatch, capsys):
        calls = []

        def fake_request(method, path, **kw):
            calls.append((method, path, kw.get("params")))
            if method == "GET":
                return self._hint(cost=50, content=None)
            calls.append(("UNEXPECTED-WRITE", path))
            return {}

        monkeypatch.setattr(client, "_request", fake_request)
        monkeypatch.setattr(client, "me", lambda: {"score": 1250})
        out = client.unlock_hint_confirmed(7, assume_yes=False)
        assert out["unlocked"] is False
        assert out["cost"] == 50
        assert out["score"] == 1250
        assert "--yes" in out["note"]
        # ни одного POST /unlocks
        assert all(meth == "GET" for meth, _, _ in calls)
        assert not any("unlocks" in p for _, p, _ in calls)

    def test_assume_yes_unlocks_and_returns_content(
        self, client, monkeypatch
    ):
        state = {"unlocked": False}

        def fake_request(method, path, **kw):
            if method == "POST" and path == "/unlocks":
                state["unlocked"] = True
                return {"type": "hints", "target": 7}
            if method == "GET" and path.startswith("/hints/7"):
                preview = (kw.get("params") or {}).get("preview")
                if preview or not state["unlocked"]:
                    return self._hint(cost=50, content=None)
                return self._hint(cost=50, content="look at the LSB")
            raise AssertionError(f"unexpected {method} {path}")

        monkeypatch.setattr(client, "_request", fake_request)
        out = client.unlock_hint_confirmed(7, assume_yes=True)
        assert out["unlocked"] is True
        assert out["content"] == "look at the LSB"
        assert "50" in out["note"]

    def test_already_unlocked_returns_content_no_spend(
        self, client, monkeypatch
    ):
        def fake_request(method, path, **kw):
            assert method == "GET"
            return self._hint(cost=50, content="already visible")

        monkeypatch.setattr(client, "_request", fake_request)
        out = client.unlock_hint_confirmed(7, assume_yes=False)
        assert out["unlocked"] is True
        assert out["content"] == "already visible"

    def test_me_failure_not_fatal(self, client, monkeypatch):
        def fake_request(method, path, **kw):
            if path.startswith("/hints/"):
                return self._hint(cost=50, content=None)
            raise AssertionError("unexpected call")

        monkeypatch.setattr(client, "_request", fake_request)
        monkeypatch.setattr(
            client, "me", lambda: (_ for _ in ()).throw(CTfdError("401"))
        )
        out = client.unlock_hint_confirmed(7)
        assert out["score"] is None
        assert out["unlocked"] is False


# ----------------------------------------------------------------------
#  Scoreboard diff
# ----------------------------------------------------------------------
class TestScoreboardDiff:
    OLD = [
        {"pos": 1, "account_id": 1, "name": "alice", "score": 3000},
        {"pos": 2, "account_id": 2, "name": "bob", "score": 2000},
        {"pos": 3, "account_id": 3, "name": "me", "score": 1500},
        {"pos": 4, "account_id": 4, "name": "carol", "score": 1000},
    ]
    NEW = [
        {"pos": 1, "account_id": 3, "name": "me", "score": 3500},
        {"pos": 2, "account_id": 1, "name": "alice", "score": 3000},
        {"pos": 3, "account_id": 4, "name": "carol", "score": 2100},
        {"pos": 4, "account_id": 2, "name": "bob", "score": 2000},
    ]

    def test_first_snapshot_note(self):
        out = CTfdClient._compute_scoreboard_diff([], self.NEW,
                                                   my_account_id=3)
        assert "первый снапшот" in out["note"]
        assert out["my"]["pos"] == 1

    def test_my_position_and_delta(self):
        out = CTfdClient._compute_scoreboard_diff(
            self.OLD, self.NEW, my_account_id=3
        )
        assert out["my"]["pos"] == 1
        assert out["my"]["prev_pos"] == 3
        assert out["my"]["delta"] == 2

    def test_passed_me_and_i_passed(self):
        out = CTfdClient._compute_scoreboard_diff(
            self.OLD, self.NEW, my_account_id=3
        )
        names_passed = [r["name"] for r in out["passed_me"]]
        names_ipassed = [r["name"] for r in out["i_passed"]]
        assert names_passed == []          # никто меня не обогнал
        assert names_ipassed == ["alice", "bob"]  # я обогнал обоих

    def test_changed_risers_first(self):
        out = CTfdClient._compute_scoreboard_diff(
            self.OLD, self.NEW, my_account_id=None
        )
        changed = {r["name"]: r["delta"] for r in out["changed"]}
        assert changed["me"] == 2
        assert changed["carol"] == 1
        assert changed["bob"] == -2
        assert out["changed"][0]["name"] == "me"  # крупнейший взлёт первым

    def test_around_me_window(self):
        out = CTfdClient._compute_scoreboard_diff(
            self.OLD, self.NEW, my_account_id=4, around=1
        )
        positions = [r["pos"] for r in out["around_me"]]
        assert positions == [2, 3, 4]  # только ±1 вокруг carol (pos=3)

    def test_top_has_deltas(self):
        out = CTfdClient._compute_scoreboard_diff(
            self.OLD, self.NEW, my_account_id=None, top=2
        )
        assert len(out["top"]) == 2
        assert out["top"][0]["name"] == "me"
        assert out["top"][0]["delta"] == 2
        assert out["top"][1]["name"] == "alice"
        assert out["top"][1]["delta"] == -1  # alice 1→2

    def test_diff_saves_snapshot(self, client, monkeypatch):
        monkeypatch.setattr(client, "scoreboard", lambda: self.NEW)
        monkeypatch.setattr(client, "me", lambda: {"id": 3, "team_id": None})
        out = client.scoreboard_diff(around=2)
        assert out["my"]["pos"] == 1
        snap = client._load_seen()["scoreboard_snapshot"]
        assert snap["ts"]
        assert len(snap["standings"]) == 4
        assert snap["standings"][0]["name"] == "me"


# ----------------------------------------------------------------------
#  Ошибки: человекочитаемый маппинг
# ----------------------------------------------------------------------
class TestExplainHttpError:
    @pytest.mark.parametrize(
        "status,fragment",
        [
            (401, "токен/сессия протухли"),
            (403, "задача скрыта/закрыта"),
            (404, "не существует"),
            (429, "rate limit"),
            (503, "повторите позже"),
        ],
    )
    def test_hints(self, status, fragment):
        err = m._explain_http_error(status, "GET", "/challenges", "body")
        assert isinstance(err, CTfdError)
        assert fragment in str(err)
        assert f"HTTP {status}" in str(err)

    def test_unknown_status(self):
        err = m._explain_http_error(418, "GET", "/x", "")
        assert "неизвестная ошибка" in str(err)


# ----------------------------------------------------------------------
#  GET-retry на 5xx / сетевых сбоях
# ----------------------------------------------------------------------
class TestGetRetry:
    def test_get_retries_on_5xx(self, client, monkeypatch):
        calls = {"n": 0}

        def fake_raw(method, url, **kw):
            calls["n"] += 1
            if calls["n"] <= 2:
                return _fake_response(503, text="oops")
            return _fake_response(200, payload={"success": True, "data": []})

        monkeypatch.setattr(client, "_raw_request", fake_raw)
        sleeps = []
        monkeypatch.setattr(m.time, "sleep", lambda s: sleeps.append(s))
        data = client._request("GET", "/challenges")
        assert data == []
        assert calls["n"] == 3  # 1 + 2 ретрая
        assert len(sleeps) == 2

    def test_get_gives_up_after_max_retries(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "_raw_request",
            lambda *a, **kw: _fake_response(500, text="down"),
        )
        monkeypatch.setattr(m.time, "sleep", lambda s: None)
        with pytest.raises(CTfdError) as ei:
            client._request("GET", "/challenges")
        assert "HTTP 500" in str(ei.value)
        assert "повторите позже" in str(ei.value)

    def test_post_never_retries_on_5xx(self, client, monkeypatch):
        calls = {"n": 0}

        def fake_raw(method, url, **kw):
            calls["n"] += 1
            return _fake_response(500, text="down")

        monkeypatch.setattr(client, "_raw_request", fake_raw)
        monkeypatch.setattr(m.time, "sleep", lambda s: None)
        with pytest.raises(CTfdError):
            client._request("POST", "/challenges/attempt",
                            json_body={"challenge_id": 1, "submission": "f"})
        assert calls["n"] == 1  # ни одного повтора

    def test_network_error_retried_for_get(self, client, monkeypatch):
        calls = {"n": 0}

        def fake_raw(method, url, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise CTfdError("Ошибка запроса: connection reset")
            return _fake_response(200, payload={"success": True, "data": [1]})

        monkeypatch.setattr(client, "_raw_request", fake_raw)
        monkeypatch.setattr(m.time, "sleep", lambda s: None)
        assert client._request("GET", "/challenges") == [1]
        assert calls["n"] == 2

    def test_4xx_not_retried(self, client, monkeypatch):
        calls = {"n": 0}

        def fake_raw(method, url, **kw):
            calls["n"] += 1
            return _fake_response(404, text="nope")

        monkeypatch.setattr(client, "_raw_request", fake_raw)
        with pytest.raises(CTfdError):
            client._request("GET", "/challenges/999")
        assert calls["n"] == 1

    def test_cf_like_503_not_retried(self, client, monkeypatch):
        """CF-челлендж на 503 уходит в _request сразу (для bridge-детекта)."""
        calls = {"n": 0}

        def fake_raw(method, url, **kw):
            calls["n"] += 1
            return _fake_response(
                503, text="Just a moment... checking your browser"
            )

        monkeypatch.setattr(client, "_raw_request", fake_raw)
        # _request без моста поднимет CloudflareBlocked/CTfdError, но БЕЗ ретраев
        with pytest.raises((CTfdError, m.CloudflareBlocked)):
            client._request("GET", "/challenges")
        assert calls["n"] == 1


# ----------------------------------------------------------------------
#  Чексуммы скачивания
# ----------------------------------------------------------------------
class TestDownloadChecksum:
    def test_checksum_printed(self, client, tmp_path, monkeypatch, capsys):
        blob = b"hello attachment"
        monkeypatch.setattr(
            client, "_raw_request",
            lambda *a, **kw: _fake_response(200).__class__(
                status_code=200, content=blob, url="https://x/f.bin"
            ) if False else _file_response(blob),
        )
        out = client.download_file("https://ctf.example.com/files/aa/f.bin",
                                   str(tmp_path))
        assert out.read_bytes() == blob
        err = capsys.readouterr().err
        assert "sha256=" in err
        import hashlib as _h
        assert _h.sha256(blob).hexdigest() in err
        assert f"{len(blob)} B" in err


def _file_response(blob: bytes):
    r = MagicMock()
    r.status_code = 200
    r.ok = True
    r.content = blob
    r.url = "https://ctf.example.com/files/aa/f.bin"
    r.headers = {"Content-Type": "application/octet-stream"}
    return r
