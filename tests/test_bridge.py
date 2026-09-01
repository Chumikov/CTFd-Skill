"""Тесты browser-bridge (CDP), Cloudflare-детекта и смежных фич.

Без сети: транспорт мокается фейковыми response-объектами и FakeCDPBridge.

Покрывает:
    - CLI: --host/--token до И после сабкоманды
    - _looks_like_cloudflare (маркеры CF, ложно-позитивы)
    - _BridgeResponse (адаптер ответа моста)
    - CDPBridge.http (генерация JS + разбор результата, binary base64)
    - CTfdClient через мост: envelope, 429-retry, CF от моста
    - авто-переключение auto → CDP при CloudflareBlocked
    - download_file через мост (base64)
    - скор-верификация после correct (scored)
    - list_events (детектор расползания воркспейсов)
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

# Делаем scripts/ импортируемым.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import ctfd_client as m  # noqa: E402
from ctfd_client import (
    CTfdClient,
    CDPBridge,
    CloudflareBlocked,
    RateLimited,
    SubmitResult,
    _BridgeResponse,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Изолируем тесты от внешних env-переменных транспорта."""
    monkeypatch.delenv("CTFD_BRIDGE", raising=False)
    monkeypatch.delenv("CTFD_CDP_URL", raising=False)


# ----------------------------------------------------------------------
#  Фейковые response/bridge
# ----------------------------------------------------------------------
class FakeResponse:
    """Минимальный response для _request (как requests/httpx)."""

    def __init__(self, status=200, payload=None, text="", ctype="application/json"):
        self.status_code = status
        self._payload = payload
        self._text = text
        self.headers = {"Content-Type": ctype}
        self.url = "https://ctf.example.com/api/v1/x"
        self.content = (
            json.dumps(payload).encode() if payload is not None else text.encode()
        )

    @property
    def text(self):
        if self._payload is not None:
            return json.dumps(self._payload)
        return self._text

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


CF_HTML = (
    "<!DOCTYPE html><html><head><title>Just a moment...</title>"
    "<script src='/cdn-cgi/challenge-platform/h/b/orchestrate'></script>"
    "</head><body>Verifying you are human...</body></html>"
)


def _envelope(data):
    return {"status": 200, "ct": "application/json",
            "body": json.dumps({"success": True, "data": data})}


class FakeBridge:
    """Заглушка CDPBridge: отвечает заготовками по очереди, помнит вызовы."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []
        self.target = {"url": "https://ctf.example.com/challenges"}

    def connect(self):
        return self.target

    def http(self, method, url, *, headers=None, body=None, binary=False):
        self.calls.append(
            {"method": method, "url": url, "headers": headers,
             "body": body, "binary": binary}
        )
        if self.responses:
            item = self.responses.pop(0)
            return item if isinstance(item, dict) else item()
        raise AssertionError("FakeBridge: нет заготовленного ответа")


class FakeCDPBridgeClass:
    """Подмена класса m.CDPBridge для тестов авто-переключения."""

    instances = []

    def __init__(self, endpoint=None, *, host=None, timeout=30.0):
        self.host = host
        self.timeout = timeout
        self.bridge = FakeBridge()
        self.target = self.bridge.target
        FakeCDPBridgeClass.instances.append(self)

    def connect(self):
        return self.target

    def http(self, method, url, *, headers=None, body=None, binary=False):
        return self.bridge.http(
            method, url, headers=headers, body=body, binary=binary
        )


def _client_with_bridge(bridge, host="https://ctf.example.com"):
    c = CTfdClient(host, token="ctfd_x")
    c._bridge = bridge
    return c


# ----------------------------------------------------------------------
#  CLI: --host/--token до и после сабкоманды
# ----------------------------------------------------------------------
class TestCLIGlobalArgsOrder:
    def test_after_subcommand(self):
        args = m._build_parser().parse_args(
            ["challenges", "--host", "https://h1", "--token", "t1"]
        )
        assert args.host == "https://h1"
        assert args.token == "t1"
        assert args.cmd == "challenges"

    def test_before_subcommand(self):
        args = m._build_parser().parse_args(
            ["--host", "https://h2", "--token", "t2", "challenges"]
        )
        assert args.host == "https://h2"
        assert args.token == "t2"

    def test_submit_after_subcommand(self):
        args = m._build_parser().parse_args(
            ["submit", "42", "flag{x}", "--host", "https://h3", "--token", "t3"]
        )
        assert args.cmd == "submit"
        assert args.id == 42
        assert args.flag == "flag{x}"
        assert args.host == "https://h3"
        assert args.token == "t3"

    def test_events_parser(self):
        args = m._build_parser().parse_args(
            ["events", "--base", "/tmp/xyz", "--host", "https://h"]
        )
        assert args.cmd == "events"
        assert args.base == "/tmp/xyz"
        assert args.host == "https://h"

    def test_before_wins_when_only_before(self):
        args = m._build_parser().parse_args(
            ["--token", "t-global", "me"]
        )
        assert args.token == "t-global"

    def test_all_subcommands_have_conn_args(self):
        parser = m._build_parser()
        for name, sp in parser._subparsers._group_actions[0].choices.items():
            opts = {a for a in sp._option_string_actions}
            assert "--host" in opts, f"{name} lacks --host"
            assert "--token" in opts, f"{name} lacks --token"


# ----------------------------------------------------------------------
#  Cloudflare-детект
# ----------------------------------------------------------------------
class TestCloudflareDetect:
    def test_403_challenge_page(self):
        r = FakeResponse(403, text=CF_HTML, ctype="text/html")
        assert m._looks_like_cloudflare(r) is True

    def test_503_challenge_page(self):
        r = FakeResponse(503, text=CF_HTML.replace("Just a moment", "Attention Required!"))
        assert m._looks_like_cloudflare(r) is True

    def test_json_403_not_cf(self):
        r = FakeResponse(403, payload={"success": False})
        assert m._looks_like_cloudflare(r) is False

    def test_200_challenge_page_detected(self):
        r = FakeResponse(200, text=CF_HTML, ctype="text/html")
        assert m._looks_like_cloudflare(r) is True

    def test_word_cloudflare_alone_is_not_a_marker(self):
        # Голое слово cloudflare в контенте задачи — НЕ CF-челлендж.
        r = FakeResponse(200, text="the challenge site sits behind cloudflare waf")
        assert m._looks_like_cloudflare(r) is False

    def test_404_never_cf(self):
        r = FakeResponse(404, text=CF_HTML)
        assert m._looks_like_cloudflare(r) is False

    def test_broken_response_object(self):
        class Broken:
            status_code = "x"  # сломается в int()

        assert m._looks_like_cloudflare(Broken()) is False

    def test_bridge_response_detected(self):
        r = _BridgeResponse(403, CF_HTML.encode(), "https://x", "text/html")
        assert m._looks_like_cloudflare(r) is True

    def test_exception_class_exported(self):
        assert issubclass(CloudflareBlocked, m.CTfdError)


# ----------------------------------------------------------------------
#  _BridgeResponse
# ----------------------------------------------------------------------
class TestBridgeResponse:
    def test_ok_and_status(self):
        r = _BridgeResponse(200, b"{}", "https://x")
        assert r.ok is True
        assert r.status_code == 200

    def test_error_status(self):
        r = _BridgeResponse(404, b"nope", "https://x")
        assert r.ok is False

    def test_text_json_headers(self):
        r = _BridgeResponse(200, b'{"a": 1}', "https://x", "application/json")
        assert r.text == '{"a": 1}'
        assert r.json() == {"a": 1}
        assert r.headers.get("Content-Type") == "application/json"


# ----------------------------------------------------------------------
#  CDPBridge.http (JS-сборка + разбор, без сети)
# ----------------------------------------------------------------------
class TestCDPBridgeHttp:
    def _bridge(self, evaluate_result):
        class _B(CDPBridge):
            def __init__(self):
                self.js = None
                self.endpoint = "http://127.0.0.1:9222"
                self.host = None
                self.timeout = 5.0

            def evaluate(self, expression):
                self.js = expression
                return evaluate_result

        return _B()

    def test_text_response(self):
        b = self._bridge(json.dumps({"status": 200, "ct": "application/json",
                                     "body": "{\"success\": true}"}))
        out = b.http("get", "https://x/api/v1/challenges")
        assert out["status"] == 200
        assert out["body"] == '{"success": true}'

    def test_binary_response(self):
        payload = base64.b64encode(b"PK\x03\x04zipdata").decode()
        b = self._bridge(json.dumps({"status": 200, "ct": "application/zip",
                                     "body": payload}))
        out = b.http("GET", "https://x/files/f", binary=True)
        assert base64.b64decode(out["body"]) == b"PK\x03\x04zipdata"

    def test_js_shape(self):
        b = self._bridge(json.dumps({"status": 200, "ct": "", "body": ""}))
        b.http("POST", "https://x/api/v1/challenges/attempt",
               headers={"Authorization": "Token t"}, body='{"a":1}')
        js = b.js
        assert "await fetch(" in js
        assert "credentials" in js and "include" in js
        assert "if (false)" in js  # не binary → base64-ветка мертва

    def test_js_binary_branch(self):
        b = self._bridge(json.dumps({"status": 200, "ct": "", "body": ""}))
        b.http("GET", "https://x/files/f", binary=True)
        assert "if (true)" in b.js
        assert "btoa" in b.js
        assert "arrayBuffer" in b.js

    def test_evaluate_exception_reraised(self):
        class _Err(CDPBridge):
            def __init__(self):
                self.endpoint = "http://127.0.0.1:9222"
                self.host = None
                self.timeout = 5.0

            def evaluate(self, expression):
                raise m.CTfdError("CDP evaluate failed: TypeError: boom")

        with pytest.raises(m.CTfdError, match="boom"):
            _Err().http("GET", "https://x")


# ----------------------------------------------------------------------
#  CTfdClient через мост
# ----------------------------------------------------------------------
class TestClientViaBridge:
    def test_list_challenges_envelope(self):
        chals = [{"id": 1, "name": "A"}]
        b = FakeBridge([_envelope(chals)])
        c = _client_with_bridge(b)
        out = c.list_challenges(update_seen=False, poll_notifications=False)
        assert out == chals
        # запрос ушёл через fetch-транспорт с auth-заголовком
        call = b.calls[0]
        assert call["method"] == "GET"
        assert call["url"].endswith("/api/v1/challenges")
        assert call["headers"]["Authorization"] == "Token ctfd_x"

    def test_attempt_correct_with_scored_true(self):
        b = FakeBridge([
            _envelope({"status": "correct", "message": "+100"}),
            _envelope([{"challenge_id": 42, "value": 100}]),
        ])
        c = _client_with_bridge(b)
        v = c.attempt(42, "flag{x}")
        assert v.correct is True
        assert v["scored"] is True
        # второй вызов — GET /users/me/solves
        assert "/users/me/solves" in b.calls[1]["url"]

    def test_attempt_correct_scored_false_warns(self, capsys, tmp_path):
        b = FakeBridge([
            _envelope({"status": "correct", "message": "+100"}),
            _envelope([]),  # my_solves пуст — solve не попал в скор
        ])
        c = _client_with_bridge(b)
        v = c.attempt(42, "flag{x}")
        assert v["scored"] is False
        err = capsys.readouterr().err
        assert "freeze" in err.lower() or "заморозк" in err.lower()

    def test_attempt_score_verification_failure_is_silent(self, capsys):
        b = FakeBridge([
            _envelope({"status": "correct", "message": "+100"}),
            {"status": 500, "ct": "text/plain", "body": "boom"},
        ])
        c = _client_with_bridge(b)
        v = c.attempt(42, "flag{x}")
        assert v.correct is True
        assert "scored" not in v  # проверка не удалась — поля нет
        assert "skipped" in capsys.readouterr().err

    def test_attempt_verify_disabled(self):
        b = FakeBridge([_envelope({"status": "correct", "message": "+100"})])
        c = _client_with_bridge(b)
        v = c.attempt(42, "flag{x}", verify_score=False)
        assert v.correct is True
        assert "scored" not in v
        assert len(b.calls) == 1  # my_solves не запрашивался

    def test_attempt_incorrect_no_verify(self):
        b = FakeBridge([_envelope({"status": "incorrect", "message": "no"})])
        c = _client_with_bridge(b)
        v = c.attempt(42, "flag{x}")
        assert v.incorrect is True
        assert len(b.calls) == 1

    def test_429_through_bridge_retries_once(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(m.time, "sleep", lambda s: sleeps.append(s))
        b = FakeBridge([
            {"status": 429, "ct": "application/json",
             "body": json.dumps({"success": False, "data": {"message": "Wait 2 seconds"}})},
            _envelope({"status": "incorrect", "message": "try again"}),
        ])
        c = _client_with_bridge(b)
        v = c.attempt(42, "flag{x}")
        assert v.incorrect is True
        assert sleeps and sleeps[0] >= 3  # wait + 1
        assert len(b.calls) == 2  # retry через мост

    def test_cf_from_bridge_raises_with_hint(self):
        b = FakeBridge([{"status": 403, "ct": "text/html", "body": CF_HTML}])
        c = _client_with_bridge(b)
        with pytest.raises(CloudflareBlocked, match="пройдите|Cloudflare"):
            c.list_challenges(update_seen=False, poll_notifications=False)

    def test_form_data_via_bridge_rejected(self):
        b = FakeBridge([])
        c = _client_with_bridge(b)
        with pytest.raises(m.CTfdError, match="form-data"):
            c._request("POST", "/login", data={"name": "x"})


# ----------------------------------------------------------------------
#  Авто-переключение auto → CDP
# ----------------------------------------------------------------------
class TestAutoSwitch:
    def _cf_session_response(self):
        return FakeResponse(403, text=CF_HTML, ctype="text/html")

    def test_switch_on_cf(self, monkeypatch):
        FakeCDPBridgeClass.instances = []
        monkeypatch.setattr(m, "CDPBridge", FakeCDPBridgeClass)
        c = CTfdClient("https://ctf.example.com", token="ctfd_x")
        assert c._bridge_mode == "auto"
        monkeypatch.setattr(
            c.session, "request", lambda *a, **kw: self._cf_session_response()
        )
        chals = [{"id": 7, "name": "B"}]

        def _http(self, method, url, *, headers=None, body=None, binary=False):
            return _envelope(chals)

        monkeypatch.setattr(FakeCDPBridgeClass, "http", _http)
        out = c.list_challenges(update_seen=False, poll_notifications=False)
        assert out == chals
        assert c._bridge is not None  # переключились навсегда

    def test_no_switch_in_off_mode(self, monkeypatch):
        c = CTfdClient("https://ctf.example.com", token="ctfd_x", bridge="off")
        monkeypatch.setattr(
            c.session, "request", lambda *a, **kw: self._cf_session_response()
        )
        with pytest.raises(CloudflareBlocked, match="CTFD_BRIDGE=cdp"):
            c._request("GET", "/challenges")

    def test_switch_fails_when_cdp_down(self, monkeypatch, capsys):
        class DeadBridge:
            def __init__(self, *a, **kw):
                raise m.CTfdError("CDP: нет открытых вкладок")

        monkeypatch.setattr(m, "CDPBridge", DeadBridge)
        c = CTfdClient("https://ctf.example.com", token="ctfd_x")
        monkeypatch.setattr(
            c.session, "request", lambda *a, **kw: self._cf_session_response()
        )
        with pytest.raises(CloudflareBlocked):
            c._request("GET", "/challenges")
        assert "CDP bridge unavailable" in capsys.readouterr().err

    def test_cdp_mode_uses_bridge_from_start(self, monkeypatch):
        calls = []

        class InstantBridge(FakeCDPBridgeClass):
            def http(self, method, url, *, headers=None, body=None, binary=False):
                calls.append(url)
                return _envelope([{"id": 1}])

        monkeypatch.setattr(m, "CDPBridge", InstantBridge)
        c = CTfdClient("https://ctf.example.com", token="ctfd_x", bridge="cdp")
        session_calls = []
        monkeypatch.setattr(
            c.session, "request", lambda *a, **kw: session_calls.append(a)
        )
        out = c.list_challenges(update_seen=False, poll_notifications=False)
        assert out == [{"id": 1}]
        assert calls and not session_calls

    def test_env_bridge_mode(self, monkeypatch):
        monkeypatch.setenv("CTFD_BRIDGE", "off")
        c = CTfdClient("https://ctf.example.com")
        assert c._bridge_mode == "off"
        monkeypatch.setenv("CTFD_BRIDGE", "requests")
        c2 = CTfdClient("https://ctf.example.com")
        assert c2._bridge_mode == "off"
        monkeypatch.setenv("CTFD_BRIDGE", "bogus")
        with pytest.raises(m.CTfdError, match="bridge"):
            CTfdClient("https://ctf.example.com")


# ----------------------------------------------------------------------
#  download_file через мост
# ----------------------------------------------------------------------
class TestDownloadViaBridge:
    def test_binary_download(self, tmp_path):
        data = b"PK\x03\x04fake-zip-content"
        b = FakeBridge([
            {"status": 200, "ct": "application/zip",
             "body": base64.b64encode(data).decode()},
        ])
        c = _client_with_bridge(b)
        c._active_ws = None
        out = c.download_file("https://ctf.example.com/files/abc/chal.zip",
                              dest_dir=str(tmp_path))
        assert out.read_bytes() == data
        assert b.calls[0]["binary"] is True

    def test_download_cf_no_switch_in_off(self, monkeypatch, tmp_path):
        c = CTfdClient("https://ctf.example.com", token="ctfd_x", bridge="off")
        monkeypatch.setattr(
            c.session, "request",
            lambda *a, **kw: FakeResponse(403, text=CF_HTML, ctype="text/html"),
        )
        with pytest.raises(CloudflareBlocked):
            c.download_file("https://ctf.example.com/files/abc/f.bin",
                            dest_dir=str(tmp_path))


# ----------------------------------------------------------------------
#  list_events
# ----------------------------------------------------------------------
class TestListEvents:
    def _mk(self, root, event, category, slug, cid, solved, host="https://ctf.example.com"):
        ws = root / event / category / slug
        ws.mkdir(parents=True)
        (ws / "challenge.json").write_text(json.dumps({
            "id": cid, "name": slug, "solved": solved, "host": host,
        }))

    def test_two_events_detected(self, tmp_path):
        self._mk(tmp_path, "thjcc-summer-2026", "web", "login", 1, True)
        self._mk(tmp_path, "thjcc-summer-2026", "crypto", "rsa", 2, False)
        self._mk(tmp_path, "thjcc-2026-summer", "web", "login", 1, True)
        c = CTfdClient("https://ctf.example.com", token="ctfd_x")
        out = c.list_events(base=str(tmp_path))
        names = [e["event"] for e in out]
        assert names == ["thjcc-2026-summer", "thjcc-summer-2026"]
        by = {e["event"]: e for e in out}
        assert by["thjcc-summer-2026"]["workspaces"] == 2
        assert by["thjcc-summer-2026"]["solved"] == 1
        assert by["thjcc-summer-2026"]["host"] == "https://ctf.example.com"

    def test_empty_base(self, tmp_path):
        c = CTfdClient("https://ctf.example.com")
        assert c.list_events(base=str(tmp_path / "missing")) == []

    def test_legacy_yaml_counted(self, tmp_path):
        ws = tmp_path / "legacy-2026" / "misc" / "old"
        ws.mkdir(parents=True)
        (ws / "challenge.yaml").write_text("id: 5\n")
        c = CTfdClient("https://ctf.example.com")
        out = c.list_events(base=str(tmp_path))
        assert out[0]["workspaces"] == 1


# ----------------------------------------------------------------------
#  CLI main(): порядок аргументов + events (без сети)
# ----------------------------------------------------------------------
class TestCliMain:
    def test_submit_with_args_after_subcommand(self, monkeypatch, capsys):
        captured = {}

        class FakeClient:
            def __init__(self, host, token=None, proxy=None):
                captured["host"] = host
                captured["token"] = token
                captured["proxy"] = proxy

            def attempt(self, cid, flag, **kw):
                captured["attempt"] = (cid, flag)
                return SubmitResult({"status": "correct", "message": "ok",
                                     "scored": True})

        monkeypatch.setattr(m, "CTfdClient", FakeClient)
        rc = m.main(["submit", "42", "flag{x}",
                     "--host", "https://cli.example.com", "--token", "ctfd_cli"])
        assert rc == 0
        assert captured["host"] == "https://cli.example.com"
        assert captured["token"] == "ctfd_cli"
        assert captured["attempt"] == (42, "flag{x}")
        assert '"scored": true' in capsys.readouterr().out

    def test_events_no_token_required(self, monkeypatch, capsys, tmp_path):
        monkeypatch.delenv("CTFD_HOST", raising=False)
        monkeypatch.delenv("CTFD_TOKEN", raising=False)
        monkeypatch.setenv("CTFD_HOST", "https://x")  # host нужен для клиента
        out = m.main(["events", "--base", str(tmp_path), "--host", "https://x"])
        assert out == 0
        assert "[]" in capsys.readouterr().out

    def test_events_offline_without_host(self, monkeypatch, tmp_path):
        monkeypatch.delenv("CTFD_HOST", raising=False)
        monkeypatch.delenv("CTFD_TOKEN", raising=False)
        with pytest.raises(SystemExit):
            m.main(["events", "--base", str(tmp_path)])
