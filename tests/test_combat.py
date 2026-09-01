"""Тесты «боевого воркфлоу» (вынесено из пост-мортема).

Без сети: транспорт мокается. Покрывает:
    - submit_queue: разбор файла очереди, статусы, атомарная перезапись,
      несдача конечных статусов повторно
    - container_request / container_renew (пути и тела запросов)
    - event_dump: файлы all_challenges.json / unsolved.txt / flags.txt
    - preflight: direct_api (CF/не CF), token, containers_plugin
    - snapshot: markdown с секциями и хвостом PROGRESS.md
    - CLI: --proxy доходит до клиента
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import ctfd_client as m  # noqa: E402
from ctfd_client import CTfdClient, CTfdError, SubmitResult  # noqa: E402


@pytest.fixture()
def c(tmp_path):
    client = CTfdClient("https://ctf.example.com", token="ctfd_test")
    return client


# ---------------------------------------------------------------- submit_queue
def test_submit_queue_rewrites_and_stops_final(c, tmp_path, monkeypatch):
    q = tmp_path / "flags.txt"
    q.write_text(
        "# comment\n"
        "11|FLAG_A|pending\n"
        "22|FLAG_B|pending\n"
        "33|FLAG_C|correct\n"
        "garbage line\n",
        encoding="utf-8",
    )
    calls = []

    def fake_attempt(cid, flag, **kw):
        calls.append((cid, flag))
        if cid == 11:
            return SubmitResult({"status": "correct", "message": "ok"})
        if cid == 22:
            return SubmitResult({"status": "incorrect", "message": "nope"})
        raise AssertionError("final status must not be resubmitted")

    monkeypatch.setattr(c, "attempt", fake_attempt)
    summary = c.submit_queue(str(q))
    assert calls == [(11, "FLAG_A"), (22, "FLAG_B")]
    assert summary["correct"] == 2  # 11 стал correct + 33 уже был correct
    assert summary["incorrect"] == 1
    text = q.read_text(encoding="utf-8")
    assert "11|FLAG_A|correct" in text
    assert "22|FLAG_B|incorrect" in text
    assert "33|FLAG_C|correct" in text  # не тронули
    assert "garbage line" in text  # мусорные строки сохранены как есть
    assert summary["all_clear"] is False


def test_submit_queue_all_clear(c, tmp_path, monkeypatch):
    q = tmp_path / "flags.txt"
    q.write_text("7|FLAG_X|pending\n", encoding="utf-8")
    monkeypatch.setattr(
        c, "attempt", lambda cid, flag, **kw: SubmitResult(
            {"status": "already_solved", "message": "dup"})
    )
    summary = c.submit_queue(str(q))
    assert summary["all_clear"] is True
    assert "7|FLAG_X|already_solved" in q.read_text(encoding="utf-8")


def test_submit_queue_error_keeps_going(c, tmp_path, monkeypatch):
    q = tmp_path / "flags.txt"
    q.write_text("1|A|pending\n2|B|pending\n", encoding="utf-8")

    def fake_attempt(cid, flag, **kw):
        raise CTfdError("network down")

    monkeypatch.setattr(c, "attempt", fake_attempt)
    summary = c.submit_queue(str(q))
    assert summary["error"] == 2
    assert "1|A|error" in q.read_text(encoding="utf-8")


def test_submit_queue_missing_file(c):
    with pytest.raises(CTfdError):
        c.submit_queue("/nonexistent/flags.txt")


# ------------------------------------------------------------- containers
def test_container_request(c, monkeypatch):
    seen = {}

    def fake_request(method, path, **kw):
        seen["method"], seen["path"], seen["json"] = method, path, kw
        return {"connection": {"host": "1.2.3.4", "port": 30019, "type": "http"},
                "instance_uuid": "u-1", "expires_at": 123}

    monkeypatch.setattr(c, "_request", fake_request)
    out = c.container_request(18)
    assert seen == {"method": "POST", "path": "/containers/request",
                    "json": {"json_body": {"challenge_id": 18}}}
    assert out["instance_uuid"] == "u-1"


def test_container_renew(c, monkeypatch):
    seen = {}

    def fake_request(method, path, **kw):
        seen["path"] = path
        return {"ok": True}

    monkeypatch.setattr(c, "_request", fake_request)
    c.container_renew("uuid-42")
    assert seen["path"] == "/containers/renew"


def test_container_renew_404_hint(c, monkeypatch):
    def fake_request(method, path, **kw):
        raise CTfdError("HTTP 404")

    monkeypatch.setattr(c, "_request", fake_request)
    with pytest.raises(CTfdError, match="container_request"):
        c.container_renew("uuid-42")


# ------------------------------------------------------------------ dump
def test_event_dump_files(c, tmp_path, monkeypatch):
    chals = [
        {"id": 1, "name": "easy", "value": 100, "solved_by_me": True,
         "category": "web", "description": "d", "files": []},
        {"id": 2, "name": "hard", "value": 500, "solved_by_me": False,
         "category": "pwn", "description": "d2", "files": ["/files/x.zip"]},
    ]
    monkeypatch.setattr(
        c, "list_challenges", lambda **kw: chals
    )
    monkeypatch.setattr(c, "me", lambda: {"name": "tester"})
    out = tmp_path / "ws"
    summary = c.event_dump(str(out))
    data = json.loads((out / "all_challenges.json").read_text(encoding="utf-8"))
    assert data["user"] == "tester"
    assert [x["id"] for x in data["challenges"]] == [1, 2]
    unsolved = (out / "unsolved.txt").read_text(encoding="utf-8")
    assert "2\thard" in unsolved and "easy" not in unsolved
    assert (out / "flags.txt").exists()
    assert summary["points_solved"] == 100
    assert summary["points_available"] == 600


def test_event_dump_docstring_tmp_rule(c):
    """Докстринг dump предписывает tmp/ ВНУТРИ папки события, не системный /tmp."""
    doc = CTfdClient.event_dump.__doc__ or ""
    assert "внутри папки события" in doc
    assert "/tmp вычищается" in doc


# -------------------------------------------------------------- preflight
def test_preflight_ok(c, monkeypatch):
    class R:
        status_code = 200
        ok = True
        text = '{"success": true}'

        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(m.requests, "get", lambda *a, **k: R())
    monkeypatch.setattr(c, "me", lambda: {"name": "tester"})
    res = c.preflight()
    assert res["ok"] is True
    assert res["direct_api"]["cloudflare"] is False
    assert res["token"]["ok"] is True
    assert res["token"]["user"] == "tester"


def test_preflight_cloudflare(c, monkeypatch):
    class R:
        status_code = 403
        ok = False
        text = "<title>Just a moment...</title>"

    monkeypatch.setattr(m.requests, "get", lambda *a, **k: R())

    def boom():
        raise m.CloudflareBlocked("blocked")

    monkeypatch.setattr(c, "me", boom)
    res = c.preflight()
    assert res["direct_api"]["cloudflare"] is True
    assert res["token"]["ok"] is False
    assert res["ok"] is False
    assert "cloudflare_note" in res


# ---------------------------------------------------------------- snapshot
def test_snapshot_markdown(c, tmp_path, monkeypatch):
    chals = [
        {"id": 1, "name": "easy", "value": 100, "solved_by_me": True,
         "category": "web"},
        {"id": 2, "name": "hard", "value": 500, "solved_by_me": False,
         "category": "pwn"},
    ]
    monkeypatch.setattr(c, "list_challenges", lambda **kw: chals)
    monkeypatch.setattr(c, "me", lambda: {"name": "tester"})
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "flags.txt").write_text("2|FLAG_H|pending\n", encoding="utf-8")
    (ws / "PROGRESS.md").write_text("# PROG\nline1\nline2\n", encoding="utf-8")
    md = c.snapshot(str(ws))
    assert "Решено: 1 задач" in md
    assert "[2] hard (500)" in md
    assert "Несданные флаги в очереди" in md
    assert "2|FLAG_H|pending" in md
    assert "## Хвост PROGRESS.md" in md
    assert "line2" in md


# --------------------------------------------------------------- CLI proxy
def test_cli_proxy_passthrough(monkeypatch):
    captured = {}

    class FakeClient:
        def __init__(self, host, token=None, proxy=None):
            captured.update(host=host, token=token, proxy=proxy)

        def preflight(self):
            return {"ok": True}

    monkeypatch.setattr(m, "CTfdClient", FakeClient)
    rc = m.main(["preflight", "--host", "https://x.example.com",
                 "--token", "t", "--proxy", "socks5://127.0.0.1:9999"])
    assert rc == 0
    assert captured["proxy"] == "socks5://127.0.0.1:9999"
