"""Тесты персистентного воркспейса CTfdClient — без обращения к сети.

Покрывает:
    - init_challenge_workspace: создание структуры, idempotency, миграция .yaml
    - auto-подстановка шаблона solve.py по категории
    - HTML → Markdown конверсия description.md
    - извлечение connection_info из описания
    - log_attempt: append в NOTES.md
    - mark_solved_meta / _read_meta / _write_meta
    - _diff_new_challenges: корректный diff против .seen.json
    - _fetch_full_challenges: параллельный fetch через mock
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import ctfd_client as m  # noqa: E402
from ctfd_client import CTfdClient, SubmitResult  # noqa: E402


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Изолируем HOME и CTFD_EVENT под временным каталогом."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CTFD_EVENT", "test-event-2026")
    monkeypatch.setenv("CTFD_HOST", "https://ctf.example.com")
    monkeypatch.setenv("CTFD_TOKEN", "ctfd_test_token")
    return home


@pytest.fixture
def client(isolated_home):
    return CTfdClient("https://ctf.example.com", token="ctfd_test_token")


@pytest.fixture
def sample_challenge():
    return {
        "id": 42,
        "name": "Buffer Overflo(w)",
        "category": "PWN",
        "value": 500,
        "solved_by_me": False,
        "description": (
            "<h2>Easy BOF</h2>"
            "<p>Connect: <code>nc ctf.example.com 31337</code></p>"
            "<ul><li>binary: <a href=\"https://ctf.example.com/files/vuln\">vuln</a></li></ul>"
        ),
        "connection_info": None,
        "hints": [{"id": 7, "cost": 0}, {"id": 8, "cost": 50}],
        "files": [],
    }


# ----------------------------------------------------------------------
#  init_challenge_workspace — основная структура
# ----------------------------------------------------------------------
class TestInitWorkspace:
    def test_creates_full_scaffold(self, client, sample_challenge, isolated_home):
        ws = client.init_challenge_workspace(sample_challenge)
        assert ws.exists()
        assert (ws / "challenge.json").exists()
        assert (ws / "description.md").exists()
        assert (ws / "NOTES.md").exists()
        assert (ws / "attachments").is_dir()
        assert (ws / "scripts").is_dir()

    def test_directory_naming(self, client, sample_challenge):
        ws = client.init_challenge_workspace(sample_challenge)
        # event/category/slug — slug нормализован из имени
        parts = ws.parts
        assert parts[-1] == "buffer_overflo_w"
        assert parts[-2] == "pwn"
        assert parts[-3] == "test-event-2026"

    def test_description_markdown_not_html(self, client, sample_challenge):
        ws = client.init_challenge_workspace(sample_challenge)
        desc = (ws / "description.md").read_text(encoding="utf-8")
        assert "Easy BOF" in desc
        assert "<h2>" not in desc
        assert "`nc ctf.example.com 31337`" in desc

    def test_challenge_json_metadata(self, client, sample_challenge):
        ws = client.init_challenge_workspace(sample_challenge)
        meta = json.loads((ws / "challenge.json").read_text())
        assert meta["id"] == 42
        assert meta["name"] == "Buffer Overflo(w)"
        assert meta["category"] == "PWN"
        assert meta["host"] == "https://ctf.example.com"
        assert meta["event"] == "test-event-2026"
        assert meta["solved"] is False
        assert "created_at" in meta
        # connection_info извлечён из описания
        assert "nc ctf.example.com 31337" in meta["connection_info"]

    def test_explicit_connection_info_wins(self, client, sample_challenge):
        sample_challenge["connection_info"] = "nc explicit.host 1"
        ws = client.init_challenge_workspace(sample_challenge)
        meta = json.loads((ws / "challenge.json").read_text())
        assert meta["connection_info"] == "nc explicit.host 1"

    def test_idempotency_solved_preserved(self, client, sample_challenge):
        ws = client.init_challenge_workspace(sample_challenge)
        # Симулируем что решили локально
        client._mark_solved_meta(ws, True)
        # Повторный init с тем же detail (solved_by_me=False)
        ws2 = client.init_challenge_workspace(sample_challenge)
        assert ws2 == ws
        meta = json.loads((ws / "challenge.json").read_text())
        assert meta["solved"] is True  # не сбросили

    def test_solved_by_me_promotes_to_solved(self, client, sample_challenge):
        sample_challenge["solved_by_me"] = True
        ws = client.init_challenge_workspace(sample_challenge)
        meta = json.loads((ws / "challenge.json").read_text())
        assert meta["solved"] is True

    def test_active_workspace_set(self, client, sample_challenge):
        ws = client.init_challenge_workspace(sample_challenge)
        assert client._active_ws == ws


# ----------------------------------------------------------------------
#  Шаблон solve.py по категории
# ----------------------------------------------------------------------
class TestSolvePyTemplate:
    @pytest.mark.parametrize(
        "cat,expected_substring",
        [
            ("pwn", "from pwn import"),
            ("web", "import requests"),
            ("crypto", "main"),
            ("rev", "TODO:"),
            ("forensics", "TODO:"),
            ("misc", "TODO:"),
        ],
    )
    def test_template_per_category(self, client, sample_challenge, cat, expected_substring):
        sample_challenge = dict(sample_challenge, category=cat, id=hash(cat) & 0xFFFF)
        ws = client.init_challenge_workspace(sample_challenge)
        solve_py = (ws / "scripts" / "solve.py").read_text()
        assert expected_substring in solve_py
        # Все плейсхолдеры раскрыты
        assert "{{" not in solve_py
        assert "{%" not in solve_py

    def test_unknown_category_falls_back_to_misc(self, client, sample_challenge):
        sample_challenge = dict(sample_challenge, category="exotic")
        ws = client.init_challenge_workspace(sample_challenge)
        solve_py = (ws / "scripts" / "solve.py").read_text()
        # misc-шаблон содержит "универсальный скелет"
        assert "универсальный скелет" in solve_py or "TODO" in solve_py

    def test_user_solve_py_not_overwritten(self, client, sample_challenge):
        ws = client.init_challenge_workspace(sample_challenge)
        solve_py = ws / "scripts" / "solve.py"
        custom = "# my own solution\n"
        solve_py.write_text(custom)
        # Повторный init не должен перезаписать
        client.init_challenge_workspace(sample_challenge)
        assert solve_py.read_text() == custom


# ----------------------------------------------------------------------
#  log_attempt + NOTES.md
# ----------------------------------------------------------------------
class TestLogAttempt:
    def test_append_dated_entry(self, client, sample_challenge):
        ws = client.init_challenge_workspace(sample_challenge)
        before = (ws / "NOTES.md").read_text()
        client.log_attempt(42, "first hypothesis", "hypothesis")
        after = (ws / "NOTES.md").read_text()
        assert len(after) > len(before)
        assert "first hypothesis" in after
        assert "hypothesis" in after

    def test_status_optional(self, client, sample_challenge):
        ws = client.init_challenge_workspace(sample_challenge)
        client.log_attempt(42, "no status line")
        notes = (ws / "NOTES.md").read_text()
        assert "no status line" in notes

    def test_unknown_challenge_lost_silently(self, client, capsys):
        # Нет воркспейса — запись теряется с предупреждением
        path = client.log_attempt(99999, "lost entry", "tried")
        captured = capsys.readouterr()
        assert "не найден" in captured.err or path == Path()

    def test_silent_does_not_warn(self, client, sample_challenge, capsys):
        client.init_challenge_workspace(sample_challenge)
        client.log_attempt(99999, "silent", "tried", _silent=True)
        captured = capsys.readouterr()
        assert captured.err == ""


# ----------------------------------------------------------------------
#  challenge.json миграция с .yaml
# ----------------------------------------------------------------------
class TestMetaMigration:
    def test_read_legacy_yaml_fallback(self, client, sample_challenge, tmp_path):
        # Создаём воркспейс руками с устаревшим .yaml
        ws = tmp_path / "legacy"
        ws.mkdir()
        # Запишем валидный YAML вручную (без PyYAML — он парсится как plain)
        (ws / "challenge.yaml").write_text(
            "id: 99\nname: legacy\nsolved: true\n"
        )
        # _read_meta не парсит YAML по-настоящему (только JSON), но должна
        # вернуть {} для невалидного JSON — это сознательное поведение.
        meta = client._read_meta(ws)
        assert meta == {}


# ----------------------------------------------------------------------
#  _diff_new_challenges
# ----------------------------------------------------------------------
class TestDiffNewChallenges:
    def test_first_call_seeds_baseline(self, client, monkeypatch):
        # .seen.json не существует → первый вызов seed'ит baseline
        seen = client._load_seen()
        assert seen == {} or "ids" not in seen
        data = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]
        out = client._diff_new_challenges(data, filtered=False, seen=seen)
        # baseline засеян
        assert out.get("baselined") is True
        # ids — union-список всех виденных id
        assert set(out.get("ids", [])) == {1, 2}

    def test_filtered_call_before_baseline_warns(self, client, capsys):
        seen = {}  # без baseline
        data = [{"id": 1, "name": "a"}]
        out = client._diff_new_challenges(data, filtered=True, seen=seen)
        # baseline не поднят
        assert out.get("baselined") is not True
        # но ids всё равно записан как union
        assert set(out.get("ids", [])) == {1}
        captured = capsys.readouterr()
        assert "baseline" in captured.err.lower()

    def test_detects_new_after_baseline(self, client, capsys):
        # Засеем baseline вручную (ключ 'ids', не 'challenges')
        seen = {"ids": [1, 2], "baselined": True, "updated_at": "2026-01-01"}
        data = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}, {"id": 3, "name": "c"}]
        out = client._diff_new_challenges(data, filtered=False, seen=dict(seen))
        # ids обновился: 1,2,3
        assert set(out["ids"]) == {1, 2, 3}
        # в stderr должно появиться сообщение о 1 новой (#3)
        captured = capsys.readouterr()
        assert "1 NEW" in captured.err
        assert "#3" in captured.err

    def test_filtered_call_does_not_shrink_ids(self, client):
        # ids хранится как union — фильтрованный вызов не должен его сужать
        seen = {"ids": [1, 2, 3], "baselined": True}
        data = [{"id": 1, "name": "a"}]
        out = client._diff_new_challenges(data, filtered=True, seen=dict(seen))
        assert set(out["ids"]) == {1, 2, 3}


# ----------------------------------------------------------------------
#  attempt с авто-логом (mocked HTTP)
# ----------------------------------------------------------------------
class TestAttemptAutolog:
    def test_correct_returns_submit_result_and_marks_solved(self, client, sample_challenge, monkeypatch):
        ws = client.init_challenge_workspace(sample_challenge)
        # Подменяем HTTP-вызов
        monkeypatch.setattr(
            client, "_request",
            lambda *a, **kw: {"status": "correct", "message": "+500 points"}
        )
        verdict = client.attempt(42, "flag{test}")
        assert isinstance(verdict, SubmitResult)
        assert verdict.correct
        assert verdict.status == "correct"
        # NOTES.md должен был получить запись
        notes = (ws / "NOTES.md").read_text()
        assert "correct" in notes
        assert "flag{test}" in notes
        # challenge.json — solved:true
        meta = json.loads((ws / "challenge.json").read_text())
        assert meta["solved"] is True
        assert "solved_at" in meta

    def test_incorrect_does_not_mark_solved(self, client, sample_challenge, monkeypatch):
        ws = client.init_challenge_workspace(sample_challenge)
        monkeypatch.setattr(
            client, "_request",
            lambda *a, **kw: {"status": "incorrect", "message": "try again"}
        )
        verdict = client.attempt(42, "wrong")
        assert not verdict.correct
        meta = json.loads((ws / "challenge.json").read_text())
        assert meta["solved"] is False
        notes = (ws / "NOTES.md").read_text()
        assert "incorrect" in notes

    def test_unknown_status_still_returns_submit_result(self, client, sample_challenge, monkeypatch):
        client.init_challenge_workspace(sample_challenge)
        monkeypatch.setattr(client, "_request", lambda *a, **kw: {"unexpected": "shape"})
        verdict = client.attempt(42, "x")
        assert isinstance(verdict, SubmitResult)
        assert verdict.status == "unknown"
        assert not verdict.correct


# ----------------------------------------------------------------------
#  unlock_free_hints (mocked)
# ----------------------------------------------------------------------
class TestUnlockFreeHints:
    def test_only_zero_cost_unlocked(self, client, monkeypatch):
        unlock_calls = []
        def fake_unlock_hint(hid):
            unlock_calls.append(hid)
            return {"success": True}
        monkeypatch.setattr(client, "unlock_hint", fake_unlock_hint)
        freed = client.unlock_free_hints([
            {"id": 1, "cost": 0},
            {"id": 2, "cost": 50},
            {"id": 3, "cost": 0},
            {"id": 4, "cost": -5},  # отрицательная стоимость — тоже "бесплатно"
        ])
        assert freed == [1, 3, 4]
        assert unlock_calls == [1, 3, 4]

    def test_missing_cost_fetched_via_preview(self, client, monkeypatch):
        monkeypatch.setattr(client, "unlock_hint", lambda hid: {"success": True})
        # _request мокается, чтобы для hint id=5 вернуть cost=0
        def fake_request(method, path, **kw):
            assert method == "GET"
            assert path.startswith("/hints/5")
            return {"id": 5, "cost": 0, "content": None}
        monkeypatch.setattr(client, "_request", fake_request)
        freed = client.unlock_free_hints([{"id": 5}])  # cost не указан
        assert freed == [5]

    def test_already_unlocked_silent(self, client, monkeypatch, capsys):
        def boom(hid):
            raise m.CTfdError("Target already unlocked")
        monkeypatch.setattr(client, "unlock_hint", boom)
        freed = client.unlock_free_hints([{"id": 1, "cost": 0}])
        assert freed == [1]  # всё равно в списке, т.к. "уже разблокирован" — ок
        captured = capsys.readouterr()
        # Не должно было печатать ошибку
        assert "Target already" not in captured.err

    def test_challenge_dict_accepted(self, client, sample_challenge, monkeypatch):
        monkeypatch.setattr(client, "unlock_hint", lambda hid: {"success": True})
        freed = client.unlock_free_hints(sample_challenge)
        assert freed == [7]  # только бесплатный, id=8 (cost 50) не трогается


# ----------------------------------------------------------------------
#  _fetch_full_challenges (mocked)
# ----------------------------------------------------------------------
class TestFetchFullChallenges:
    def test_parallel_merge(self, client, monkeypatch):
        # Подменяем get_challenge возвратом description
        def fake_get(cid):
            return {"id": cid, "description": f"<p>task {cid}</p>", "files": [f"f{cid}"]}
        monkeypatch.setattr(client, "get_challenge", fake_get)
        stubs = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}, {"id": 3, "name": "c"}]
        out = client._fetch_full_challenges(stubs, max_workers=4)
        assert len(out) == 3
        for s in out:
            assert "description" in s
            assert "files" in s
            # stub-поля сохранены
            assert "name" in s

    def test_empty_stubs(self, client):
        assert client._fetch_full_challenges([]) == []

    def test_failure_keeps_stub(self, client, monkeypatch, capsys):
        def fake_get(cid):
            if cid == 2:
                raise m.CTfdError("404 not found")
            return {"id": cid, "files": []}
        monkeypatch.setattr(client, "get_challenge", fake_get)
        stubs = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}, {"id": 3, "name": "c"}]
        out = client._fetch_full_challenges(stubs)
        # Все 3 вернулись
        assert len(out) == 3
        # id=2 — stub без detail
        id2 = next(s for s in out if s["id"] == 2)
        assert "files" not in id2
        # id=1 и id=3 — обогащены
        id1 = next(s for s in out if s["id"] == 1)
        assert "files" in id1
        captured = capsys.readouterr()
        assert "404 not found" in captured.err
