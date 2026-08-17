"""Smoke-тесты чистых хелперов CTfdClient — без обращения к сети.

Покрывает:
    - SubmitResult (dict-compat + property-access)
    - _html_to_markdown (regex-fallback; markdownify-вариант отдельно мокать не нужно)
    - _extract_connection_info
    - _slugify
    - _classify_notification
    - _parse_retry_seconds
    - _scrape_nonce
    - _render_template (включая {% else %})
    - _solve_template_for
    - AsyncCTfdClient: создание, lazy-import httpx, API surface
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Делаем scripts/ импортируемым.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import ctfd_client as m  # noqa: E402
from ctfd_client import (
    AsyncCTfdClient,
    CTfdClient,
    SubmitResult,
)


# ----------------------------------------------------------------------
#  SubmitResult
# ----------------------------------------------------------------------
class TestSubmitResult:
    def test_dict_access_backward_compat(self):
        r = SubmitResult({"status": "correct", "message": "+500"})
        assert r["status"] == "correct"
        assert r.get("message") == "+500"

    def test_property_correct(self):
        assert SubmitResult({"status": "correct"}).correct is True
        assert SubmitResult({"status": "already_solved"}).correct is True
        assert SubmitResult({"status": "incorrect"}).correct is False

    def test_property_already_solved(self):
        assert SubmitResult({"status": "already_solved"}).already_solved is True
        assert SubmitResult({"status": "correct"}).already_solved is False

    def test_property_ratelimited(self):
        assert SubmitResult({"status": "ratelimited"}).ratelimited is True
        assert SubmitResult({"status": "correct"}).ratelimited is False

    def test_property_incorrect(self):
        assert SubmitResult({"status": "incorrect"}).incorrect is True
        assert SubmitResult({"status": "correct"}).incorrect is False

    def test_default_status_unknown(self):
        r = SubmitResult({"data": {"x": 1}})
        assert r.status == "unknown"
        assert r.correct is False
        assert r.message == ""

    def test_repr(self):
        r = SubmitResult({"status": "correct", "message": "ok"})
        assert "status='correct'" in repr(r)


# ----------------------------------------------------------------------
#  _html_to_markdown
# ----------------------------------------------------------------------
class TestHtmlToMarkdown:
    def test_none(self):
        assert CTfdClient._html_to_markdown(None) == "(описание отсутствует)"

    def test_empty(self):
        assert CTfdClient._html_to_markdown("") == "(описание отсутствует)"

    def test_simple_html_stripped(self):
        out = CTfdClient._html_to_markdown("<p>Hello <code>flag{}</code></p>")
        assert "flag{}" in out
        assert "<p>" not in out
        assert "<code>" not in out
        assert "`flag{}`" in out  # inline code preserved as markdown

    def test_headings_and_lists(self):
        out = CTfdClient._html_to_markdown(
            "<h2>Title</h2><ul><li>a</li><li>b</li></ul>"
        )
        # Заголовок: либо ATX (## Title), либо Setext (Title / -----) — оба валидны.
        assert "Title" in out
        assert ("## Title" in out) or ("----" in out)
        # Список: либо '- a', либо '* a' (зависит от markdownify vs fallback)
        assert ("- a" in out) or ("* a" in out)
        assert ("- b" in out) or ("* b" in out)

    def test_links(self):
        out = CTfdClient._html_to_markdown('<a href="http://x">L</a>')
        # markdownify использует [L](http://x) с optional title; fallback — то же.
        assert "[L](http://x)" in out

    def test_entities(self):
        out = CTfdClient._html_to_markdown("a &amp; b &lt;tag&gt; c &quot;q&quot;")
        assert "a & b <tag> c \"q\"" in out

    def test_pre_block(self):
        out = CTfdClient._html_to_markdown("<pre>line1\nline2</pre>")
        assert "```" in out
        assert "line1" in out and "line2" in out


# ----------------------------------------------------------------------
#  _extract_connection_info
# ----------------------------------------------------------------------
class TestExtractConnectionInfo:
    def test_explicit_wins(self):
        out = CTfdClient._extract_connection_info(
            "<desc>ignored</desc>", explicit="nc explicit.host 1"
        )
        assert out == "nc explicit.host 1"

    def test_none_description(self):
        assert CTfdClient._extract_connection_info(None) is None

    def test_empty_description(self):
        assert CTfdClient._extract_connection_info("nothing here") is None

    def test_nc_extraction_from_html(self):
        out = CTfdClient._extract_connection_info("<p>nc ctf.example.com 1337</p>")
        assert "nc ctf.example.com 1337" in out

    def test_ncat_extraction(self):
        out = CTfdClient._extract_connection_info("Connect: ncat host.io 22")
        assert "ncat host.io 22" in out

    def test_url_extraction(self):
        out = CTfdClient._extract_connection_info(
            "Open https://web.ctf.io:8443/path now"
        )
        assert "https://web.ctf.io:8443/path" in out

    def test_ssh_extraction(self):
        out = CTfdClient._extract_connection_info("ssh player@chall.host -p 2222")
        assert "ssh player@chall.host" in out

    def test_multiple_unique(self):
        out = CTfdClient._extract_connection_info(
            "nc a 1 and nc a 1 and ncat b 2"
        )
        # Дедуп
        assert out.count("nc a 1") == 1
        assert "ncat b 2" in out


# ----------------------------------------------------------------------
#  _slugify
# ----------------------------------------------------------------------
class TestSlugify:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Easy Challenge", "easy_challenge"),
            ("BoF'23 (pwn!)", "bof_23_pwn"),
            ("UPPER", "upper"),
            ("   spaced  ", "spaced"),
            ("", "challenge"),
            ("!!!", "challenge"),
            ("CryptoHack 2026: RSA", "cryptohack_2026_rsa"),
        ],
    )
    def test_cases(self, raw, expected):
        assert CTfdClient._slugify(raw) == expected


# ----------------------------------------------------------------------
#  _classify_notification
# ----------------------------------------------------------------------
class TestClassifyNotification:
    @pytest.mark.parametrize(
        "title,body,expected",
        [
            ("Hint for task 1", "", "hint"),
            ("Подсказка по задаче", "", "hint"),
            ("Clarification: typo in desc", "", "clarification"),
            ("Fix: updated flag", "", "clarification"),
            ("New challenge released", "", "new"),
            ("Новая задача опубликована", "", "new"),
            ("Score freeze in 1h", "", "scoring"),
            ("Bonus +50 for first blood", "", "scoring"),
            ("", "general announcement text", "general"),
            ("Hello world", "just an info", "general"),
        ],
    )
    def test_classification(self, title, body, expected):
        assert CTfdClient._classify_notification(title, body) == expected


# ----------------------------------------------------------------------
#  _parse_retry_seconds
# ----------------------------------------------------------------------
class TestParseRetrySeconds:
    def _fake_response(self, payload):
        class _R:
            def json(self_inner):
                return payload
        return _R()

    def test_data_message(self):
        r = self._fake_response({"data": {"message": "Please wait 30 seconds"}})
        assert CTfdClient._parse_retry_seconds(r) == 30

    def test_top_level_message(self):
        r = self._fake_response({"message": "Wait 5 seconds before retry"})
        assert CTfdClient._parse_retry_seconds(r) == 5

    def test_no_message(self):
        r = self._fake_response({"data": {}})
        assert CTfdClient._parse_retry_seconds(r) is None

    def test_invalid_json(self):
        class _Bad:
            def json(self):
                raise ValueError()
        assert CTfdClient._parse_retry_seconds(_Bad()) is None


# ----------------------------------------------------------------------
#  _scrape_nonce
# ----------------------------------------------------------------------
class TestScrapeNonce:
    def test_csrf_nonce_assignment(self):
        html = 'window.csrfNonce = "abc123def456";'
        assert CTfdClient._scrape_nonce(html) == "abc123def456"

    def test_meta_tag(self):
        html = '<meta name="csrf-token" content="deadbeef">'
        assert CTfdClient._scrape_nonce(html) == "deadbeef"

    def test_input_field(self):
        html = '<input name="nonce" value="0123abcd">'
        assert CTfdClient._scrape_nonce(html) == "0123abcd"

    def test_no_nonce(self):
        assert CTfdClient._scrape_nonce("<html>no nonce here</html>") is None


# ----------------------------------------------------------------------
#  _render_template
# ----------------------------------------------------------------------
class TestRenderTemplate:
    def test_simple_substitution(self):
        assert m._render_template("Hi {{name}}!", {"name": "X"}) == "Hi X!"

    def test_missing_key_becomes_empty(self):
        assert m._render_template("[{{x}}]", {}) == "[]"

    def test_if_true(self):
        out = m._render_template("a{% if x %}B{% endif %}c", {"x": "1"})
        assert out == "aBc"

    def test_if_false(self):
        out = m._render_template("a{% if x %}B{% endif %}c", {"x": ""})
        assert out == "ac"

    def test_if_else_true_branch(self):
        out = m._render_template("a{% if x %}B{% else %}D{% endif %}c", {"x": "1"})
        assert out == "aBc"

    def test_if_else_false_branch(self):
        out = m._render_template("a{% if x %}B{% else %}D{% endif %}c", {"x": ""})
        assert out == "aDc"

    def test_no_condition(self):
        assert m._render_template("plain", {}) == "plain"

    def test_all_default_templates_render(self):
        for cat, tmpl in m._DEFAULT_TEMPLATES.items():
            for ci in ["nc host 1", ""]:
                out = m._render_template(tmpl, {
                    "name": "T", "slug": "t", "host": "h",
                    "connection_info": ci, "flag_prefix": "flag{...}",
                })
                assert "{{" not in out, f"unrendered in {cat}"
                assert "{%" not in out, f"unrendered cond in {cat}"


# ----------------------------------------------------------------------
#  _solve_template_for
# ----------------------------------------------------------------------
class TestSolveTemplateFor:
    def test_known_categories(self):
        for cat in ["pwn", "web", "crypto", "rev", "forensics", "misc"]:
            assert m._solve_template_for(cat) == m._DEFAULT_TEMPLATES[cat]

    def test_case_insensitive(self):
        assert m._solve_template_for("PWN") == m._DEFAULT_TEMPLATES["pwn"]
        assert m._solve_template_for(" Web ") == m._DEFAULT_TEMPLATES["web"]

    def test_unknown_returns_none(self):
        assert m._solve_template_for("nonexistent") is None

    def test_user_override(self, tmp_path, monkeypatch):
        user_dir = tmp_path / "ctfd" / "templates"
        user_dir.mkdir(parents=True)
        (user_dir / "pwn.tmpl").write_text("# custom pwn template")
        monkeypatch.setattr(m, "_category_templates_dir", lambda: user_dir)
        assert m._solve_template_for("pwn") == "# custom pwn template"


# ----------------------------------------------------------------------
#  AsyncCTfdClient: API surface + lazy-import
# ----------------------------------------------------------------------
class TestAsyncClient:
    def test_exports_include_async(self):
        assert "AsyncCTfdClient" in m.__all__

    def test_lazy_httpx(self):
        # httpx установлен в окружении — проверяем что создание работает
        c = AsyncCTfdClient("https://ctf.example.com", token="ctfd_x")
        assert c.host == "https://ctf.example.com"
        assert c._token == "ctfd_x"

    def test_ensure_client_creates_async_client_with_auth_headers(self):
        import httpx
        c = AsyncCTfdClient("https://ctf.example.com", token="ctfd_x")
        client = c._ensure_client()
        assert isinstance(client, httpx.AsyncClient)
        assert client.headers["Authorization"] == "Token ctfd_x"
        assert client.headers["Content-Type"] == "application/json"

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("CTFD_HOST", "https://env.example.com")
        monkeypatch.setenv("CTFD_TOKEN", "ctfd_env")
        c = AsyncCTfdClient.from_env()
        assert c.host == "https://env.example.com"
        assert c._token == "ctfd_env"

    def test_from_env_missing_host(self, monkeypatch):
        monkeypatch.delenv("CTFD_HOST", raising=False)
        monkeypatch.delenv("CTFD_TOKEN", raising=False)
        with pytest.raises(m.CTfdError):
            AsyncCTfdClient.from_env()

    def test_all_player_methods_are_coroutines(self):
        import inspect
        c = AsyncCTfdClient("https://ctf.example.com", token="ctfd_x")
        for name in (
            "list_challenges", "get_challenge", "get_challenge_solves", "attempt",
            "get_hint", "unlock", "unlock_hint", "unlock_solution",
            "unlock_free_hints", "scoreboard", "scoreboard_top", "me",
            "my_solves", "my_fails", "my_awards", "my_team", "my_team_solves",
            "notifications", "download_file", "init_challenge_workspace",
            "log_attempt",
        ):
            method = getattr(c, name)
            assert inspect.iscoroutinefunction(method), f"{name} is not a coroutine"

    def test_url_resolution(self):
        c = AsyncCTfdClient("https://ctf.example.com", token="ctfd_x")
        assert c._url("/challenges") == "/api/v1/challenges"
        assert c._url("/api/v1/challenges") == "/api/v1/challenges"
        assert c._url("https://other/x") == "https://other/x"
