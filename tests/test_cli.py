import pytest

from breachchecker import cli


def _patch_password(monkeypatch, value):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": value)


def test_cli_reports_breach(monkeypatch, capsys):
    # A distinctive value so we can assert the secret itself is never echoed.
    secret = "Zq7!breachSENTINEL42"
    _patch_password(monkeypatch, secret)
    monkeypatch.setattr(cli, "pwned_count", lambda pw: 12345)

    rc = cli.run([])
    out = capsys.readouterr().out
    assert rc == 1
    assert "BREACHED" in out
    assert "12,345" in out
    assert "Strength" in out
    # The password value must never be echoed back.
    assert secret not in out
    assert "SENTINEL" not in out


def test_cli_reports_clean(monkeypatch, capsys):
    _patch_password(monkeypatch, "Zx9$longAndUnusual!")
    monkeypatch.setattr(cli, "pwned_count", lambda pw: 0)

    rc = cli.run([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "not found in any known breach" in out
    assert "Zx9" not in out


def test_cli_empty_password(monkeypatch, capsys):
    _patch_password(monkeypatch, "")
    rc = cli.run([])
    assert rc == 2
    assert "No password" in capsys.readouterr().err


def test_cli_network_error(monkeypatch, capsys):
    _patch_password(monkeypatch, "whatever")

    def boom(pw):
        raise cli.requests.RequestException("no network")

    monkeypatch.setattr(cli, "pwned_count", boom)
    rc = cli.run([])
    assert rc == 3
    assert "Could not reach" in capsys.readouterr().err
