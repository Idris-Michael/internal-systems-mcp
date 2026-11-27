import pytest
from conftest import SECRET

from internal_mcp.auth import JwtVerifier
from internal_mcp.cli import main


async def test_token_command_mints_a_verifiable_token(monkeypatch, capsys):
    monkeypatch.setenv("MCP_TOKEN_SECRET", SECRET)
    assert main(["token", "ci-agent", "brand:read", "--ttl", "120"]) == 0
    tok = await JwtVerifier(SECRET).verify_token(capsys.readouterr().out.strip())
    assert tok is not None and tok.client_id == "ci-agent" and tok.scopes == ["brand:read"]


def test_missing_secret_stops_the_cli(monkeypatch):
    monkeypatch.delenv("MCP_TOKEN_SECRET", raising=False)
    with pytest.raises(SystemExit, match="MCP_TOKEN_SECRET"):
        main(["token", "a", "brand:read"])


def test_scan_reports_this_server_clean(live, capsys):
    assert main(["scan", live.url, "--token", live.token("brand:read")]) == 0
    out = capsys.readouterr().out
    assert "6 tools scanned, 0 finding(s)" in out
