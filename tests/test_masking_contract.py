"""Contract tests for secret masking (tests/test_masking_contract.py).
Run: python -m pytest tests/test_masking_contract.py

계약(policies/CLAUDE.md): 비밀 값 원문은 어떤 출력에도 남지 않는다.
형식·변수명은 보존하고 값만 마스킹한다.
"""
from agents.sast_agent import _mask_secret_evidence as mask


def test_sk_live_is_masked():
    out = mask('API_TOKEN = "sk-live-abc"')
    assert "sk-live-abc" not in out
    assert "****" in out


def test_password_double_quote_is_masked():
    out = mask('PASSWORD = "abc123"')
    assert "abc123" not in out
    assert "PASSWORD" in out          # 변수명은 보존되어야 한다
    assert '"****"' in out


def test_secret_single_quote_keeps_varname():
    # 과거 회귀: 치환문 그룹참조가 깨져 'SECRET' 대신 literal '\1' 이 출력되던 버그
    out = mask("SECRET = 'abc123'")
    assert "abc123" not in out
    assert out == "SECRET = '****'"


def test_no_backref_literal_leak():
    out = mask("SECRET = 'abc123'")
    assert "\\1" not in out           # literal 백슬래시-1 이 새면 안 된다


def test_aws_key_keyed_is_masked():
    out = mask('API_KEY = "AKIAIOSFODNN7EXAMPLE"')
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "****" in out


def test_aws_key_bare_token_is_masked():
    out = mask("default_key=AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_vehicle_uds_seed_is_masked():
    out = mask('diag_seed = "uds-seed-0xDEADBEEF"')
    assert "DEADBEEF" not in out


def test_github_pat_is_masked():
    out = mask("gh = ghp_0123456789abcdefABCDEF")
    assert "ghp_0123456789abcdefABCDEF" not in out


def test_non_secret_line_unchanged():
    # 비밀이 아닌 평범한 코드는 건드리지 않는다
    src = 'rows = conn.execute(query).fetchall()'
    assert mask(src) == src
