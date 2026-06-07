"""Contract tests for secret_agent masking + dependency version compare.
Run: python -m pytest tests/test_secret_and_deps.py
"""
import os
import tempfile

from agents import secret_agent
from agents.dependency_agent import _older
from agents.masking import looks_like_unmasked_secret


def _scan(content, name="cfg.py"):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        return secret_agent.run(d)


# ── secret_agent: 공용 마스킹 사용(앞 3글자·bare 토큰 누출 회귀 방지) ──

def test_secret_value_fully_masked_no_prefix_leak():
    fs = _scan('API_TOKEN = "sk-live-9f8e7d6c5b4a3210"\n')
    assert fs, "발견이 있어야 한다"
    ev = fs[0]["evidence"]
    assert "sk-live-9f8e7d6c5b4a3210" not in ev
    assert "9f8e7d6c5b4a3210" not in ev          # 앞 3글자만 가리던 과거 누출 방지
    assert "****" in ev


def test_secret_bare_aws_key_is_masked():
    fs = _scan("aws_key=AKIAIOSFODNN7EXAMPLE\n")
    assert fs
    ev = fs[0]["evidence"]
    assert "AKIAIOSFODNN7EXAMPLE" not in ev
    # 마스킹된 근거는 무결성 게이트를 통과해야 한다(전체 BLOCK 유발 금지)
    assert not looks_like_unmasked_secret(ev)


def test_short_secret_not_leaked():
    fs = _scan('password = "abc"\n')
    assert fs
    assert "abc" not in fs[0]["evidence"]


def test_one_finding_per_line():
    # 한 줄이 여러 규칙(GENERIC-KEY + KEYWORD)에 걸려도 발견은 1건
    fs = _scan('API_TOKEN = "sk-live-abcdefghijkl"\n')
    assert len([f for f in fs if f["line"] == 1]) == 1


# ── dependency_agent: 길이 다른 버전 비교 거짓양성 방지 ──

def test_older_basic():
    assert _older("2.0.1", "2.2.5") is True
    assert _older("5.1", "5.4") is True


def test_older_equal_with_padding():
    # 2.31 == 2.31.0 → 취약 아님(과거엔 (2,31)<(2,31,0)=True 거짓양성)
    assert _older("2.31", "2.31.0") is False
    assert _older("2.31.0", "2.31.0") is False


def test_older_newer_is_safe():
    assert _older("3.0", "2.2.5") is False


def test_older_nonnumeric_is_safe():
    assert _older("2.0.1rc1", "2.2.5") is False
