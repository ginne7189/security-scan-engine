"""Contract tests for the optional LLM interpretation layer.
Run: python -m pytest tests/test_llm_client.py

핵심 보장: 키가 없거나 호출이 실패해도 절대 크래시하지 않고
결정론적 fallback 으로 안전 강하한다. LLM 입력에는 비밀 원문이 들어가지 않는다.
이 테스트는 네트워크/실제 LLM 을 호출하지 않는다(결정론 부분만 검증).
"""
from agents.llm_client import _compact, _fallback_summary, interpret


def _f(**over):
    base = {"severity": "High", "title": "X", "cwe": "CWE-1",
            "file": "a/b.py", "line": 3, "evidence": "x = 1", "cve": None}
    base.update(over)
    return base


def test_empty_findings_no_crash():
    assert "해석 생략" in interpret([])


def test_fallback_counts_by_severity():
    out = _fallback_summary([_f(severity="Critical"), _f(severity="High"), _f(severity="High")])
    assert "총 3건" in out
    assert "Critical 1건" in out
    assert "High 2건" in out


def test_compact_masks_secret_evidence():
    # LLM 입력으로 가공할 때 비밀 원문이 마스킹돼야 한다
    rows = _compact([_f(evidence='PASSWORD = "Plaintext_Secret_42"')])
    assert "Plaintext_Secret_42" not in rows[0]["evidence"]
    assert "****" in rows[0]["evidence"]


def test_compact_uses_basename_only():
    rows = _compact([_f(file="sample_app/control/ecu_handler.py")])
    assert rows[0]["file"] == "ecu_handler.py"
