"""Contract tests for the review() quality gate (tests/test_review_gate.py).
Run: python -m pytest tests/test_review_gate.py

검증 노드는 죽은 코드가 아니라 실제로 PASS / RETRY / BLOCK 을 구분해야 한다.
"""
from orchestrator.supervisor_graph import review


def _finding(**over):
    base = {"title": "X", "severity": "Medium", "cwe": "CWE-1",
            "file": "a.py", "line": 1, "evidence": "x = 1",
            "provenance": "tool:test", "cve": None}
    base.update(over)
    return base


def _state(findings, retries=0):
    return {"findings": findings, "cves": [], "retries": retries}


def test_clean_findings_pass():
    s = review(_state([_finding(), _finding(severity="High", evidence="shell=True")]))
    assert s["verdict"] == "PASS"


def test_malformed_triggers_retry_and_resets():
    # High 인데 근거 없음 → 회복 가능 결함 → RETRY + findings 초기화
    s = review(_state([_finding(severity="High", evidence="")], retries=0))
    assert s["verdict"] == "RETRY"
    assert s["retries"] == 1
    assert s["findings"] == []      # 재스캔 전 초기화(중복 누적 방지)
    assert s["cves"] == []


def test_missing_required_field_triggers_retry():
    s = review(_state([_finding(provenance="")], retries=0))
    assert s["verdict"] == "RETRY"


def test_block_after_retries_exhausted():
    # 재시도 소진(retries=2) 후에도 결함이 남으면 BLOCK
    s = review(_state([_finding(severity="High", evidence="")], retries=2))
    assert s["verdict"] == "BLOCK"


def test_unmasked_secret_blocks_immediately():
    # 마스킹 누락(정책 위반)은 회복 불가 → 재시도 없이 즉시 BLOCK
    leak = _finding(title="hardcoded", evidence='PASSWORD = "Plaintext_999"')
    s = review(_state([leak], retries=0))
    assert s["verdict"] == "BLOCK"


def test_masked_secret_does_not_block():
    # 정상 마스킹된 근거는 BLOCK 되면 안 된다(거짓 양성 방지)
    ok = _finding(title="hardcoded", evidence='API_TOKEN = "****"')
    s = review(_state([ok]))
    assert s["verdict"] == "PASS"
