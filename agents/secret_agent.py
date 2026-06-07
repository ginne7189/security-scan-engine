"""
Secret Agent (agents/secret_agent.py) — [Day 3 · LAB 3]
하드코딩된 비밀을 탐지한다(값은 항상 마스킹). 더미 키는 '확인 필요'로 분리.
"""
import argparse
import os
import re

# 마스킹은 공용 단일 구현을 사용한다(sast/report/secret 모두 동일 정책으로 통일).
# 과거 자체 _mask 는 앞 3글자를 노출하고 bare 토큰을 마스킹하지 못해 누출 위험이 있었다.
try:
    from agents.masking import mask_secret_evidence as _mask_secret_evidence
except ImportError:  # `python agents/secret_agent.py` 처럼 agents/ 가 sys.path[0]일 때
    from masking import mask_secret_evidence as _mask_secret_evidence

SECRET_RULES = [
    ("AWS-KEY", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key 노출", "High"),
    ("GENERIC-KEY", re.compile(r"(sk-[A-Za-z0-9\-]{8,}|uds-seed-0x[0-9A-Fa-f]+)"), "API/진단 키 하드코딩", "High"),
    ("KEYWORD", re.compile(r"(secret|password|pwd|token|api[_-]?key)\s*=", re.I), "비밀 추정 변수", "Medium"),
]


def _iter_files(target):
    exts = (".py", ".env", ".cfg", ".ini", ".yaml", ".yml", ".txt")
    if os.path.isfile(target):
        yield target; return
    for root, _, files in os.walk(target):
        for fn in files:
            if fn.endswith(exts):
                yield os.path.join(root, fn)


def run(target, policy_path="policies/CLAUDE.md"):
    findings = []
    for path in _iter_files(target):
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            continue
        for i, line in enumerate(lines, start=1):
            for rule_id, rx, title, sev in SECRET_RULES:
                if rx.search(line):
                    dummy = any(w in line.lower() for w in ("demo", "test", "example", "dummy"))
                    findings.append({
                        "rule": rule_id, "title": title, "severity": sev, "cwe": "CWE-798",
                        "file": path, "line": i, "evidence": _mask_secret_evidence(line.strip())[:120],
                        "confidence": "확인 필요" if dummy else "의심",
                        "agent": "secret", "provenance": f"tool:secret_rules#{rule_id}", "cve": None,
                    })
                    break  # 한 줄당 한 건(가장 강한 규칙 우선) — 같은 비밀 중복 발견 방지
    return findings


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Secret Agent (LAB 3)")
    ap.add_argument("--target", default="sample_app/")
    a = ap.parse_args()
    res = run(a.target)
    print(f"[Secret] 노출 의심 {len(res)}건 (값은 마스킹됨)")
    for r in res:
        print(f"  [{r['confidence']:8}] {os.path.basename(r['file'])}:{r['line']}  {r['title']}  {r['evidence']}")
    # LAB 2-2 산출물: 단독 실행 리포트 (값은 항상 마스킹 상태로 기록)
    os.makedirs("reports", exist_ok=True)
    with open("reports/lab2_secret_report.md", "w", encoding="utf-8") as f:
        f.write(f"# LAB 2-2 - Secret Agent 단독 리포트\n\n대상: `{a.target}` · 노출 의심 {len(res)}건 (값 마스킹)\n\n")
        for r in res:
            f.write(f"- **[{r['confidence']}]** `{os.path.basename(r['file'])}:{r['line']}` - {r['title']}\n")
            f.write(f"  - 근거: `{r['evidence']}`\n")
        f.write("\n> SAST와의 차이: SAST는 '코드 패턴'을, Secret Agent는 '비밀의 존재'를 봅니다. 값은 어떤 출력에서도 원문을 남기지 않습니다.\n")
    print("→ reports/lab2_secret_report.md 저장")
