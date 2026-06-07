"""
Dependency Agent (agents/dependency_agent.py) — [Day 3 · LAB 3]
requirements.txt를 교육용 오프라인 취약 DB와 대조해 영향 패키지·CVE를 산출.
산출 CVE는 State를 거쳐 Threat Agent로 넘어간다.
"""
import argparse
import os
import re

VULN_DB = {
    "flask":    {"max_safe": "2.2.5", "cve": "CVE-2023-30861", "sev": "Medium"},
    "requests": {"max_safe": "2.31.0", "cve": "CVE-2023-32681", "sev": "Medium"},
    "pyyaml":   {"max_safe": "5.4",    "cve": "CVE-2020-14343", "sev": "High"},
    "jinja2":   {"max_safe": "3.1.3",  "cve": "CVE-2024-22195", "sev": "Medium"},
}


def _older(v, safe):
    """v 가 safe(첫 패치 버전)보다 낮으면 True. 길이가 다른 버전은 0으로 패딩해 비교."""
    def t(x): return tuple(int(p) for p in x.split("."))
    try:
        a, b = t(v), t(safe)
    except ValueError:
        return False
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))   # 2.31 vs 2.31.0 같은 길이 차이로 인한 거짓양성 방지
    b += (0,) * (n - len(b))
    return a < b


def _find_requirements(target):
    if os.path.isfile(target) and target.endswith("requirements.txt"):
        return target
    for root, _, files in os.walk(target):
        if "requirements.txt" in files:
            return os.path.join(root, "requirements.txt")
    return None


def run(target, policy_path="policies/CLAUDE.md"):
    req = _find_requirements(target)
    if not req:
        return []
    findings = []
    with open(req, encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            m = re.match(r"\s*([A-Za-z0-9_\-]+)\s*==\s*([0-9.]+)", line)
            if not m:
                continue
            pkg, ver = m.group(1).lower(), m.group(2)
            info = VULN_DB.get(pkg)
            if info and _older(ver, info["max_safe"]):
                findings.append({
                    "rule": "DEP-VULN", "title": f"{pkg} {ver} 취약 버전",
                    "severity": info["sev"], "cwe": "CWE-1104", "file": req, "line": i,
                    "evidence": f"{pkg}=={ver} < {info['max_safe']}", "confidence": "확정",
                    "agent": "dependency", "provenance": "tool:check_dependencies(offline-db)",
                    "cve": info["cve"],
                })
    return findings


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Dependency Agent (LAB 3)")
    ap.add_argument("--target", default="sample_app/")
    a = ap.parse_args()
    res = run(a.target)
    print(f"[Dependency] 취약 의존성 {len(res)}건")
    for r in res:
        print(f"  [{r['severity']:8}] {r['cve']}  {r['title']}")
    # LAB 2-3 산출물: requirements 기반 CVE 후보 리포트
    os.makedirs("reports", exist_ok=True)
    with open("reports/lab2_dependency_report.md", "w", encoding="utf-8") as f:
        f.write(f"# LAB 2-3 - Dependency Agent 단독 리포트\n\n대상: `{a.target}` · 취약 의존성 {len(res)}건\n\n")
        f.write("| 심각도 | CVE | 패키지/내용 |\n|---|---|---|\n")
        for r in res:
            f.write(f"| {r['severity']} | {r['cve']} | {r['title']} |\n")
        f.write("\n> SAST와의 차이: 여기서 찾은 위험은 '우리 코드'가 아니라 '우리가 쓰는 라이브러리'의 위험입니다. 이 CVE 목록이 Day 4 위협 정보 조회의 입력이 됩니다.\n")
    print("→ reports/lab2_dependency_report.md 저장")
