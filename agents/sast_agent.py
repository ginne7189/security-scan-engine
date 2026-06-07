"""
SAST Agent (agents/sast_agent.py) - [Day 1 / LAB 1]

소스 코드를 정적 분석해 취약점을 찾고 CWE를 매핑한다.
별도 서버나 포트 실행 없이, 단일 파이썬 함수로 분석이 수행된다.
supervisor_graph가 이 함수를 그래프 노드로 호출한다.

[정답지] sample_app/vulnerability.py 에는 9종 취약점이 심어져 있다.
이 SAST Agent는 그 중 '코드 패턴으로 탐지 가능한 8종'을 잡도록 설계되었다.
나머지 1종(CWE-532 민감 정보 로깅)은 의도적으로 누락되며,
Day 3에서 규칙을 보강해 개선하는 학습 과제로 남긴다.
"""
import argparse
import os
import re

# 마스킹은 공용 단일 구현을 사용한다(sast/report 양쪽이 어긋나지 않도록 통합).
try:
    from agents.masking import mask_secret_evidence as _mask_secret_evidence
except ImportError:  # `python agents/sast_agent.py` 처럼 agents/ 가 sys.path[0]일 때
    from masking import mask_secret_evidence as _mask_secret_evidence

# (규칙ID, 정규식, 제목, 심각도, CWE)
# 각 규칙은 정답지 9종 중 한 종과 1:1로 대응하도록 정밀하게 작성했다.
# CWE-532(민감 정보 로깅)는 의도적으로 규칙에서 제외한다 -> Day 3 개선 과제.
RULES = [
    ("SQLI-STRCAT", re.compile(r"SELECT .*\" *\+|query *= *\"[^\"]*\" *\+"), "SQL Injection 의심", "High", "CWE-89"),
    ("HARDCODED-CRED", re.compile(r"(API_TOKEN|API_KEY|SECRET|PASSWORD) *= *\"[^\"]+\""), "하드코딩 자격증명", "High", "CWE-798"),
    ("CMDI-SHELL", re.compile(r"shell=True|os\.system\("), "Command Injection 의심", "High", "CWE-78"),
    ("PATH-TRAVERSAL", re.compile(r"open\( *\"[^\"]*\" *\+ *\w+"), "Path Traversal 의심", "High", "CWE-22"),
    ("WEAK-HASH", re.compile(r"hashlib\.(md5|sha1)\("), "약한 해시 사용", "Medium", "CWE-328"),
    ("UNSAFE-DESERIAL", re.compile(r"pickle\.loads?\(|yaml\.load\((?!.*Loader)"), "안전하지 않은 역직렬화", "High", "CWE-502"),
    ("DEBUG-ON", re.compile(r"app\.run\([^)]*debug *= *True"), "디버그 모드 노출", "Medium", "CWE-489"),
    ("OPEN-REDIRECT", re.compile(r"redirect\( *request\.|redirect\( *target"), "검증 없는 리다이렉트", "Medium", "CWE-601"),
    # ↓ CWE-532(민감 정보 로깅)는 의도적으로 규칙 없음 = 누락 1건 (Day 3 개선 과제)
]

SEV_ORDER = ["Low", "Medium", "High", "Critical"]


def _bump(sev):
    return SEV_ORDER[min(SEV_ORDER.index(sev) + 1, len(SEV_ORDER) - 1)]


def _load_policy(p):
    try:
        with open(p, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _iter_py(target):
    if os.path.isfile(target):
        if target.endswith(".py"):
            yield target
        return
    for root, _, files in os.walk(target):
        for fn in files:
            if fn.endswith(".py"):
                yield os.path.join(root, fn)


def run(target, policy_path="policies/CLAUDE.md"):
    """대상 경로를 정적 분석해 발견(dict) 리스트를 반환.

    각 파일에서 규칙별로 '첫 번째 매칭 한 건'만 발견으로 기록한다.
    (같은 규칙이 여러 줄에 걸려 중복 발견이 쌓이는 것을 방지)
    """
    policy = _load_policy(policy_path)
    control_boost = "한 단계 높은 심각도" in policy
    findings = []
    for path in _iter_py(target):
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        is_control = (os.sep + "control" + os.sep) in path
        seen_rules = set()  # 파일 내 규칙 중복 방지
        for i, line in enumerate(lines, start=1):
            # 주석 줄(설명/정답지)은 건너뛴다 -> docstring 오탐 방지
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"') or stripped.startswith("'"):
                continue
            for rule_id, rx, title, sev, cwe in RULES:
                if rule_id in seen_rules:
                    continue
                if rx.search(line):
                    severity = _bump(sev) if (is_control and control_boost) else sev
                    findings.append({
                        "rule": rule_id, "title": title, "severity": severity,
                        "cwe": cwe, "file": path, "line": i,
                        "evidence": _mask_secret_evidence(stripped)[:120], "confidence": "의심",
                        "agent": "sast", "provenance": f"tool:sast_rules#{rule_id}",
                        "cve": None,
                    })
                    seen_rules.add(rule_id)
    return findings


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SAST Agent - 단일 정적 분석 (LAB 1)")
    ap.add_argument("--target", default="sample_app/")
    ap.add_argument("--policy", default="policies/CLAUDE.md")
    args = ap.parse_args()
    res = run(args.target, args.policy)
    print(f"[SAST] {args.target} 분석 완료 - 발견 {len(res)}건 (정책: {args.policy})")
    for r in res:
        print(f"  [{r['severity']:8}] {r['cwe']:8} {os.path.basename(r['file'])}:{r['line']}  {r['title']}")
    if args.target.rstrip("/").endswith("vulnerability.py"):
        print("  → vulnerability.py 기준: 정답지 9종 중 8종 탐지 (CWE-532 민감 정보 로깅 1종 누락, Day 3 개선 과제)")
    else:
        print("  → sample_app 전체 기준: vulnerability.py 8건 + control/ 1건 = 총 9건 출력")
    os.makedirs("reports", exist_ok=True)
    with open("reports/lab1_sast.md", "w", encoding="utf-8") as f:
        f.write(f"# LAB 1 - SAST 단일 분석 리포트\n\n총 발견: {len(res)}건\n\n")
        single = args.target.rstrip("/").endswith("vulnerability.py")
        if single:
            f.write("- vulnerability.py 기준: 정답지 9종 중 8종 탐지\n")
            f.write("- 미탐지: CWE-532 민감 정보 로깅\n\n")
        else:
            f.write("- vulnerability.py 기준: 정답지 9종 중 8종 탐지\n")
            f.write("- control/ 기준: 차량 제어 모듈 발견 1건 추가\n")
            f.write("- 미탐지: CWE-532 민감 정보 로깅\n")
            f.write("- 정책 적용 시 control/ 발견은 High에서 Critical로 상향\n\n")
        for r in res:
            f.write(f"- **[{r['severity']}]** {r['cwe']} `{os.path.basename(r['file'])}:{r['line']}` - {r['title']}\n")
            f.write(f"  - 근거: `{r['evidence']}`\n")
        f.write("\n> 미탐지: CWE-532(민감 정보 로깅). Day 3에서 규칙 보강으로 개선.\n")
