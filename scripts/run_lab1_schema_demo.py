#!/usr/bin/env python3
"""
LAB 1-3 - 출력 형식(스키마) 고정 (scripts/run_lab1_schema_demo.py)

SAST 결과를 고정 스키마(finding_id, severity, cwe, file, line, evidence,
recommendation)로 정렬해 출력한다. 형식이 고정되어야 후속 도구(리포트 합성,
점수화)가 안정적으로 이어받을 수 있다 - 하네스 요소 1(출력 형식)의 실천이다.

사용:
  python scripts/run_lab1_schema_demo.py --target sample_app/

산출물:
  reports/lab1_schema.md
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from agents import sast_agent  # noqa: E402

# CWE별 권고(recommendation) - 발견을 '대응 가능한 항목'으로 바꾸는 마지막 칸
RECO = {
    "CWE-89":  "문자열 결합 대신 파라미터 바인딩(prepared statement) 사용",
    "CWE-78":  "shell=True 제거, 인자 리스트 호출과 입력 검증 적용",
    "CWE-22":  "경로 정규화 후 허용 목록(베이스 디렉터리) 검증",
    "CWE-798": "비밀을 코드에서 분리해 .env/Secrets로 이동, 키 회전",
    "CWE-328": "MD5/SHA1 대신 전용 비밀번호 해시(bcrypt 등) 사용",
    "CWE-502": "pickle 대신 json 등 안전한 직렬화 사용",
    "CWE-489": "운영 배포에서 debug=False 강제(설정 분리)",
    "CWE-601": "리다이렉트 대상 허용 목록 검증",
}


def main():
    ap = argparse.ArgumentParser(description="LAB 1-3 - 출력 스키마 고정 데모")
    ap.add_argument("--target", default="sample_app/")
    ap.add_argument("--policy", default="policies/CLAUDE.md")
    args = ap.parse_args()

    findings = sast_agent.run(args.target, args.policy)
    print(f"[Schema] {len(findings)}건을 고정 스키마로 출력 (대상: {args.target})")

    os.makedirs("reports", exist_ok=True)
    with open("reports/lab1_schema.md", "w", encoding="utf-8") as f:
        f.write("# LAB 1-3 - 고정 스키마 SAST 리포트\n\n")
        f.write("스키마: finding_id · severity · cwe · file · line · evidence · recommendation\n\n")
        for i, r in enumerate(findings, start=1):
            fid = f"SAST-{i:03d}"
            reco = RECO.get(r["cwe"], "입력 검증과 최소 권한 원칙 적용")
            print(f"  {fid}  [{r['severity']:8}] {r['cwe']:8} {os.path.basename(r['file'])}:{r['line']}")
            f.write(f"## {fid}\n")
            f.write(f"- severity: {r['severity']}\n- cwe: {r['cwe']}\n")
            f.write(f"- file: {r['file']}\n- line: {r['line']}\n")
            f.write(f"- evidence: `{r['evidence']}`\n")
            f.write(f"- recommendation: {reco}\n\n")
        f.write("> 같은 발견이라도 '고정된 칸'에 담겨야 다음 단계(점수화·리포트 합성)가 코드로 이어받을 수 있습니다.\n")
    print("→ reports/lab1_schema.md 저장")


if __name__ == "__main__":
    main()
