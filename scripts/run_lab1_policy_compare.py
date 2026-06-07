#!/usr/bin/env python3
"""
LAB 1-2 - 정책 전후 비교 자동화 (scripts/run_lab1_policy_compare.py)

같은 대상을 CLAUDE_base.md(가중 규칙 없음)와 CLAUDE.md(가중 규칙 포함)로
두 번 분석해, 정책 한 줄이 결과를 어떻게 바꾸는지 한 화면에서 비교한다.

사용:
  python scripts/run_lab1_policy_compare.py --target sample_app/

산출물:
  reports/lab1_policy_compare.md
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from agents import sast_agent  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="LAB 1-2 - 정책 전후 비교")
    ap.add_argument("--target", default="sample_app/")
    args = ap.parse_args()

    base = sast_agent.run(args.target, "policies/CLAUDE_base.md")
    full = sast_agent.run(args.target, "policies/CLAUDE.md")

    # 같은 발견(파일:라인:CWE)을 키로 두 결과의 심각도를 짝지어 비교한다.
    def key(r):
        return (os.path.basename(r["file"]), r["line"], r["cwe"])
    base_map = {key(r): r["severity"] for r in base}

    changed = []
    print(f"[비교] base={len(base)}건 / full={len(full)}건 (대상: {args.target})")
    for r in full:
        b = base_map.get(key(r))
        mark = ""
        if b and b != r["severity"]:
            mark = f"  ← 정책으로 {b} → {r['severity']} 상향"
            changed.append((r, b))
        print(f"  [{r['severity']:8}] {r['cwe']:8} {os.path.basename(r['file'])}:{r['line']}  {r['title']}{mark}")

    os.makedirs("reports", exist_ok=True)
    with open("reports/lab1_policy_compare.md", "w", encoding="utf-8") as f:
        f.write("# LAB 1-2 - 정책 전후 비교 리포트\n\n")
        f.write(f"대상: `{args.target}` · base {len(base)}건 / full {len(full)}건\n\n")
        f.write("| 발견 | CWE | base (CLAUDE_base.md) | full (CLAUDE.md) |\n|---|---|---|---|\n")
        for r in full:
            b = base_map.get(key(r), "-")
            hi = " **(상향)**" if b != "-" and b != r["severity"] else ""
            f.write(f"| {r['title']} `{os.path.basename(r['file'])}:{r['line']}` | {r['cwe']} | {b} | {r['severity']}{hi} |\n")
        f.write(f"\n> 정책 문장 한 줄('차량 제어 관련 모듈은 한 단계 높은 심각도')이 {len(changed)}건의 심각도를 바꿨습니다. ")
        f.write("같은 코드, 같은 도구 - 달라진 것은 정책뿐입니다.\n")
    print(f"→ reports/lab1_policy_compare.md 저장 (상향 {len(changed)}건)")


if __name__ == "__main__":
    main()
