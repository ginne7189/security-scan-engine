#!/usr/bin/env python3
"""
LLM 해석 실습 (scripts/run_llm_interpret.py)

결정론적 도구(scan_code·detect_secrets·check_dependencies)로 발견을 모은 뒤,
LLM 해석 레이어(agents/llm_client.py)로 자연어 요약 + 즉시 대응 Top 3 을 만든다.

- ANTHROPIC_API_KEY 가 있으면 실제 Claude(SECLAB_MODEL, 기본 claude-sonnet-4-6) 호출.
- 없으면 결정론적 fallback 요약 — 키 없이도 실습이 멈추지 않는다.

사용:
  python scripts/run_llm_interpret.py --target sample_app/

산출물:
  reports/llm_interpretation.md
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from agents import sast_agent, secret_agent, dependency_agent  # noqa: E402
from agents.llm_client import interpret, mode_label             # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="LLM 해석 실습 — 발견 → 자연어 해석")
    ap.add_argument("--target", default="sample_app/")
    args = ap.parse_args()

    findings = []
    findings += sast_agent.run(args.target)
    findings += secret_agent.run(args.target)
    findings += dependency_agent.run(args.target)

    mode = mode_label()
    print(f"[LLM 해석] 발견 {len(findings)}건 · 모드: {mode}")
    text = interpret(findings)
    print("─" * 60)
    print(text)
    print("─" * 60)

    os.makedirs("reports", exist_ok=True)
    with open("reports/llm_interpretation.md", "w", encoding="utf-8") as f:
        f.write("# LLM 해석 리포트\n\n")
        f.write(f"대상: `{args.target}` · 발견 {len(findings)}건 · 모드: **{mode}**\n\n")
        f.write(text + "\n\n")
        f.write("> 핵심 발견(정규식 도구)은 키 없이도 동작합니다. "
                "이 해석 섹션만 LLM 선택 레이어입니다.\n")
    print("→ reports/llm_interpretation.md 저장")


if __name__ == "__main__":
    main()
