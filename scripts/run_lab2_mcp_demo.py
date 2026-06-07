#!/usr/bin/env python3
"""
LAB 2 필수 실습 — MCP 도구 데모 (scripts/run_lab2_mcp_demo.py)

Claude CLI 인증·MCP 등록 없이도 Day 2 핵심 학습(도구의 발견 + 원본/해석 분리)을
진행할 수 있도록, mcp_servers/security_tools_server.py의 도구 3종을 직접 호출한다.

생성 산출물:
  - reports/lab2_scan_raw.json   (도구 원본 — 수정하지 않는 '증거')
  - reports/lab2_report.md       (해석 리포트 — 사람이 읽는 문서)
  - memory/audit_log.jsonl       (도구 호출 기록 1줄씩 append)

사용:
  python scripts/run_lab2_mcp_demo.py --target sample_app/

확장 실습(별도): claude mcp add security-tools -- python mcp_servers/security_tools_server.py
"""
import argparse
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone

# 저장소 루트를 import 경로에 추가 (scripts/ 하위에서 실행돼도 동작)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

# 서버 모듈을 파일에서 직접 로드 → 도구 함수 3종을 그대로 사용 (MCP 등록과 무관)
spec = importlib.util.spec_from_file_location(
    "security_tools_server", os.path.join(ROOT, "mcp_servers", "security_tools_server.py"))
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def audit(tool, target, count):
    """도구 호출 1건을 감사 로그에 append (누가·언제·무엇을·결과)."""
    os.makedirs("memory", exist_ok=True)
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "agent": "lab2_demo", "action": "tool_call",
           "tool": tool, "target": target, "result_count": count}
    with open("memory/audit_log.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def main():
    ap = argparse.ArgumentParser(description="LAB 2 필수 실습 — MCP 도구 직접 호출 데모")
    ap.add_argument("--target", default="sample_app/")
    args = ap.parse_args()

    # 1) 도구 3종 직접 호출 (MCP 서버에 등록된 것과 동일한 함수)
    results = {}
    for tool_name in ("scan_code", "detect_secrets", "check_dependencies"):
        fn = getattr(server, tool_name)
        out = fn(args.target)
        results[tool_name] = out
        audit(tool_name, args.target, len(out))
        print(f"[tool] {tool_name:20s} → {len(out)}건")

    # 2) 원본 JSON 저장 (증거 — 그대로 보존)
    os.makedirs("reports", exist_ok=True)
    with open("reports/lab2_scan_raw.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("→ reports/lab2_scan_raw.json 저장 (도구 원본)")

    # 3) 해석 리포트 생성 (심각도 순 정리 — 결정적 해석)
    merged = [x for v in results.values() for x in v]
    merged.sort(key=lambda x: SEV_ORDER.get(x.get("severity", "Low"), 9))
    with open("reports/lab2_report.md", "w", encoding="utf-8") as f:
        f.write("# LAB 2 - 도구 발견 해석 리포트\n\n")
        f.write(f"대상: `{args.target}` · 도구 3종 호출 · 총 발견 {len(merged)}건\n\n")
        f.write("| 심각도 | CWE | 위치 | 발견 |\n|---|---|---|---|\n")
        for r in merged:
            loc = f"{os.path.basename(r.get('file',''))}:{r.get('line','')}"
            f.write(f"| {r.get('severity','')} | {r.get('cwe','')} | `{loc}` | {r.get('title','')} |\n")
        f.write("\n> 원본은 reports/lab2_scan_raw.json 에 그대로 보존됩니다. ")
        f.write("해석이 의심되면 언제든 원본으로 되돌아가 검증하세요.\n")
        f.write("\n> 확장 실습: `claude mcp add security-tools -- python mcp_servers/security_tools_server.py` ")
        f.write("등록 후 Claude Code 대화창에서 같은 도구를 자연어로 호출해 보세요.\n")
    print("→ reports/lab2_report.md 저장 (해석 리포트)")
    print("→ memory/audit_log.jsonl 에 호출 기록 3건 append")
    print("\nLAB 2 필수 실습 완료 — 확장 실습(claude mcp add)은 PPT의 다음 장을 참고하세요.")


if __name__ == "__main__":
    main()
