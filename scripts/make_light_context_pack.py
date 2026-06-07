#!/usr/bin/env python3
"""Make a small context pack for GPT/Claude review inside Codespaces.
No API call is made. This is designed for low-token Claude Code or copy/paste into GPT.
"""
from __future__ import annotations
import argparse
from pathlib import Path

DAY_FILES = {
    "1": ["policies/CLAUDE_base.md", "policies/CLAUDE.md", "agents/sast_agent.py", "reports/lab1_sast.md"],
    "2": ["mcp_servers/security_tools_server.py", "scripts/run_lab2_mcp_demo.py", "reports/lab2_report.md"],
    "3": ["orchestrator/supervisor_graph.py", "reports/lab3_report.md", "memory/audit_log.jsonl"],
    "4": ["templates/threat_tools.py", "agents/threat_agent.py", "reports/risk_score_table.md"],
    "5": ["orchestrator/supervisor_graph.py", "reports/final_report.md", "reports/risk_score_table.md"],
}

def short_text(path: Path, limit: int = 2200) -> str:
    if not path.exists():
        return "(file not generated yet)"
    text = path.read_text(encoding="utf-8", errors="replace")
    return text[:limit] + ("\n...<truncated>" if len(text) > limit else "")

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", choices=list(DAY_FILES), required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    root = Path.cwd()
    out = Path(args.out or f"reports/context_pack_day{args.day}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    parts = [f"# Day {args.day} Lightweight Context Pack", "", "목적: GPT/Claude에 전체 저장소를 넣지 않고, 오늘 검토에 필요한 최소 파일만 제공합니다.", ""]
    for rel in DAY_FILES[args.day]:
        p = root / rel
        parts += [f"## {rel}", "```text", short_text(p), "```", ""]
    parts += ["## Review Prompt", "아래 기준으로 검토하세요: 1) 보안 정책 준수 2) 실습 산출물 일치 3) 마스킹 4) 다음 단계 연결."]
    out.write_text("\n".join(parts), encoding="utf-8")
    print(f"[OK] context pack written: {out}")

if __name__ == "__main__":
    main()
