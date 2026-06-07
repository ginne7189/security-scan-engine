#!/usr/bin/env python3
"""Deterministic lightweight review loop.
Checks whether key reports exist and whether raw-looking secrets are leaked.
No API key, no GitHub token, no network required.
"""
from __future__ import annotations
from pathlib import Path
import re, json, time

SECRET_PATTERNS = [r"sk-live-[A-Za-z0-9_-]+", r"ghp_[A-Za-z0-9_]+", r"PASSWORD\s*=\s*['\"][^'\"]+['\"]", r"SECRET\s*=\s*['\"][^'\"]+['\"]"]
REPORTS = ["reports/lab1_sast.md", "reports/lab2_report.md", "reports/lab3_report.md", "reports/risk_score_table.md", "reports/final_report.md"]

def scan(path: Path):
    if not path.exists():
        return {"path": str(path), "exists": False, "leaks": []}
    text = path.read_text(encoding="utf-8", errors="replace")
    leaks=[]
    for pat in SECRET_PATTERNS:
        leaks += re.findall(pat, text, flags=re.I)
    return {"path": str(path), "exists": True, "leaks": leaks[:5]}

def main():
    findings = [scan(Path(r)) for r in REPORTS]
    verdict = "PASS" if all(f["exists"] and not f["leaks"] for f in findings if "final_report" in f["path"] or "lab1" in f["path"]) else "REVIEW"
    Path("reports").mkdir(exist_ok=True)
    out = Path("reports/light_review_result.json")
    out.write_text(json.dumps({"verdict": verdict, "checked_at": time.time(), "findings": findings}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[review] verdict={verdict} written={out}")
    for f in findings:
        print(f" - {f['path']}: exists={f['exists']} leaks={len(f['leaks'])}")

if __name__ == "__main__":
    main()
