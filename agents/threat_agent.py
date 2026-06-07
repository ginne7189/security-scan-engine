"""
Threat Intelligence Agent (agents/threat_agent.py) — [Day 4 · TI 실습]

Dependency Agent가 넘긴 CVE 목록에 대해 templates/threat_tools.py 의 세 도구
(lookup_cve · check_kev · get_epss)를 호출해 '위협 컨텍스트'를 만든다.
산출물: threat_context.json (위험도 점수화의 입력).
하지 않는 것: 최종 판정(점수화는 report_agent, 승인은 사람).
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from templates.threat_tools import lookup_cve, check_kev, get_epss


def run(cves, out_path="reports/threat_context.json"):
    """CVE 목록 → {cve: {severity, kev, epss, summary}} 위협 컨텍스트."""
    ctx = {}
    for cve in sorted(set(c for c in cves if c)):
        detail = lookup_cve(cve)
        ctx[cve] = {
            "severity": detail["severity"],
            "summary": detail["summary"],
            "kev": check_kev(cve),
            "epss": get_epss(cve),
        }
    # threat_context.json 산출 (Day 4 산출물)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(ctx, f, ensure_ascii=False, indent=2)
    return ctx


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Threat Intelligence Agent (Day 4)")
    ap.add_argument("--cve", nargs="*",
                    default=["CVE-2020-14343", "CVE-2023-30861", "CVE-2024-22195"])
    a = ap.parse_args()
    ctx = run(a.cve)
    print(f"[Threat] 위협 컨텍스트 {len(ctx)}건 → reports/threat_context.json")
    for cve, v in ctx.items():
        kev = "KEV등재" if v["kev"] else "-"
        print(f"  {cve}  {v['severity']:8} {kev:8} EPSS={v['epss']:.2f}  {v['summary']}")
