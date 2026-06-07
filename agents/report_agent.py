"""
Report Agent (agents/report_agent.py) - [Day 3 / Day 5]

발견과 위협 컨텍스트를 받아 위험도 점수를 계산하고 리포트를 합성한다.
새 발견을 만들지 않는다(취합/작성만).
위험도 = 심각도 x KEV가중 x (0.5+EPSS) x 노출면. 점수는 권고, 결정은 사람.
산출물: risk_score_table.md (HITL 상태 컬럼 포함) + final_report.md / lab3_report.md

[HITL 상태 표기]
  finding['confidence'] == '반려됨'  -> HITL에서 반려/보류된 발견
  그 외                              -> 확정(또는 미검토)
비대화형 기본 거부는 유지하되, 리포트에서 상태가 분명히 보이도록 분리 표기한다.
"""
import argparse
import os

# 리포트 최종 출구에서도 동일한 공용 마스킹을 한 번 더 적용한다(심층 방어).
# 상류 Agent가 누락하더라도 비밀값 원문이 리포트에 실리지 않게 한다.
try:
    from agents.masking import mask_secret_evidence as _mask_secret_evidence
except ImportError:  # `python agents/report_agent.py` 처럼 agents/ 가 sys.path[0]일 때
    from masking import mask_secret_evidence as _mask_secret_evidence

# LLM 해석 레이어(선택) — 키 있으면 실제 Claude, 없으면 결정론적 fallback.
try:
    from agents.llm_client import interpret as _llm_interpret, mode_label as _llm_mode
except ImportError:
    from llm_client import interpret as _llm_interpret, mode_label as _llm_mode

SEV_WEIGHT = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2}


def risk_score(finding, threat_ctx):
    base = SEV_WEIGHT.get(finding["severity"], 2)
    cve = finding.get("cve")
    kev_mult, epss = 1.0, 0.1
    if cve and cve in threat_ctx:
        kev_mult = 1.6 if threat_ctx[cve]["kev"] else 1.0
        epss = max(threat_ctx[cve]["epss"], 0.05)
    exposure = 1.3 if (os.sep + "control" + os.sep) in finding["file"] else 1.0
    return round(base * kev_mult * (0.5 + epss) * exposure, 1)


def _hitl_state(f):
    return "반려/보류" if f.get("confidence") == "반려됨" else "확정"


def _table(scored, threat_ctx):
    lines = ["# 위험도 점수표 (risk_score_table.md)\n",
             "| 순위 | 발견 | 심각도 | HITL 상태 | CWE | CVE | 위험도 |",
             "|---|---|---|---|---|---|---|"]
    for rank, s in enumerate(scored, start=1):
        cve = s.get("cve") or "-"
        lines.append(f"| {rank} | {s['title']} | {s['severity']} | {_hitl_state(s)} | {s['cwe']} | {cve} | {s['risk']} |")
    return "\n".join(lines) + "\n"


def build(findings, threat_ctx, out_path):
    scored = sorted(
        ({**f, "risk": risk_score(f, threat_ctx)} for f in findings),
        key=lambda x: x["risk"], reverse=True,
    )
    confirmed = [s for s in scored if _hitl_state(s) == "확정"]
    rejected = [s for s in scored if _hitl_state(s) == "반려/보류"]

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    table_md = _table(scored, threat_ctx)
    with open("reports/risk_score_table.md", "w", encoding="utf-8") as f:
        f.write(table_md)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("# 통합 보안 점검 리포트 (Security Agent Lab)\n\n")
        f.write(f"총 발견: {len(scored)}건 (확정 {len(confirmed)} / 반려·보류 {len(rejected)}) "
                f"· 위협 정보 결합 CVE: {len(threat_ctx)}건\n\n")
        f.write(table_md + "\n")
        # 확정 발견
        f.write("## 확정 발견 (대응 대상)\n\n")
        if confirmed:
            for s in confirmed:
                f.write(f"- **[{s['severity']}]** {s['title']} - `{os.path.basename(s['file'])}:{s['line']}`\n")
                f.write(f"  - 근거: `{_mask_secret_evidence(s['evidence'])}` · 출처: `{s['provenance']}` · 위험도: {s['risk']}\n")
        else:
            f.write("- (확정된 발견 없음 - 비대화형 실행 시 High 이상은 기본 거부됩니다)\n")
        # 반려/보류 발견
        f.write("\n## 반려·보류 발견 (HITL 미승인)\n\n")
        if rejected:
            for s in rejected:
                f.write(f"- **[{s['severity']}]** {s['title']} - `{os.path.basename(s['file'])}:{s['line']}` (HITL 반려/보류)\n")
        else:
            f.write("- (반려·보류된 발견 없음)\n")
        f.write("\n> 위험도 점수는 우선순위 '권고'입니다. 'HITL 상태'가 '확정'인 발견만 실제 대응 대상입니다.\n")
        # ── AI 해석 레이어 (부가 로직) ──
        # 키 있으면 LLM 자연어 해석, 없으면 결정론적 요약. 외부 호출 실패해도 리포트는 항상 완성된다.
        f.write("\n## AI 해석 (LLM)\n\n")
        f.write(f"> 모드: {_llm_mode()}\n\n")
        f.write(_llm_interpret(confirmed or scored, threat_ctx) + "\n")
    return out_path


if __name__ == "__main__":
    demo = [{"title": "SQL Injection", "severity": "High", "cwe": "CWE-89",
             "file": "sample_app/vulnerability.py", "line": 39, "evidence": "...",
             "provenance": "tool:sast", "confidence": "의심", "cve": None}]
    print("Report Agent 단독 데모:", build(demo, {}, "reports/_demo_report.md"))
