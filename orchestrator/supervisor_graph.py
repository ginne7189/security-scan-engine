"""
Supervisor Graph (orchestrator/supervisor_graph.py) — [Day 3 · LAB 3/4, Day 5 · 통합 PoC]

LangGraph 중앙 오케스트레이션으로 5개 Agent를 조율하는 핵심 파일.
- 5개 Agent는 별도 서버나 포트 없이, 이 그래프가 호출하는 단일 파이썬 함수(노드)다.
- 모든 결과는 중앙 State를 거친다(에이전트 간 직접 호출 금지).
- 검증(PASS/RETRY/BLOCK)·HITL 승인·Audit Log 적재가 한 곳에 모인다.

수강생이 수정하는 곳: route_input 분기, 각 노드의 프롬프트·정책, review 기준.
수강생이 건드리지 않는 곳(템플릿 고정): 그래프 배선(add_node/add_edge), compile.

LangGraph가 있으면 StateGraph로, 없으면 동일 흐름을 순수 파이썬으로 실행한다
(강의장 의존성 문제로 실습이 멈추지 않도록 한 graceful fallback).
"""
import argparse
import datetime
import json
import os
import sys
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import sast_agent, secret_agent, dependency_agent, threat_agent, report_agent
from agents.masking import looks_like_unmasked_secret

AUDIT_PATH = "memory/audit_log.jsonl"

# 발견(finding)이 갖춰야 할 필수 필드 — 누락 시 '품질 결함'으로 본다.
REQUIRED_FIELDS = ("title", "severity", "cwe", "file", "line", "evidence", "provenance")


# ── 감사 로그 (append-only) ──
def audit(agent, action, **kw):
    os.makedirs("memory", exist_ok=True)
    rec = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
           "agent": agent, "action": action, **kw}
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ── 노드 함수 (수강생 수정 영역) ──
def route_input(state):
    """입력 유형을 보고 점검 경로를 정한다. (수정 지점 1)"""
    state.setdefault("route", [])
    state["route"] = ["sast", "secret", "deps", "threat", "report"]
    audit("router", "route", target=state["target"], route=state["route"])
    return state


def node_sast(state):
    res = sast_agent.run(state["target"], state.get("policy", "policies/CLAUDE.md"))
    state["findings"].extend(res)
    audit("sast", "scan", outcome=f"{len(res)} findings")
    return state


def node_secret(state):
    res = secret_agent.run(state["target"])
    state["findings"].extend(res)
    audit("secret", "scan", outcome=f"{len(res)} findings(masked)")
    return state


def node_deps(state):
    res = dependency_agent.run(state["target"])
    state["findings"].extend(res)
    state["cves"].extend([f["cve"] for f in res if f.get("cve")])
    audit("dependency", "scan", outcome=f"{len(res)} deps", cves=state["cves"])
    return state


def node_threat(state):
    if not state.get("threat_intel"):
        return state
    ctx = threat_agent.run(state["cves"])  # threat_context.json 산출
    state["threat_ctx"] = ctx
    audit("threat", "lookup", outcome=f"{len(ctx)} cve ctx -> reports/threat_context.json")
    return state


def _is_malformed(f):
    """재시도로 회복 가능한 품질 결함: 필수 필드 누락 또는 High/Critical인데 근거 없음."""
    for k in REQUIRED_FIELDS:
        v = f.get(k)
        if v is None or v == "":
            return True
    if f["severity"] in ("High", "Critical") and not f["evidence"]:
        return True
    return False


def review(state):
    """검증 노드: PASS / RETRY / BLOCK 판정. (수정 지점 2)

    - BLOCK: 근거에 마스킹되지 않은 비밀 원문이 남음 → 정책 위반(회복 불가, 즉시 차단).
             또는 재시도를 소진하고도 품질 결함이 남는 경우.
    - RETRY: 품질 결함(필수 필드 누락 등)이 있고 재시도 여유가 있음 → 재스캔.
    - PASS : 정량(필드 완전성)·정성(비밀 비노출) 모두 통과.
    """
    findings = state["findings"]

    # 1) 정책 위반(비밀 원문 노출)은 재시도로 못 고친다 → 즉시 BLOCK
    leaking = [f for f in findings if looks_like_unmasked_secret(f.get("evidence", ""))]
    if leaking:
        state["verdict"] = "BLOCK"
        audit("reviewer", "verdict", verdict="BLOCK",
              basis=f"{len(leaking)} finding(s) with unmasked secret (policy violation)")
        return state

    # 2) 회복 가능한 품질 결함 → 재시도 여유가 있으면 RETRY (findings 초기화 후 재스캔)
    malformed = [f for f in findings if _is_malformed(f)]
    if malformed and state["retries"] < 2:
        state["retries"] += 1
        state["verdict"] = "RETRY"
        state["findings"] = []   # 재스캔 전 초기화 — 중복 누적 방지(langgraph·fallback 공통)
        state["cves"] = []
        state["threat_ctx"] = {}  # CVE가 줄어든 재스캔에서 이전 위협 컨텍스트가 남지 않도록
        audit("reviewer", "verdict", verdict="RETRY",
              basis=f"{len(malformed)} malformed finding(s), retry {state['retries']}/2")
        return state

    # 3) 재시도를 소진하고도 결함이 남으면 차단
    if malformed:
        state["verdict"] = "BLOCK"
        audit("reviewer", "verdict", verdict="BLOCK",
              basis=f"{len(malformed)} malformed finding(s) after {state['retries']} retries")
        return state

    state["verdict"] = "PASS"
    audit("reviewer", "verdict", verdict="PASS", basis="quant:ok, qual:ok")
    return state


def hitl_gate(state):
    """HITL: High 이상 발견에 사람 승인 강제. (--hitl 일 때만)"""
    if not state.get("hitl"):
        return state
    highs = [f for f in state["findings"] if f["severity"] in ("High", "Critical")]
    for f in highs:
        decision = _ask_human(f)
        audit("hitl", "decision", item=f["title"], decision=decision["action"],
              by="admin", reason=decision.get("reason"))
        if decision["action"] == "reject":
            f["confidence"] = "반려됨"
    return state


def node_report(state):
    out = "reports/final_report.md" if state.get("report") == "final" else "reports/lab3_report.md"
    # BLOCK 판정이면 정식 리포트를 만들지 않는다(유출 가능 데이터 덤프 방지).
    if state.get("verdict") == "BLOCK":
        os.makedirs("reports", exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write("# 점검 BLOCK — 리포트 생성 보류\n\n")
            f.write("검증 노드(review)가 정책 위반 또는 품질 결함을 발견해 정식 리포트 합성을 중단했습니다.\n")
            f.write("원인은 감사 로그(memory/audit_log.jsonl)의 `reviewer · verdict=BLOCK` 항목을 확인하세요.\n")
        state["report_path"] = out
        audit("report", "blocked", outcome=out)
        return state
    path = report_agent.build(state["findings"], state.get("threat_ctx", {}), out)
    state["report_path"] = path
    audit("report", "write", outcome=path, also="reports/risk_score_table.md")
    return state


def _ask_human(finding):
    """승인 대기. 비대화형(자동 채점) 환경에서는 기본값 거부(deny-by-default)."""
    prompt = (f"\n[HITL] 승인 대기 — {finding['severity']} {finding['title']} "
              f"({os.path.basename(finding['file'])}:{finding['line']})\n"
              f"  '확정'으로 포함할까요? [approve / reject <사유>]: ")
    try:
        if not sys.stdin.isatty():
            return {"action": "reject", "reason": "non-interactive default-deny"}
        ans = input(prompt).strip()
    except EOFError:
        return {"action": "reject", "reason": "no input (default-deny)"}
    if ans.lower().startswith("approve"):
        return {"action": "approve"}
    return {"action": "reject", "reason": ans[6:].strip() or "no reason"}


# ── 그래프 실행 (배선부 — 템플릿 고정) ──
def run_pipeline(state):
    try:
        from langgraph.graph import StateGraph, END
        from typing import TypedDict, List, Dict

        class SecurityState(TypedDict, total=False):
            target: str; policy: str; findings: List; cves: List; threat_ctx: Dict
            verdict: str; retries: int; report_path: str
            hitl: bool; threat_intel: bool; report: str; route: List

        g = StateGraph(SecurityState)
        g.add_node("router", route_input)
        g.add_node("sast", node_sast)
        g.add_node("secret", node_secret)
        g.add_node("deps", node_deps)
        g.add_node("threat", node_threat)
        g.add_node("review", review)
        g.add_node("hitl", hitl_gate)
        g.add_node("report", node_report)
        g.set_entry_point("router")
        for a, b in [("router", "sast"), ("sast", "secret"), ("secret", "deps"),
                     ("deps", "threat"), ("threat", "review")]:
            g.add_edge(a, b)
        def after_review(s):
            v = s.get("verdict")
            if v == "RETRY":
                return "sast"          # 결함 → 재스캔
            if v == "BLOCK":
                return "report"        # 차단 → HITL 건너뛰고 보류 리포트로
            return "hitl"              # PASS → 사람 승인 게이트
        g.add_conditional_edges("review", after_review,
                                {"sast": "sast", "hitl": "hitl", "report": "report"})
        g.add_edge("hitl", "report")
        g.add_edge("report", END)
        app = g.compile()
        return app.invoke(state)
    except Exception:
        # ── Fallback: 동일 흐름의 순수 파이썬 실행 (langgraph 경로와 동작 일치) ──
        state = route_input(state)
        for _ in range(3):
            state = node_sast(state)
            state = node_secret(state)
            state = node_deps(state)
            state = node_threat(state)
            state = review(state)
            if state.get("verdict") != "RETRY":
                break
            # RETRY 시 findings/cves 초기화는 review()가 담당(중복 누적 방지)
        if state.get("verdict") != "BLOCK":
            state = hitl_gate(state)   # BLOCK이면 HITL 건너뜀
        state = node_report(state)
        return state


def main():
    ap = argparse.ArgumentParser(description="Supervisor Graph — 멀티 에이전트 오케스트레이션")
    ap.add_argument("--target", default="sample_app/")
    ap.add_argument("--policy", default="policies/CLAUDE.md")
    ap.add_argument("--hitl", action="store_true", help="High 이상 발견에 사람 승인 강제")
    ap.add_argument("--threat-intel", action="store_true", help="CVE/KEV/EPSS 위협 정보 결합")
    ap.add_argument("--report", default="lab3", help="'final' 지정 시 final_report.md 생성")
    a = ap.parse_args()

    state = {"target": a.target, "policy": a.policy, "findings": [], "cves": [],
             "threat_ctx": {}, "retries": 0, "hitl": a.hitl,
             "threat_intel": a.threat_intel, "report": a.report}
    print(f"[Supervisor] 점검 시작 — target={a.target} hitl={a.hitl} TI={a.threat_intel}")
    result = run_pipeline(state)
    print(f"[Supervisor] 완료 — 발견 {len(result['findings'])}건 · "
          f"판정 {result.get('verdict')} · 리포트 {result.get('report_path')}")
    print(f"  감사 로그: {AUDIT_PATH}")


if __name__ == "__main__":
    main()
