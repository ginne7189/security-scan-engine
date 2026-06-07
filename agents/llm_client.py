"""
LLM 해석 클라이언트 (agents/llm_client.py)

결정론적 도구가 찾은 '발견(findings)'을 LLM이 자연어로 해석·우선순위화하는 레이어.
이 랩의 핵심/부가 로직 분리 철학을 따른다:

  - 핵심(필수): 정규식 도구가 발견을 찾고 리포트를 만든다  → 키 없이도 항상 동작.
  - 부가(선택): LLM 이 그 발견을 사람이 읽기 좋게 해석한다  → 키 있으면 동작.

프로바이더 자동 선택:
  - ANTHROPIC_API_KEY 가 있으면 Claude(SECLAB_MODEL, 기본 claude-sonnet-4-6),
  - 없고 OPENAI_API_KEY 가 있으면 GPT(OPENAI_MODEL, 기본 gpt-4o-mini),
  - 둘 다 없거나 호출이 실패하면 결정론적 fallback 요약.
    → 외부 API 실패가 핵심 파이프라인을 절대 막지 않는다(방어적 설계).

LLM 에는 '마스킹된 근거'만 전달한다 — 비밀 원문은 외부로 나가지 않는다.
"""
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    from agents.masking import mask_secret_evidence
except ImportError:  # `python agents/...` 처럼 agents/ 가 sys.path[0]일 때
    from masking import mask_secret_evidence

ANTHROPIC_MODEL = os.getenv("SECLAB_MODEL", "claude-sonnet-4-6")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

PROMPT = """당신은 보안 점검 결과를 경영진에게 보고하는 시니어 보안 분석가입니다.
아래는 자동 점검 도구가 찾은 발견 목록(JSON)입니다. 비밀값은 이미 ****로 마스킹돼 있습니다.

이를 바탕으로 한국어로 작성하세요:
1) 핵심 요약 3~4문장 (가장 시급한 위험 중심)
2) 즉시 대응 Top 3 (각 1줄, 근거 포함)

규칙: 발견 목록에 없는 내용을 지어내지 마세요. 비밀값 원문을 복원하려 하지 마세요.

발견 목록:
{data}
"""


def _provider():
    """사용할 LLM 프로바이더를 결정한다(키 우선순위: Anthropic → OpenAI)."""
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    return None


def _sdk_ok(provider):
    try:
        if provider == "anthropic":
            import anthropic  # noqa: F401
            return True
        if provider == "openai":
            import openai  # noqa: F401
            return True
    except Exception:
        return False
    return False


def llm_available():
    """실제 LLM 호출이 가능한 환경인지 (키 + 해당 SDK 모두 존재)."""
    p = _provider()
    return bool(p) and _sdk_ok(p)


def active_model():
    p = _provider()
    return {"anthropic": ANTHROPIC_MODEL, "openai": OPENAI_MODEL}.get(p)


def mode_label():
    """리포트/콘솔에 표시할 현재 모드 문자열."""
    if llm_available():
        return f"실제 LLM 호출 ({_provider()}:{active_model()})"
    return "결정론적 fallback (LLM 키 미설정)"


def _compact(findings, limit=20):
    """LLM 입력용으로 발견을 마스킹·축약한다(토큰 절약 + 비밀 비노출)."""
    rows = []
    for f in findings[:limit]:
        rows.append({
            "severity": f.get("severity"),
            "title": f.get("title"),
            "cwe": f.get("cwe"),
            "file": os.path.basename(f.get("file", "")),
            "line": f.get("line"),
            "evidence": mask_secret_evidence(f.get("evidence", ""))[:120],
            "cve": f.get("cve"),
        })
    return rows


def _fallback_summary(findings):
    """LLM 없이도 항상 동작하는 결정론적 요약."""
    from collections import Counter
    sev = Counter(f.get("severity", "?") for f in findings)
    parts = [f"{s} {sev[s]}건" for s in ("Critical", "High", "Medium", "Low") if sev.get(s)]
    return ("(LLM 미설정 — 결정론적 요약) "
            f"총 {len(findings)}건: " + ", ".join(parts) + ". "
            "ANTHROPIC_API_KEY 또는 OPENAI_API_KEY 설정 시 LLM 자연어 해석이 생성됩니다.")


def _call_anthropic(prompt):
    import anthropic
    msg = anthropic.Anthropic().messages.create(
        model=ANTHROPIC_MODEL, max_tokens=700,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()


def _call_openai(prompt):
    import openai
    resp = openai.OpenAI().chat.completions.create(
        model=OPENAI_MODEL, max_tokens=700,
        messages=[{"role": "user", "content": prompt}],
    )
    return (resp.choices[0].message.content or "").strip()


def complete(system, user, max_tokens=600):
    """주어진 '시스템 프롬프트(정책)'로 LLM 을 호출한다 — Day1 '하네스' 데모용.

    같은 user 입력이라도 system(정책)을 바꾸면 출력이 달라지는 것을 보여준다.
    키가 없거나 호출 실패면 None 을 반환 → 호출 측에서 규칙 fallback 으로 안전 강하.
    """
    if not llm_available():
        return None
    try:
        if _provider() == "anthropic":
            import anthropic
            msg = anthropic.Anthropic().messages.create(
                model=ANTHROPIC_MODEL, max_tokens=max_tokens, system=system,
                messages=[{"role": "user", "content": user}],
            )
            return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
        import openai
        resp = openai.OpenAI().chat.completions.create(
            model=OPENAI_MODEL, max_tokens=max_tokens,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception:
        return None  # 외부 API 실패가 실습을 막지 않는다


def interpret(findings, threat_ctx=None):
    """발견을 LLM 으로 해석한 텍스트를 반환. 불가/실패 시 결정론적 fallback."""
    if not findings:
        return "(발견 없음 — 해석 생략)"
    if not llm_available():
        return _fallback_summary(findings)
    try:
        import json
        data = json.dumps(_compact(findings), ensure_ascii=False, indent=2)
        prompt = PROMPT.format(data=data)
        text = _call_anthropic(prompt) if _provider() == "anthropic" else _call_openai(prompt)
        return text or _fallback_summary(findings)
    except Exception as e:
        # 외부 API 실패가 핵심 로직을 막지 않는다 — fallback 으로 안전 강하.
        return _fallback_summary(findings) + f"\n(참고: LLM 호출 실패 — {type(e).__name__})"


if __name__ == "__main__":
    demo = [
        {"severity": "Critical", "title": "Command Injection 의심", "cwe": "CWE-78",
         "file": "ecu_handler.py", "line": 13, "evidence": "subprocess.call(cmd, shell=True)", "cve": None},
        {"severity": "High", "title": "하드코딩 자격증명", "cwe": "CWE-798",
         "file": "vulnerability.py", "line": 31, "evidence": 'API_TOKEN = "****"', "cve": None},
    ]
    print(f"[llm_client] 모드: {mode_label()}")
    print(interpret(demo))
