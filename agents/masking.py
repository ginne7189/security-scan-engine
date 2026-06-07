"""
Secret masking (agents/masking.py)

정책(policies/CLAUDE.md): '비밀 값은 어떤 출력에서도 원문을 표시하지 않는다(마스킹 필수)'.
SAST·Secret·Report 어느 출구에서든 동일하게 적용되도록 단일 구현으로 통합한다.

[수정 이력]
이전에는 sast_agent / report_agent 에 같은 정규식이 각각 복붙돼 있었고,
raw string 안의 `\\s`(공백이 아니라 'literal 백슬래시+s')와 치환문의 `\\1`
(그룹참조가 아니라 'literal \\1') 때문에 마스킹이 깨져 있었다.
그 결과 sk- 접두 키만 우연히 가려지고 PASSWORD/AWS키/차량 진단시드는
평문으로 리포트에 유출됐다. 본 모듈로 통합하며 바로잡았다.
"""
import re

# 1) 키 이름으로 식별되는 비밀:  KEY = "value"  /  KEY = 'value'
#    변수명·따옴표·형식은 보존하고 값만 ****로 치환한다.
_KV_RE = re.compile(
    r"(?i)\b(API_TOKEN|API_KEY|SECRET|PASSWORD|PWD|TOKEN)(\s*=\s*)(['\"])[^'\"]+(['\"])"
)

# 2) 키 이름 없이도 형태로 식별되는 토큰형 비밀
_TOKEN_RES = [
    (re.compile(r"sk-[A-Za-z0-9_\-]+"), "sk-****"),               # OpenAI/Anthropic 류
    (re.compile(r"ghp_[A-Za-z0-9]+"), "ghp_****"),                # GitHub PAT
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA****"),                # AWS Access Key
    (re.compile(r"uds-seed-0x[0-9A-Fa-f]+"), "uds-seed-0x****"),  # 차량 진단 시드
]


def mask_secret_evidence(text):
    """근거 코드 한 줄에서 비밀값 원문을 마스킹한다(변수명·형식은 보존)."""
    if not text:
        return text
    text = _KV_RE.sub(r"\1\2\3****\4", text)
    for rx, repl in _TOKEN_RES:
        text = rx.sub(repl, text)
    return text


# ── 무결성 점검: '마스킹이 누락된 원문 비밀'을 식별 ──
# 정상 마스킹 결과(sk-****, AKIA****, uds-seed-0x****, ghp_****, KEY="****")는
# 모두 매칭되지 않는다. 상류 Agent가 마스킹을 빠뜨렸을 때만 True가 된다.
_RAW_TOKEN_RES = [
    # sk-live-/sk-proj-/sk-ant- 등 OpenAI·Anthropic 키 원문 (마스킹 시 sk-****).
    # \b 로 단어 경계를 요구해 'task-'·'risk-' 같은 단어 중간 오탐을 막는다.
    re.compile(r"\bsk-(?:live|test|proj|ant|or|svcacct)-[A-Za-z0-9]"),
    re.compile(r"AKIA[0-9A-Z]{16}"),           # AWS Access Key 원문
    re.compile(r"uds-seed-0x[0-9A-Fa-f]{2,}"), # 차량 진단 시드 원문
    re.compile(r"ghp_[A-Za-z0-9]{8,}"),        # GitHub PAT 원문
]
_KV_RAW_RE = re.compile(
    r"(?i)\b(?:API_TOKEN|API_KEY|SECRET|PASSWORD|PWD|TOKEN)\s*=\s*['\"][^'\"]+['\"]"
)


def looks_like_unmasked_secret(text):
    """근거에 마스킹되지 않은 비밀 원문이 남아 있으면 True(리뷰 무결성 게이트용)."""
    if not text:
        return False
    if any(rx.search(text) for rx in _RAW_TOKEN_RES):
        return True
    m = _KV_RAW_RE.search(text)
    # 비밀 키워드의 따옴표 값에 마스킹 마커(****)가 전혀 없으면 누락으로 본다
    return bool(m and "****" not in m.group(0))
