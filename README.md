# 🛡️ security-scan-engine

규칙 기반 **보안 취약점 스캐닝 엔진**. 키·외부 API 없이 결정론적으로 동작하며,
LLM 키가 있으면 발견 결과를 자연어로 해석하는 레이어가 추가됩니다.

> `security-agent-lab` 모노레포에서 **스캐닝 엔진**만 떼어낸 독립 저장소입니다.
> (교육용 Day 1~5 Streamlit 실습은 `security-agent-lab-day1` ~ `security-agent-lab-day5` 저장소 참고)

## 구성

| 디렉터리 | 역할 |
|---|---|
| `agents/` | 핵심 에이전트 — `sast`(코드 취약점)·`secret`(비밀값)·`dependency`(CVE)·`threat`(KEV/EPSS)·`report` + `masking`·`llm_client` |
| `sample_app/` | 점검 대상 — 의도적으로 취약점을 심은 샘플 코드 (`vulnerability.py`, `control/ecu_handler.py`) |
| `policies/` | 정책(시스템 프롬프트) — `CLAUDE.md`(차량 모듈 가중) / `CLAUDE_base.md` |
| `templates/` | `threat_tools` — CVE→KEV/EPSS 조회 도구 |
| `orchestrator/` | `supervisor_graph` — 검증·HITL·차단 게이트가 포함된 통합 파이프라인 |
| `mcp_servers/` | `security_tools_server` — MCP 서버로 도구 노출 |
| `scripts/` | CLI 데모 (`run_lab1_*`, `run_lab2_mcp_demo`, `run_llm_interpret` …) |
| `tests/` | 마스킹 계약·시크릿/의존성·LLM·리뷰 게이트 테스트 |

## 빠른 시작

```bash
pip install -r requirements.txt
python check_env.py            # 환경 점검
pytest -q                      # 전체 테스트 (키 불필요)

# 개별 에이전트 직접 실행
python -m agents.sast_agent --target sample_app/ --policy policies/CLAUDE.md
python -m agents.secret_agent --target sample_app/
python -m agents.dependency_agent --target sample_app/

# 통합 파이프라인(검증·HITL·위협정보·리포트)
python orchestrator/supervisor_graph.py --target sample_app/ --threat-intel --report final
```

LLM 해석 레이어를 켜려면 `.env` 에 `ANTHROPIC_API_KEY`(또는 `OPENAI_API_KEY`)를 넣으세요.
키가 없어도 모든 스캐너는 규칙 기반으로 끝까지 동작합니다.

<!-- NAV -->

## 🔗 관련 저장소 (5일 과정 전체)

| | 저장소 | 내용 |
|---|---|---|
|  | [`security-agent-lab-day1`](https://github.com/ginne7189/security-agent-lab-day1) | Day 1 · 정책이 결과를 바꾼다 |
|  | [`security-agent-lab-day2`](https://github.com/ginne7189/security-agent-lab-day2) | Day 2 · 도구 호출 & 결과 분리 |
|  | [`security-agent-lab-day3`](https://github.com/ginne7189/security-agent-lab-day3) | Day 3 · 멀티에이전트 = 역할 분리 |
|  | [`security-agent-lab-day4`](https://github.com/ginne7189/security-agent-lab-day4) | Day 4 · 위험도 점수화 |
|  | [`security-agent-lab-day5`](https://github.com/ginne7189/security-agent-lab-day5) | Day 5 · 통합 |
| 👉 **현재** | [`security-scan-engine`](https://github.com/ginne7189/security-scan-engine) | 🛠️ 스캐닝 엔진 코어 (SAST·Secret·Dependency·Threat) |

