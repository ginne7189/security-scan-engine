#!/usr/bin/env python3
"""환경 점검 (check_env.py) — Day 1 · LAB 0. 5개 항목을 일괄 점검한다."""
import importlib.util
import os
import shutil
import subprocess
import sys
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


def ok(label, hint=""): print(f"[OK]   {label}")
def warn(label): print(f"[WARN] {label}")
def fail(label, hint=""): print(f"[FAIL] {label}" + (f"  → {hint}" if hint else ""))


def main():
    passed = True

    # 0) 실행 환경 — Codespaces 여부 / 저장소 루트 / CLI 존재
    if os.getenv("CODESPACES") == "true" or os.getenv("CODESPACE_NAME"):
        ok("Codespaces runtime")
    else:
        warn("Codespaces 외 환경 — 로컬 실행도 가능하지만 수업 표준은 Codespaces")

    if os.path.exists("check_env.py") and os.path.isdir("agents") and os.path.isdir("mcp_servers"):
        ok("repo root")
    else:
        fail("repo root", "저장소 최상위에서 실행하세요 (check_env.py·agents/·mcp_servers/가 보여야 함)")
        passed = False

    if shutil.which("claude"):
        try:
            v = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=5)
            ok(f"claude CLI ({(v.stdout or v.stderr).strip().splitlines()[0][:40]})" if (v.stdout or v.stderr).strip() else "claude CLI")
        except Exception:
            ok("claude CLI")
    else:
        warn("claude CLI 미확인 — Day 2 확장 실습(claude mcp add) 전 설치·로그인 필요")

    if shutil.which("codex"):
        ok("codex CLI")
    else:
        warn("codex CLI 미확인 — Codex 선택 실습이면 설치 필요 (미사용 시 무시)")

    # 1) Python 3.12+
    v = sys.version_info
    if v >= (3, 12):
        ok(f"Python {v.major}.{v.minor}")
    else:
        fail(f"Python {v.major}.{v.minor}", "Python 3.12 이상 권장"); passed = False

    # 2) 핵심 패키지
    core_ok = True
    if importlib.util.find_spec("flask") is None:
        fail("packages: flask", "pip install -r requirements.txt"); core_ok = False
    if importlib.util.find_spec("langgraph") is None:
        warn("langgraph 미설치 — 순수 파이썬 fallback으로 동작합니다")
    if core_ok:
        ok("packages")
    passed &= core_ok

    # 3) API 키 (없어도 도구 기반 동작 → 경고 수준)
    key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY")
    if key:
        ok("API key")
    else:
        warn("API key 미설정 — 도구 기반 분석은 가능, LLM 해석은 건너뜀")

    # 4) MCP 서버 파일 존재 확인 (실제 'claude mcp add' 등록은 LAB 0에서 별도 수행)
    if os.path.exists("mcp_servers/security_tools_server.py"):
        ok("mcp_servers/security_tools_server.py exists")
    else:
        fail("mcp_servers/security_tools_server.py", "mcp_servers/security_tools_server.py 없음"); passed = False

    # 5) 점검 대상
    if os.path.exists("sample_app/vulnerability.py"):
        ok("sample_app")
    else:
        fail("sample_app", "저장소를 다시 클론하세요"); passed = False

    print()
    if passed:
        print("환경 점검 통과 — LAB 1로 진행하세요.")
        sys.exit(0)
    else:
        print("일부 항목 실패 — README의 Troubleshooting(T0)을 참고하세요.")
        sys.exit(1)


if __name__ == "__main__":
    main()
