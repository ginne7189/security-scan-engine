"""
Security Tools MCP Server (mcp_servers/security_tools_server.py) — [Day 2 · LAB 2]

순수 보안 도구만 노출한다(에이전트 프록시 아님). 에이전트 조율은 orchestrator가 전담.
노출 도구: scan_code · detect_secrets · check_dependencies · lookup_cve
등록: claude mcp add security-tools -- python mcp_servers/security_tools_server.py
"""
import os
import sys
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import sast_agent, secret_agent, dependency_agent, threat_agent

try:
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("security-tools")
    _HAS_MCP = True
except Exception:
    _HAS_MCP = False


def scan_code(target: str = "sample_app/") -> list:
    """소스 코드를 정적 분석해 취약점 발견 목록을 반환한다."""
    return sast_agent.run(target)


def detect_secrets(target: str = "sample_app/") -> list:
    """하드코딩된 비밀을 탐지한다(값은 항상 마스킹)."""
    return secret_agent.run(target)


def check_dependencies(target: str = "sample_app/") -> list:
    """의존성을 취약점 DB와 대조해 영향 패키지/CVE를 반환한다."""
    return dependency_agent.run(target)


def lookup_cve(cves: list) -> dict:
    """CVE 목록의 KEV 등재 여부와 EPSS 점수를 조회한다."""
    return threat_agent.run(cves)


if _HAS_MCP:
    mcp.tool()(scan_code)
    mcp.tool()(detect_secrets)
    mcp.tool()(check_dependencies)
    mcp.tool()(lookup_cve)


if __name__ == "__main__":
    if _HAS_MCP:
        mcp.run(transport="stdio")
    else:
        print("[security-tools] mcp 미설치 — 도구 자체 점검")
        print("scan_code:", len(scan_code()), "건")
        print("detect_secrets:", len(detect_secrets()), "건")
        print("check_dependencies:", len(check_dependencies()), "건")
