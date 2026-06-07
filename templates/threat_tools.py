"""
Threat Intelligence 조회 도구 (templates/threat_tools.py) — [Day 4]

Day 4 실습에서 수강생이 이 세 함수를 agents/threat_agent.py 에 연결합니다.
모든 조회는 '교육용 오프라인 피드'를 사용합니다(외부 실호출 없음 · 방어적 점검).

  lookup_cve(cve)  : CVE 상세(심각도 라벨)
  check_kev(cve)   : KEV(실제 악용 확인) 등재 여부
  get_epss(cve)    : EPSS(30일 내 악용 확률 0~1)
"""

# 교육용 오프라인 데이터 (실제 NVD/CISA/FIRST 조회를 모사)
_CVE_DETAIL = {
    "CVE-2023-30861": {"severity": "Medium", "summary": "Flask 세션 쿠키 캐싱 취약점"},
    "CVE-2023-32681": {"severity": "Medium", "summary": "requests 프록시 자격증명 누출"},
    "CVE-2020-14343": {"severity": "High",   "summary": "PyYAML 임의 코드 실행(역직렬화)"},
    "CVE-2024-22195": {"severity": "Medium", "summary": "Jinja2 XSS via xmlattr 필터"},
}
_KEV_CATALOG = {"CVE-2020-14343", "CVE-2024-3094"}          # 실제 악용 확인 목록(모사)
_EPSS_FEED = {
    "CVE-2023-30861": 0.12, "CVE-2023-32681": 0.08,
    "CVE-2020-14343": 0.82, "CVE-2024-22195": 0.21,
}


def lookup_cve(cve: str) -> dict:
    """CVE 상세 정보를 반환(없으면 Unknown)."""
    return _CVE_DETAIL.get(cve, {"severity": "Unknown", "summary": "미수록 CVE"})


def check_kev(cve: str) -> bool:
    """KEV(실제 악용) 등재 여부."""
    return cve in _KEV_CATALOG


def get_epss(cve: str) -> float:
    """EPSS 점수(0~1). 미수록은 0.0."""
    return _EPSS_FEED.get(cve, 0.0)
