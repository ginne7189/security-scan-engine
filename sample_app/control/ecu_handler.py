"""
차량 제어 모듈 모사 (sample_app/control/ecu_handler.py)

policies/CLAUDE.md 의 '차량 제어 모듈은 한 단계 높은 심각도' 정책이
실제로 작동하는지 확인하기 위한 예제입니다.
이 파일의 Command Injection 발견은 정책 적용 시 High -> Critical 로 상향됩니다.
"""
import subprocess


def apply_firmware(cmd):
    # Command Injection (CWE-78) - 제어 모듈에서의 셸 실행은 특히 위험
    return subprocess.call(cmd, shell=True)
