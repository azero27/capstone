import subprocess
from typing import Optional

def convert_domain_to_ip(domain: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ['dig', '+short', domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        output = result.stdout.strip().splitlines()
        # 첫 번째 줄이 IP 주소일 수 있음 (AAAA는 제외)
        for line in output:
            if '.' in line:  # IPv4만 우선 고려
                return line.strip()
        return None
    except Exception as e:
        print(f"[ERROR] convert_domain_to_ip: {e}")
        return None


def convert_ip_to_domain(ip: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ['dig', '-x', ip, '+short'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        output = result.stdout.strip()
        return output if output else None
    except Exception as e:
        print(f"[ERROR] convert_ip_to_domain: {e}")
        return None
