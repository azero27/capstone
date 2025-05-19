import re

def strip_ansi_codes(text: str) -> str:
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def parse_amass_output(output: str, meta: dict):
    # 전체 로그에서 ANSI 제거 (stdout + stderr 포함)
    full_log_clean = strip_ansi_codes(meta.get("output_log", ""))

    # 도메인만 포함할 클린 로그 생성
    lines = full_log_clean.strip().splitlines()
    subdomains = []

    for line in lines:
        line = line.strip()
        if line and not line.lower().startswith("the enumeration") and not line.lower().startswith("discoveries are being"):
            subdomains.append(line)

    logs_clean = "\n".join(subdomains)

    return {
        "tool_id": 2,
        "target": meta.get("target_url", ""),
        "command": meta.get("command"),
        "success": 1 if subdomains else 0,
        "subdomains": logs_clean,
        "logs": logs_clean,          # 도메인만 포함된 로그
        "logs_full": full_log_clean, # 전체 로그 (output_log 기반)
        "start_time": meta.get("start_time"),
        "end_time": meta.get("end_time")
    }
