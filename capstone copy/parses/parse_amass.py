import re
from datetime import datetime

def strip_ansi_codes(text: str) -> str:
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def parse_amass_output(output: str, meta: dict):
    full_log_clean = strip_ansi_codes(meta.get("output_log", ""))
    lines = full_log_clean.strip().splitlines()
    subdomains = []

    for line in lines:
        line = line.strip()
        if line and not line.lower().startswith("the enumeration") and not line.lower().startswith("discoveries are being"):
            subdomains.append(line)

    logs_clean = "\n".join(subdomains)

    return [
        {
            "tool_id": 3,
            "target": meta.get("target_url", ""),
            "command": meta.get("command"),
            "status": meta.get("status"),
            "subdomain": sub,
            "logs": logs_clean,
            "start_time": meta.get("start_time"),
            "end_time": meta.get("end_time")
        }
        for sub in subdomains
    ]
