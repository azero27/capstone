import re
from datetime import datetime

def parse_nmap_port_scan_output(output: str, command: str, status: str, start_time=None, end_time=None, tool_id=1):
    parsed_result = []

    # 타겟 IP 또는 도메인 추출
    match = re.search(r"Nmap scan report for (.+)", output)
    target = match.group(1).strip() if match else "unknown"

    # 문자열일 경우 datetime으로 파싱
    try:
        if isinstance(start_time, str):
            start_time = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        if isinstance(end_time, str):
            end_time = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
    except:
        now = datetime.now()
        start_time = start_time or now
        end_time = end_time or now

    # 포트 정보 추출
    for line in output.splitlines():
        line = line.strip()
        if re.match(r"^\d+/[a-z]+\s+open\s+\S+", line):
            parts = line.split()
            port_number = int(parts[0].split("/")[0])
            protocol = parts[0].split("/")[1]
            port_status = parts[1]
            service_name = parts[2]
            service_version = " ".join(parts[3:]) if len(parts) > 3 else ""

            parsed_result.append({
                "tool_id": tool_id,
                "target": target,
                "command": command,
                "success_failure": 1 if status == "success" else 0,
                "port_number": port_number,
                "port_status": port_status,
                "protocol": protocol,
                "service_name": service_name,
                "service_version": service_version,
                "logs": output,
                "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S")
            })

    return parsed_result
