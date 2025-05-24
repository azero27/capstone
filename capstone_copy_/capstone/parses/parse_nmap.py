import re
from datetime import datetime

def parse_nmap_port_scan_output(output: str, command: str, status: str, start_time=None, end_time=None, tool_id=1):
    parsed_result = []

    match = re.search(r"Nmap scan report for (.+)", output)
    target = match.group(1).strip() if match else "unknown"

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
                "success_failure": status,
                "port_number": port_number,
                "port_status": port_status,
                "protocol": protocol,
                "service_name": service_name,
                "service_version": service_version,
                "logs": output,
                "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S") if start_time else None,
                "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S") if end_time else None
            })

    return parsed_result