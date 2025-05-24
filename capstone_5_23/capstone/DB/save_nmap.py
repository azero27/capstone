# DB/save_nmap.py
import mysql.connector
import re
from datetime import datetime


def parse_nmap_output(output, command, status, start_time, end_time, tool_id=1):
    nmap_output = output
    results = []

    ip_match = re.search(r'Nmap scan report for (?:[^\s]+ )?\(?([\d.]+)\)?', nmap_output)
    ip = ip_match.group(1) if ip_match else 'unknown'

    success_flag = 1 if "PORT" in nmap_output else 0

    # 시간 처리
    try:
        start_time = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end_time = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
    except:
        now = datetime.now()
        start_time = now
        end_time = now

    port_section_started = False

    for line in nmap_output.strip().splitlines():
        line = line.strip()
        if line.startswith("PORT"):
            port_section_started = True
            continue
        if not port_section_started or not line:
            continue

        match = re.match(r'^(\d+)/(\w+)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$', line)
        if match:
            port = int(match.group(1))
            protocol = match.group(2)
            status = match.group(3)
            service = match.group(4)
            version = match.group(5) if match.group(5) else ""

            results.append({
                "tool_id": tool_id,
                "target": ip,
                "command": command,
                "success": success_flag,
                "port_number": port,
                "port_status": status,
                "protocol": protocol,
                "service_name": service,
                "service_version": version.strip(),
                "logs": nmap_output,
                "start_time": start_time.strftime('%Y-%m-%d %H:%M:%S'),
                "end_time": end_time.strftime('%Y-%m-%d %H:%M:%S')
            })

    return results


def save_nmap_result(scan_result: dict, target_ip: str, tool_id: int):
    import mysql.connector
    from datetime import datetime
    from parses.parse_nmap import parse_nmap_port_scan_output

    parsed_services = parse_nmap_output(
        scan_result["output"],
        scan_result["command"],
        scan_result.get("status"),
        scan_result.get("start_time"),
        scan_result.get("end_time"),
        tool_id
    )

    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE",
        port=3306
    )
    cursor = conn.cursor()

    for svc in parsed_services:
        cursor.execute("""
            INSERT INTO NmapResult (
                tool_id, target, command, success,
                port_number, port_status, protocol,
                service_name, service_version, log,
                start_time, end_time
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            svc["tool_id"],
            svc["target"],
            svc["command"],
            svc["success"],
            svc["port_number"],
            svc["port_status"],
            svc["protocol"],
            svc["service_name"],
            svc["service_version"],
            svc["logs"],
            svc["start_time"],
            svc["end_time"]
        ))

    conn.commit()
    cursor.close()
    conn.close()
    print(f"[+] {target_ip} 스캔 결과 DB 저장 완료")

