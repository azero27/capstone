import mysql.connector
import re
from datetime import datetime

def save_nmap_result(scan_result: dict, target_ip: str, tool_id: int, scan_result_id: int, step: int):
    from parses.parse_nmap import parse_nmap_port_scan_output

    parsed_services = parse_nmap_port_scan_output(
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
                start_time, end_time,
                scan_result_id, step
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            svc["tool_id"],
            svc["target"],
            svc["command"],
            svc["success_failure"],
            svc["port_number"],
            svc["port_status"],
            svc["protocol"],
            svc["service_name"],
            svc["service_version"],
            svc["logs"],
            svc["start_time"],
            svc["end_time"],
            scan_result_id,
            step
        ))

    conn.commit()
    cursor.close()
    conn.close()
    print(f"[+] {target_ip} 스캔 결과 DB 저장 완료")
