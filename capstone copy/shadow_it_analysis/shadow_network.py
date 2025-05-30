import mysql.connector
import json

def compare_and_store_shadow_network_findings():
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor(dictionary=True)

    # 1. 최신 ScanResult ID 가져오기
    cursor.execute("SELECT MAX(id) as latest_id FROM ScanResult")
    latest_result_id = cursor.fetchone()["latest_id"]

    # 2. NmapResult (해당 scan_result_id만)
    cursor.execute("""
        SELECT port, service
        FROM NmapResult
        WHERE scan_result_id = %s
    """, (latest_result_id,))
    nmap_entries = cursor.fetchall()
    nmap_set = set((entry["port"], entry["service"].lower()) for entry in nmap_entries)
    nmap_ports = set(entry["port"] for entry in nmap_entries)

    # 3. PortList 전체
    cursor.execute("SELECT port, service FROM PortList")
    port_list_entries = cursor.fetchall()
    portlist_set = set((item["port"], item["service"].lower()) for item in port_list_entries)
    portlist_ports = set(item["port"] for item in port_list_entries)

    # 4. 결과 분류
    findings = []

    # 4-1. 예상했지만 열려있지 않은 포트
    for (port, service) in portlist_set:
        if port not in nmap_ports:
            findings.append({
                "port": port,
                "expected_service": service,
                "actual_service": "closed",
                "reason": "Expected open port is closed",
                "type": "closed_expected_port",
                "scan_result_id": latest_result_id
            })

    # 4-2. 예상하지 못했지만 열린 포트
    for entry in nmap_entries:
        port = entry["port_number"]
        service = entry["service_name"].lower()
        target = entry["target"]
        if port not in portlist_ports:
            findings.append({
                "port": port,
                "actual_service": service,
                "expected_service": None,
                "reason": "Unexpected open port",
                "type": "unexpected_open_port",
                "scan_result_id": latest_result_id
            })
        elif (port, service) not in portlist_set:
            expected_service = next((e["service"] for e in port_list_entries if e["port"] == port), "N/A")
            findings.append({
                "port": port,
                "actual_service": service,
                "expected_service": expected_service,
                "reason": "Service mismatch",
                "type": "mismatched_service",
                "scan_result_id": latest_result_id
            })

    # 5. ShadowNetwork에 저장
    for f in findings:
        cursor.execute("""
            INSERT INTO ShadowNetwork (port, actual_service, expected_service, reason, scan_result_id)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            f["port"],
            f["actual_service"],
            f.get("expected_service"),
            f["reason"],
            f["scan_result_id"]
        ))

    conn.commit()
    cursor.close()
    conn.close()

    # 6. 결과 출력
    print(json.dumps(findings, indent=2, ensure_ascii=False))

