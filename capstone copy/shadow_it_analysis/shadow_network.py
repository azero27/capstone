import mysql.connector
import json

def analyze_shadow_network():
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT MAX(id) as latest_id FROM ScanResult")
    latest_result_id = cursor.fetchone()["latest_id"]
    print("[DEBUG] Latest scan_result_id:", latest_result_id)


    cursor.execute("""
        SELECT port_number, service_name
        FROM NmapResult
        WHERE scan_result_id = %s
    """, (latest_result_id,))
    nmap_entries = cursor.fetchall()
    nmap_set = set((entry["port_number"], entry["service_name"].lower()) for entry in nmap_entries)
    nmap_ports = set(entry["port_number"] for entry in nmap_entries)

    cursor.execute("SELECT port, service FROM PortList")
    port_list_entries = cursor.fetchall()
    portlist_set = set((item["port"], item["service"].lower()) for item in port_list_entries)
    portlist_ports = set(item["port"] for item in port_list_entries)

    findings = []

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

    for entry in nmap_entries:
        port = entry["port_number"]
        service = entry["service_name"].lower()
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
    
    print(json.dumps(findings, indent=2, ensure_ascii=False))

