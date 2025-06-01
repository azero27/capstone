from flask import Blueprint, jsonify
import mysql.connector

scan_result_bp = Blueprint('scan_result', __name__)

@scan_result_bp.route('/api/snapshots/<int:scan_id>/scan_result', methods=['GET'])
def get_scan_result(scan_id):
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="DBA",
            password="1234",
            database="SKYROUTE"
        )
        cursor = conn.cursor(dictionary=True)

        results = []

        tools = [
            ("NmapResult",      "Nmap"),
            ("AmassResult",     "Amass"),
            ("NucleiResult",    "Nuclei"),
            ("CloudEnumResult", "CloudEnum"),
            ("S3scannerResult", "S3scanner"),
        ]

        for table, tool_name in tools:
            cursor.execute(f"SELECT * FROM {table} WHERE scan_result_id = %s", (scan_id,))
            rows = cursor.fetchall()

            if not rows:
                continue

            # 첫 행에서 공통 정보 추출
            first = rows[0]
            tool_id = first.get("tool_id")
            step = first.get("step", 1)
            status = "success" if first.get("success", 0) == 1 else "fail"
            log = first.get("log", "(no log)")

            # summary 생성
            if tool_name == "Nmap":
                open_ports = [
                    str(r["port_number"])
                    for r in rows
                    if r.get("port_status") == "open" and r.get("port_number") is not None
                ]
                summary = ", ".join(open_ports) + " open" if open_ports else "No open ports"
            elif tool_name == "Amass":
                domains = [r["domain"] for r in rows if r.get("success") == 1 and r.get("domain")]
                summary = f"{len(domains)} subdomains found" if domains else "No subdomains"
            elif tool_name == "Nuclei":
                vulns = [r for r in rows if r.get("success") == 1]
                summary = f"{len(vulns)} vulnerabilities" if vulns else "No vulnerabilities"
                log = "\n\n".join([r.get("log", "") for r in rows if r.get("log")])
            elif tool_name == "CloudEnum":
                public_services = [r["service"] for r in rows if r.get("success") == 1 and r.get("service")]
                summary = f"{len(public_services)} public services found" if public_services else "No public services"
                log = "\n\n".join([r.get("log", "") for r in rows if r.get("log")])
            elif tool_name == "S3scanner":
                buckets = [
                    r["bucket_name"]
                    for r in rows
                    if r.get("bucket_name") and r.get("allusers_permission") not in (None, "", "[]")
                ]
                summary = f"{len(buckets)} open buckets" if buckets else "No public buckets"
                log = "\n\n".join([r.get("log", "") for r in rows if r.get("log")])
            else:
                summary = f"{tool_name} executed"

            results.append({
                "step": step,
                "tool": tool_name,
                "tool_id": tool_id,
                "status": status,
                "log": log,
                "summary": summary
            })

        cursor.close()
        conn.close()
        return jsonify(results)

    except Exception as e:
        print(f"[ERROR] scan_result fetch failed: {e}")
        return jsonify({"error": str(e)}), 500
