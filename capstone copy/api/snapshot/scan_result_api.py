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

            tool_id = rows[0].get("tool_id")
            step = rows[0].get("step", 1)

            # 도구별 처리
            if tool_name == "Nmap":
                status = "success" if rows[0].get("success", 0) == 1 else "fail"
                open_ports = [str(r["port_number"]) for r in rows if r.get("port_status") == "open"]
                summary = ", ".join(open_ports) + " open" if open_ports else "No open port"
                log = rows[0].get("log", "(no log)")

            elif tool_name == "Amass":
                count = sum(1 for r in rows if r.get("success") == 1)
                status = "success" if count > 0 else "fail"
                summary = f"{count} subdomains found" if count else "No subdomains"
                log = "\n\n".join([r.get("log", "") for r in rows if r.get("log")])

            elif tool_name == "Nuclei":
                count = sum(1 for r in rows if r.get("success") == 1)
                status = "success" if count > 0 else "fail"
                summary = f"{count} CNAME records found" if count else "No CNAME record"
                log = "\n\n".join([r.get("log", "") for r in rows if r.get("log")])

            elif tool_name == "CloudEnum":
                count = sum(1 for r in rows if r.get("success") == 1)
                status = "success" if count > 0 else "fail"
                summary = f"{count} public services found" if count else "No public services"
                log = "\n\n".join([r.get("log", "") for r in rows if r.get("log")])

            elif tool_name == "S3scanner":
                buckets = [r["bucket_name"] for r in rows if r.get("bucket_name") and r.get("allusers_permission") not in (None, "", "[]")]
                status = "success" if buckets else "fail"
                summary = f"{len(buckets)} open buckets" if buckets else "No public buckets"
                log = "\n\n".join([r.get("log", "") for r in rows if r.get("log")])

            else:
                status = "success"
                summary = f"{tool_name} executed"
                log = rows[0].get("log", "(no log)")

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