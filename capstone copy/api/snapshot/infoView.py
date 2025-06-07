# capstone/api/snapshot/infoView.py

from flask import Blueprint, jsonify, request
import mysql.connector

info_bp = Blueprint('info', __name__)

@info_bp.route('/api/info/<int:scan_result_id>', methods=['GET'])
def get_information(scan_result_id):
    shadow_only = request.args.get('shadow_only', 'false').lower() == 'true'

    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="DBA",
            password="1234",
            database="SKYROUTE"
        )
        cursor = conn.cursor(dictionary=True)
        resource_data = []

        # 1. EC2 입력 IP
        cursor.execute("""
            SELECT ip, domain
            FROM CloudInfo
            WHERE id = (
                SELECT cloud_info_id FROM ScanResult WHERE id = %s
            )
        """, (scan_result_id,))
        row = cursor.fetchone()
        if row:
            ip = row["ip"]
            domain = row["domain"]
            resource_data.append({
                "type": "ec2",
                "value": domain or ip,  # 표시는 도메인이 우선
                "target": ip,           # 연결은 IP 기준
                "is_shadow": False,
                "contents": [
                    f"Domain: {domain}" if domain else "Domain: 없음",
                    f"IP: {ip}"
                ]
            })

        # 2. ShadowNetwork 로딩 (포트 기반)
        cursor.execute("""
            SELECT port, reason FROM ShadowNetwork WHERE scan_result_id = %s
        """, (scan_result_id,))
        shadow_ports = set()
        shadow_port_reasons = {}
        for r in cursor.fetchall():
            port = str(r["port"])
            shadow_ports.add(port)
            shadow_port_reasons[port] = r["reason"]

        # 3. ShadowResource 로딩 (도메인, s3 기반)
        cursor.execute("""
            SELECT bucket_name, reason
            FROM ShadowResource
            WHERE scan_result_id = %s
        """, (scan_result_id,))
        shadow_resources = set()
        shadow_s3_reasons = {}
        for r in cursor.fetchall():
            bucket = r["bucket_name"]
            shadow_resources.add(bucket)
            shadow_s3_reasons[bucket] = r["reason"]

        # 4. NmapResult → 포트
        cursor.execute("""
            SELECT port_number, protocol, service_name, service_version, target
            FROM NmapResult
            WHERE scan_result_id = %s
        """, (scan_result_id,))
        for row in cursor.fetchall():
            port = str(row["port_number"])
            contents = [
                f"Port: {port}",
                f"Protocol: {row['protocol']}",
                f"Service: {row['service_name']}",
                f"Version: {row['service_version']}"
            ]

            
            is_shadow = port in shadow_ports
            if is_shadow and port in shadow_port_reasons:
                contents.insert(0, f"[Shadow IT] {shadow_port_reasons[port]}")

            resource_data.append({
                "type": "port",
                "value": port,
                "target": row["target"],
                "is_shadow": is_shadow,
                "contents": contents
            })


        # NucleiResult → 도메인 기반 Shadow 리소스
        cursor.execute("""
            SELECT target, risk_level, url
            FROM NucleiResult
            WHERE scan_result_id = %s
        """, (scan_result_id,))
        for row in cursor.fetchall():
            domain = row["target"]
            risk = (row["risk_level"] or "").lower()
            url = row["url"] or "(url 없음)"
            is_shadow = risk == "high"  # ✅ high일 때만 Shadow 처리

            # URL 내용을 줄 단위로 분리 & "URL:" 제거
            url_raw = row.get("url", "")
            url_lines = [line for line in url_raw.strip().splitlines() if line.strip().lower() != "url:"]

            # 최종 contents 구성
            contents = [f"Domain: {domain}"] + url_lines

            if is_shadow:
                contents.insert(0, "[Shadow IT] Dangling DNS 탐지")

            resource_data.append({
                "type": "domain",
                "value": domain,
                "target": domain,
                "is_shadow": is_shadow,
                "contents": contents
            })


        # 6. S3scannerResult → S3
        cursor.execute("""
            SELECT R.bucket_name, R.allusers_permission, R.authusers_permission, O.object
            FROM S3scannerResult R
            LEFT JOIN S3scannerObject O ON R.id = O.s3scanner_id
            WHERE R.scan_result_id = %s
        """, (scan_result_id,))

        from collections import defaultdict

        bucket_info = defaultdict(lambda: {
            "files": [],
            "allusers": None,
            "authusers": None
        })

        for row in cursor.fetchall():
            bucket = row["bucket_name"]
            if row["object"]:
                bucket_info[bucket]["files"].append(row["object"])
            bucket_info[bucket]["allusers"] = row["allusers_permission"]
            bucket_info[bucket]["authusers"] = row["authusers_permission"]

        for bucket, info in bucket_info.items():
            perm_strs = []
            if info["allusers"] not in (None, "", "[]"):
                perm_strs.append(f"AllUsers: {info['allusers']}")
            if info["authusers"] not in (None, "", "[]"):
                perm_strs.append(f"AuthUsers: {info['authusers']}")
            if not perm_strs:
                perm_strs = ["Private"]

            files = info["files"] or ["(no objects)"]
            contents = perm_strs + files

            is_shadow = bucket in shadow_resources
            if is_shadow and bucket in shadow_s3_reasons:
                contents.insert(0, f"[Shadow IT] {shadow_s3_reasons[bucket]}")

            resource_data.append({
                "type": "s3",
                "value": bucket,
                "target": "s3.amazonaws.com",
                "is_shadow": is_shadow,
                "contents": contents
            })


        cursor.close()
        conn.close()

        if shadow_only:
            resource_data = [r for r in resource_data if r["is_shadow"]]

        return jsonify(resource_data)

    except Exception as e:
        print(f"[ERROR] /api/info/{scan_result_id} failed: {e}")
        return jsonify({"error": str(e)}), 500
