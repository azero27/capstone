from flask import Blueprint, request, jsonify
import mysql.connector
from datetime import datetime

timeline_bp = Blueprint('timeline_bp', __name__)

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )

@timeline_bp.route('/api/timeline_nodes', methods=['POST'])
def timeline_nodes():
    data = request.get_json()
    start = data.get("start")
    end = data.get("end")

    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        # 시간 범위에 해당하는 scan_result_id 목록 가져오기
        cursor.execute("""
            SELECT id, start_time FROM ScanResult
            WHERE start_time BETWEEN %s AND %s
        """, (start, end))
        scan_results = cursor.fetchall()
        scan_ids = [r["id"] for r in scan_results]
        id_to_time = {r["id"]: r["start_time"] for r in scan_results}

        all_rows = []

        if scan_ids:
            format_ids = ",".join(map(str, scan_ids))

            # EC2 = Amass + Nuclei
            cursor.execute(f"""
                SELECT scan_result_id, target, diff_type, description
                FROM AmassDiff
                WHERE scan_result_id IN ({format_ids})
            """)

            for row in cursor.fetchall():
                all_rows.append({
                    "rsc": "EC2",
                    "date": id_to_time[row["scan_result_id"]].isoformat(),
                    "type": row["diff_type"],
                    "dif": f"[Amass] {row['description']}"
                })

            cursor.execute(f"""
                SELECT scan_result_id, target, diff_type, description
                FROM NucleiDiff
                WHERE scan_result_id IN ({format_ids})
            """)

            for row in cursor.fetchall():
                all_rows.append({
                    "rsc": "EC2",
                    "date": id_to_time[row["scan_result_id"]].isoformat(),
                    "type": row["diff_type"],
                    "dif": f"[Nuclei] {row['description']}"
                })

            # S3 = S3scanner + CloudEnum
            cursor.execute(f"""
                SELECT scan_result_id, target, diff_type, description
                FROM S3scannerDiff
                WHERE scan_result_id IN ({format_ids})
            """)

            for row in cursor.fetchall():
                all_rows.append({
                    "rsc": "S3",
                    "date": id_to_time[row["scan_result_id"]].isoformat(),
                    "type": row["diff_type"],
                    "dif": f"[S3scanner] {row['description']}"
                })

            cursor.execute(f"""
                SELECT scan_result_id, target, diff_type, description
                FROM CloudEnumDiff
                WHERE scan_result_id IN ({format_ids})
            """)

            for row in cursor.fetchall():
                all_rows.append({
                    "rsc": "S3",
                    "date": id_to_time[row["scan_result_id"]].isoformat(),
                    "type": row["diff_type"],
                    "dif": f"[CloudEnum] {row['description']}"
                })

            # NmapDiff -> PORT 리소스로 변환
            cursor.execute(f"""
                SELECT scan_result_id, target, port_number, protocol, diff_type, description
                FROM NmapDiff
                WHERE scan_result_id IN ({format_ids})
            """)
            for row in cursor.fetchall():
                all_rows.append({
                    "rsc": "PORT",
                    "date": id_to_time[row["scan_result_id"]].isoformat(),
                    "type": row["diff_type"],
                    "dif": f"{row['target']}:{row['port_number']}/{row['protocol']} - {row['description']}"
                })
                
            # ShadowNetworkDiff
            cursor.execute(f"""
                SELECT scan_result_id, target, diff_type, description
                FROM ShadowNetworkDiff
                WHERE scan_result_id IN ({format_ids})
            """)
            for row in cursor.fetchall():
                all_rows.append({
                    "rsc": "PORT",  # 시각화에선 PORT로 취급
                    "date": id_to_time[row["scan_result_id"]].isoformat(),
                    "type": row["diff_type"],
                    "dif": f"Port {row['target']} - {row['description']}"
                })

            # ShadowResourceDiff
            cursor.execute(f"""
                SELECT scan_result_id, target, diff_type, description
                FROM ShadowResourceDiff
                WHERE scan_result_id IN ({format_ids})
            """)
            for row in cursor.fetchall():
                all_rows.append({
                    "rsc": "S3",  # 시각화에선 S3 리소스와 병합
                    "date": id_to_time[row["scan_result_id"]].isoformat(),
                    "type": row["diff_type"],
                    "dif": f"Bucket {row['target']} - {row['description']}"
                })
            
        all_rows.sort(key=lambda x: x["date"], reverse=True)
        return jsonify(all_rows)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()