from flask import Blueprint, jsonify
import mysql.connector
from datetime import datetime

archiving_bp = Blueprint('archiving', __name__)

@archiving_bp.route('/api/snapshots', methods=['GET'])
def get_snapshot_list():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="DBA",
            password="1234",
            database="SKYROUTE"
        )
        cursor = conn.cursor(dictionary=True)

        # ScanResult에서 ID, 시작 시간만 가져오기
        cursor.execute("SELECT id, start_time FROM ScanResult ORDER BY start_time DESC")
        rows = cursor.fetchall()

        # 시간 ISO 형식 문자열로 변환
        results = []
        for row in rows:
            results.append({
                "id": row["id"],
                "start_time": row["start_time"].isoformat()
            })

        cursor.close()
        conn.close()

        return jsonify(results)
    
    except Exception as e:
        print(f"[ERROR] /api/snapshots: {e}")
        return jsonify({"error": str(e)}), 500
