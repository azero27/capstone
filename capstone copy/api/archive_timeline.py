# app.py

from flask import Flask, request, jsonify
import mysql.connector
from datetime import datetime

app = Flask(__name__)

# MySQL 접속 정보 (save_scan_result.py 스타일)
db_config = {
    'host':     'localhost',
    'user':     'DBA',
    'password': '1234',
    'database': 'SKYROUTE',
    'port':     3306,
    'charset':  'utf8mb4'
}

@app.route('/api/archives', methods=['GET'])
def get_archive_timeline():

    start_iso = request.args.get('start')  
    end_iso   = request.args.get('end')   

    # DB 연결
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

   
    sql = """
        SELECT timestamp, resource, description
          FROM archive_events
         WHERE 1
    """
    params = []

    # 필터 
    if start_iso:
        try:
            dt = datetime.fromisoformat(start_iso)
            sql += " AND timestamp >= %s"
            params.append(dt.strftime('%Y-%m-%d %H:%M:%S'))
        except ValueError:
            return jsonify({"error": "Invalid start format"}), 400

    if end_iso:
        try:
            dt = datetime.fromisoformat(end_iso)
            sql += " AND timestamp <= %s"
            params.append(dt.strftime('%Y-%m-%d %H:%M:%S'))
        except ValueError:
            return jsonify({"error": "Invalid end format"}), 400

    # 시간순 
    sql += " ORDER BY timestamp ASC"


    cursor.execute(sql, params)
    rows = cursor.fetchall()

    timeline = []
    for row in rows:
        ts: datetime = row['timestamp']
        timeline.append({
            "date": ts.strftime('%Y-%m-%dT%H:%M'),
            "rsc":  row['resource'],
            "dif":  row['description']
        })

    cursor.close()
    conn.close()


    return jsonify(timeline), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
