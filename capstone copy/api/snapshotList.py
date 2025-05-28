# capstone/api/snapshotList.py
from flask import Blueprint, jsonify

archiving_bp = Blueprint('archiving', __name__)

@archiving_bp.route('/api/snapshots', methods=['GET'])
def get_snapshot_list():

    # 실제 DB 대신 테스트용 데이터 반환 
    conn = [
        {"id": 1, "date": "01-JAN-2025", "time": "12:00"},
        {"id": 2, "date": "02-JAN-2025", "time": "13:30"},
        {"id": 3, "date": "03-JAN-2025", "time": "15:45"},
    ]

    
    return jsonify(conn)
