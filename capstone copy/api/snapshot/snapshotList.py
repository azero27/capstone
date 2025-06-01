# capstone/api/snapshotList.py
from flask import Blueprint, jsonify

archiving_bp = Blueprint('archiving', __name__)

@archiving_bp.route('/api/snapshots', methods=['GET'])
def get_snapshot_list():

    # 실제 DB 대신 테스트용 데이터 반환 
    conn = [
        { "id": 1, "start_time": "2025-01-01T12:00:00" },
        { "id": 2, "start_time": "2025-01-02T13:30:00" },
        { "id": 3, "start_time": "2025-01-03T15:45:00" }
    ]

    
    return jsonify(conn)