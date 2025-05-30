from flask import Blueprint, jsonify

scan_result_bp = Blueprint('scan_result', __name__)

@scan_result_bp.route('/api/snapshots/<int:scan_id>/scan_result', methods=['GET'])
def get_scan_result(scan_id):
    # 실제로는 DB에서 scan_id 기준으로 조회하겠지만 지금은 mock data
    mock_results = [
        {
            "step": 1,
            "tool": "Nmap",
            "tool_id": 101,
            "status": "success",
            "log": "Open ports: 22, 80, 443",
            "summary": "22, 80, 443 open"
        },
        {
            "step": 2,
            "tool": "Amass",
            "tool_id": 201,
            "status": "fail",
            "log": "Failed to resolve domain",
            "summary": "Domain resolution failed"
        }
    ]
    return jsonify(mock_results)
