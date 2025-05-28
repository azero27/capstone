from flask import Flask, jsonify
from datetime import datetime

app = Flask(__name__)

@app.route('/api/snapshots')
def get_mock_snapshots():
    mock_data = [
        {
            "id": 1,
            "start_time": "2025-05-03 19:00:00",
            "end_time": "2025-05-03 19:04:00"
        },
        {
            "id": 2,
            "start_time": "2025-05-03 18:00:00",
            "end_time": "2025-05-03 18:03:30"
        },
        {
            "id": 3,
            "start_time": "2025-05-03 17:00:00",
            "end_time": "2025-05-03 17:04:50"
        }
    ]
    return jsonify(mock_data)
