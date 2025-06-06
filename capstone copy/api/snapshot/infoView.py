# capstone/api/infoView.py

from flask import Blueprint, jsonify

info_bp = Blueprint('info', __name__)

@info_bp.route('/api/info/<int:snapshot_id>', methods=['GET'])
def get_information(snapshot_id):
    dummy_data = [
        {"type": "port", "value": "22", "target": "15.165.170.99", "is_shadow": True},
        {"type": "port", "value": "80", "target": "15.165.170.99", "is_shadow": False},
        {"type": "s3", "value": "skyroute7", "target": "s3.amazonaws.com", "is_shadow": True},
        {"type": "s3", "value": "public.sskyroute", "target": "s3.amazonaws.com", "is_shadow": False}
    ]
    return jsonify(dummy_data)
