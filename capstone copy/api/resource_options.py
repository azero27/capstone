# api/resource_options.py

from flask import Blueprint, jsonify

resource_bp = Blueprint('resource_bp', __name__)

@resource_bp.route('/api/resources', methods=['GET'])
def get_supported_resources():
    # 리포트에서 지원하는 리소스 종류
    supported_resources = ["port", "s3", "domain", "shadow_network", "shadow_resource", "shadow_domain"]
    return jsonify(supported_resources)
