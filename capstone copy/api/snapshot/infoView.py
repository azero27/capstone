# capstone/api/infoView.py

from flask import Blueprint, jsonify, request

info_bp = Blueprint('info', __name__)

@info_bp.route('/api/info/<int:snapshot_id>', methods=['GET'])
def get_information(snapshot_id):
    # Get shadow_only parameter from query string
    shadow_only = request.args.get('shadow_only', 'false').lower() == 'true'
    
    # Comprehensive dummy data with various resource types
    dummy_data = [
        # Port resources
        {"type": "port", "value": "22", "target": "15.165.170.99", "is_shadow": True},
        {"type": "port", "value": "80", "target": "15.165.170.99", "is_shadow": False},
        {"type": "port", "value": "443", "target": "15.165.170.99", "is_shadow": False},
        {"type": "port", "value": "3389", "target": "15.165.170.99", "is_shadow": True},
        
        # S3 resources
        {"type": "s3", "value": "skyroute7", "target": "s3.amazonaws.com", "is_shadow": True},
        {"type": "s3", "value": "public.sskyroute", "target": "s3.amazonaws.com", "is_shadow": False},
        {"type": "s3", "value": "backup-data-2024", "target": "s3.amazonaws.com", "is_shadow": True},
        
        # Domain resources
        {"type": "domain", "value": "api.skyroute.com", "target": "15.165.170.99", "is_shadow": False},
        {"type": "domain", "value": "test.skyroute.com", "target": "15.165.170.100", "is_shadow": True},
        {"type": "domain", "value": "dev.skyroute.com", "target": "15.165.170.101", "is_shadow": True},
        
        # EC2 instances
        {"type": "ec2", "value": "i-0123456789abcdef0", "target": "15.165.170.102", "is_shadow": True},
        {"type": "ec2", "value": "i-0123456789abcdef1", "target": "15.165.170.103", "is_shadow": False},
        
        # RDS instances
        {"type": "rds", "value": "prod-db-1", "target": "rds.amazonaws.com", "is_shadow": False},
        {"type": "rds", "value": "test-db-2", "target": "rds.amazonaws.com", "is_shadow": True},
        
        # Lambda functions
        {"type": "lambda", "value": "process-data-fn", "target": "lambda.amazonaws.com", "is_shadow": False},
        {"type": "lambda", "value": "backup-fn", "target": "lambda.amazonaws.com", "is_shadow": True}
    ]
    
    # Filter for shadow resources if requested
    if shadow_only:
        dummy_data = [item for item in dummy_data if item['is_shadow']]
        
    return jsonify(dummy_data)


