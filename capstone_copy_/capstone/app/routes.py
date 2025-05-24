import os
import subprocess
from flask import Blueprint, jsonify, render_template, send_from_directory, jsonify

main = Blueprint('main', __name__)

CLOUDMAPPER_PATH = "/cloud-1/cloudmapper"
ACCOUNT_NAME = "my-account"

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/run-cloudmapper')
def run_cloudmapper():
    try:
        # CloudMapper 실행
        subprocess.run(
            f"cd {CLOUDMAPPER_PATH} && python3 collect.py --account {ACCOUNT_NAME} && python3 prepare.py --account {ACCOUNT_NAME}",
            shell=True, check=True
        )
        return jsonify({"status": "success"})
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@main.route('/view-cloudmapper')
def view_cloudmapper():
    result_dir = os.path.join(CLOUDMAPPER_PATH, "web")
    return send_from_directory(result_dir, "index.html")

@main.route('/api/test')
def test_api():
    return jsonify({"message": "Flask 백엔드 연결 성공!"})
