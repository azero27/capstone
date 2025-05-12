from flask import Flask, request, jsonify, render_template, redirect, url_for
from tools.nmap import run_nmap  # nmap.py에서 만든 모듈을 임포트
from tools.s3scanner import run_s3scanner  # s3scanner 실행
import socket
import re


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    # 사용자가 제출한 IP 주소를 가져오기
    ip_address = request.form['ip_address']
    
    # 여기서 IP 주소를 처리하는 로직을 추가할 수 있습니다
    # 예를 들어, nmap 스캔을 실행하거나 다른 작업을 수행할 수 있습니다.
    
    # 임시 응답으로 입력된 IP 주소를 보여줍니다.
    return redirect(url_for('scan', ip=ip_address))


@app.route('/scan', methods=['GET'])
def scan():
    """
    클라이언트로부터 IP 주소를 받아 Nmap을 실행하고 결과를 반환하는 엔드포인트.
    """
    ip = request.args.get('ip')

    if not ip:
        return jsonify({"status": "error", "message": "IP address is required"}), 400
    
    # Nmap 실행
    nmap_result = run_nmap(ip)

    open_ports = nmap_result.get("open_ports", [])
    service_info = nmap_result.get("service_info", [])

    # 후속 도구 실행: 예를 들어 S3Scanner는 HTTP, HTTPS 포트가 열려 있으면 실행
    s3scanner_result = None
    if "80/tcp" in open_ports or "443/tcp" in open_ports:
        s3scanner_result = run_s3scanner(ip)  # HTTP 또는 HTTPS 포트가 열려 있으면 S3Scanner 실행

    return jsonify({
        "nmap_result": nmap_result,
        "s3scanner_result": s3scanner_result
        
    })
if __name__ == '__main__':
    app.run(debug=True)
