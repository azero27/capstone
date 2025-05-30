import sys
import os
import csv
print("sys.path =", sys.path)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template, redirect, url_for
from task_defs import celery, make_celery, schedule_scan, analyze_shadow_components_mock, run_oneoff_full_scan  # ❗ make_celery 추가
from dns_utils import convert_domain_to_ip, convert_ip_to_domain
import json
import redis
from datetime import datetime
import time 
from DB.cloud_info import get_or_create_cloud_info
from DB.save_scan_result import save_scan_result_start, update_scan_result_end
from DB.scan_setting import save_scan_setting, latest_scan_setting_id, latest_scan_setting
from celery import chord
from api.snapshotList import archiving_bp
from api.infoView import info_bp
from parses.parse_file import parse_domain_file, parse_port_file, parse_s3_file
from flask_cors import CORS
from waitress import serve
import hashlib

r = redis.Redis(host='localhost', port=6379, db=0)
upload_dir = 'csv_files'
os.makedirs(upload_dir, exist_ok=True)

def get_file_hash(file_path):
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def create_app():
    app = Flask(__name__)
    app.config.update(
        broker_url='redis://localhost:6379/0',
        result_backend='redis://localhost:6379/0'
    )
    make_celery(app)  # 필수

    # Blueprint 등록
    app.register_blueprint(archiving_bp)
    app.register_blueprint(info_bp)

    try:
        if latest_scan_setting_id() is None:
            save_scan_setting(60)  # 기본 주기 60분
    except Exception as e:
        print(f"[ERROR] 초기 ScanSetting 저장 실패: {e}")

    r.set('has_user_input', 'false')  # 사용자 입력 없음으로 초기화
    r.set('scan_status', 'idle')      # 스캔 상태도 초기화

    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/submit', methods=['POST'])
    def submit():
        ip_address = request.form.get('ip_address', '').strip()
        domain     = request.form.get('domain', '').strip()
        #keyword    = request.form.get('keyword', '').strip()

        #if not keyword:
        #    return "❌ keyword는 필수입니다.", 400
        if not ip_address and not domain:
            return "❌ IP 또는 도메인 중 하나는 반드시 입력해야 합니다.", 400
        
        from shadow_it_analysis.extract_keyword import extract_keyword
        keyword = extract_keyword('csv_files/domain.csv')

        print("[DOMAIN KEYWORD ANALYSIS]", keyword)


        # IP → 도메인 변환
        if ip_address and not domain:
            domain = convert_ip_to_domain(ip_address)
            if not domain:
                return "❌ IP로부터 도메인을 찾을 수 없습니다.", 400

        # 도메인 → IP 변환
        if domain and not ip_address:
            ip_address = convert_domain_to_ip(domain)
            if not ip_address:
                return "❌ 도메인으로부터 IP를 찾을 수 없습니다.", 400

        # cloud_info 및 scan_result_id 미리 생성
        cloud_info_id = get_or_create_cloud_info(ip_address, domain)
        scan_setting_id = latest_scan_setting_id()
        scan_result_id = save_scan_result_start(cloud_info_id, scan_setting_id)

        r.set("scheduled_ip", ip_address)
        r.set("scheduled_domain", domain)
        r.set("scheduled_keyword", keyword)
        # 사용자 입력에 따라 스케줄 타이머 시작
        r.set('scan_status', 'running')
        r.set('last_scan_time', time.time())       # datetime.now().timestamp()도 가능
        r.set('has_user_input', 'true')

        # 병렬 스캔 태스크 (Signature 형태로)
        scan_tasks = [
            schedule_scan.s('ip', ip_address, scan_setting_id, 1, scan_result_id),
            schedule_scan.s('keyword', keyword, scan_setting_id, 1, scan_result_id)
        ]

        # 병렬 태스크 모두 끝나면 shadow 분석(mock) 실행
        chord(scan_tasks)(analyze_shadow_components_mock.s())

        # 상태 관리는 Celery 완료 콜백에서 직접 처리 x → 대신 추후 백엔드에서 모니터링 가능
        # 콜백 내부에서 상태를 무조건 idle로 바꾸면 race condition 발생 가능

        return jsonify({
            'status': 'scheduled',
            'ip': ip_address,
            'domain': domain,
            'keyword': keyword
        }), 202

    @app.route('/upload-data', methods=['POST'])
    def upload_data():
        def process_file(name, path, redis_key, parser_func):
            uploaded_file = request.files.get(name)
            if uploaded_file:
                uploaded_file.save(path)
                new_hash = get_file_hash(path)
                old_hash = r.get(redis_key)

                if not old_hash or old_hash.decode() != new_hash:
                    # 데이터 재삽입을 위해 기존 데이터 삭제는 parser 내부에서 처리
                    parser_func(path)
                    r.set(redis_key, new_hash)

        process_file('domain_file', os.path.join(upload_dir, 'domain.csv'), 'domain_file_hash', parse_domain_file)
        process_file('port_file', os.path.join(upload_dir, 'port.csv'), 'port_file_hash', parse_port_file)
        process_file('s3_file', os.path.join(upload_dir, 's3_bucket.csv'), 's3_file_hash', parse_s3_file)

        return "✅ 파일 파싱 완료 및 DB 반영됨", 200

    @app.route('/set-schedule', methods=['POST'])
    def set_schedule():
        try:
            interval = float(request.json.get("interval_seconds"))
            if interval < 60:
                return jsonify({"status": "error", "message": "주기는 최소 60초 이상이어야 합니다."}), 400

            # 현재 시간
            now = time.time()

            # 이전 스캔 시간 가져오기
            try:
                last_scan = float(r.get('last_scan_time') or now)
            except:
                last_scan = now

            # 지난 시간 계산
            elapsed = now - last_scan

            # 지난 시간을 고려해서 새로운 주기 기준으로 last_scan_time 조정
            adjusted_last_scan = now - min(elapsed, interval)
            r.set('last_scan_time', adjusted_last_scan)

            # 설정 파일 저장
            with open("schedule_config.json", "w") as f:
                json.dump({"interval_seconds": interval}, f)

            return jsonify({"status": "ok", "interval": interval}), 200

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 400

    @app.route('/status', methods=['GET'])
    def status():
        # 현재 상태 가져오기 
        scan_status = r.get('scan_status')
        scan_status = scan_status.decode('utf-8') if scan_status else 'idle'

        # 사용자 입력이 있었는지 확인
        has_input = r.get('has_user_input')
        if has_input != b'true':
            return jsonify({
                'scan_status': scan_status,
                'message': '아직 스캔이 시작되지 않았습니다.',
                'seconds_remaining': None
            })

        # 스케줄 주기 가져오기
        try:
            with open("schedule_config.json", "r") as f:
                config = json.load(f)
            interval = float(config.get("interval_seconds", 300))
        except:
            interval = 300

        # 마지막 스캔 시각 가져오기 
        try:
            last_scan = float(r.get('last_scan_time').decode())
        except:
            last_scan = 0

        # 현재 시각과 비교 
        now = datetime.now().timestamp()
        seconds_since_last = int(now - last_scan)
        seconds_remaining = max(0, int(interval - seconds_since_last))

        return jsonify({
            'scan_status': scan_status,
            'last_scan_time': last_scan,
            'seconds_remaining': seconds_remaining
        })

    @app.route('/test-scan')
    def test_scan():
        schedule_scan.delay('keyword', 'skyroute', 'manual-test')
        return "✅ 수동 태스크 실행 요청 전송됨", 200

    @app.route('/scan', methods=['POST'], endpoint='scan_request')
    def scan_request():
        data = request.json or request.args
        resource_type = data.get('resource_type')
        value         = data.get('value')
        job_id        = data.get('job_id', 0)

        if not resource_type or not value:
            return jsonify({'status': 'error', 'message': 'resource_type과 value가 필요합니다.'}), 400

        schedule_scan.delay(resource_type, value, job_id)
        return jsonify({'status': 'scheduled'}), 202

    @app.route('/scan-page')
    def scan():
        return render_template('scan.html')

    @app.route('/settings')
    def settings():
        return render_template('settings.html')

    @app.route('/report')
    def report():
        return render_template('report.html')

    @app.route('/archiving/timeline')
    def archiving_tl():
        return render_template('archiving_tl.html')

    @app.route('/archiving/snapshot')
    def archiving_sn():
        return render_template('archiving_sn.html')

    @app.route('/archiving/snapshot/scan/<int:id>')
    def archiving_sn_scan(id):
        return render_template('archiving_sn_scan.html', scan_id=id)

    @app.route('/archiving/snapshot/info/<int:id>')
    def archiving_sn_info(id):
        return render_template('archiving_sn_info.html', scan_id=id)

    @app.route('/api/snapshots', methods=['GET'])
    def api_snapshots():
        # 실제 구현 시 DB에서 전체 스냅샷(스캔) 목록을 조회
        scanResults = [
            {
                "id": 1,
                "cloud_info_id": 101,
                "scan_setting_id": 201,
                "start_time": "2025-05-15T14:30:00",
                "end_time": "2025-05-15T14:40:00"
            },
            {
                "id": 2,
                "cloud_info_id": 102,
                "scan_setting_id": 202,
                "start_time": "2025-05-18T09:00:00",
                "end_time": "2025-05-18T09:15:00"
            }
        ]
        return jsonify(scanResults)

    @app.route('/api/snapshots/<int:id>/resources', methods=['GET'])
    def api_snapshot_resources(id):
        # 실제로는 DB/Redis에서 해당 id에 대한 리소스 리스트 반환
        resources = [
            "EC2", "S3", "Lambda", "IAM", "RDS", "CloudFront", "EBS", "VPC", "Route53", "ECS"
        ]
        return jsonify(resources)

    @app.route('/api/snapshots/<int:id>/scan_result', methods=['GET'])
    def api_snapshot_scan_result(id):
        # 실제로는 id에 따른 DB/Redis 조회
        scan_result = [
            {
                "step": 1,
                "tool": "Nmap",
                "tool_id": 101,
                "status": "success",
                "log": "Open ports: 22, 80, 443",
                "summary": "22, 80, 443 open"
            },
            {
                "step": 1,
                "tool": "Amass",
                "tool_id": 201,
                "status": "fail",
                "log": "Failed to resolve domain",
                "summary": "Domain resolution failed"
            },
            {
                "step": 2,
                "tool": "S3scanner",
                "tool_id": 301,
                "status": "success",
                "log": "Found open bucket: company-public-data",
                "summary": "company-public-data open"
            },
            {
                "step": 2,
                "tool": "Nuclei",
                "tool_id": 401,
                "status": "success",
                "log": "Found: CVE-2021-1234, CVE-2022-5678",
                "summary": "2 vulnerabilities detected"
            }
        ]
        return jsonify(scan_result)

    @app.route('/api/timeline', methods=['GET'])
    def api_timeline():
        timelineData = [
            { "date": "2025-05-01T10:00", "rsc": "server1", "dif": "port 80 opened" },
            { "date": "2025-05-02T12:30", "rsc": "server2", "dif": "new user added" },
            { "date": "2025-05-04T09:15", "rsc": "server1", "dif": "config change" },
            { "date": "2025-05-05T14:00", "rsc": "server3", "dif": "SSH disabled" },
            { "date": "2025-05-05T16:00", "rsc": "server1", "dif": "SSH disabled" }
        ]
        return jsonify(timelineData)

    @app.route('/api/resources', methods=['GET'])
    def api_resources():
        resources = [
            "EC2", "S3", "Lambda", "IAM Role", "RDS", "VPC",
            "CloudFront", "ECS", "EBS", "Route53"
        ]
        return jsonify(resources)

    @app.route('/api/generate_report', methods=['POST'])
    def api_generate_report():
        data = request.json
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        resources = data.get('resources', [])
        if not start_date or not end_date or not resources:
            return jsonify({'status': 'error', 'message': '필터가 부족합니다.'}), 400

        # (실제로는 DB 조회, PDF 생성 태스크 트리거)
        pdf_url = f"/static/reports/report_{start_date}_{end_date}.pdf"
        # 예: celery_report_generate.delay(start_date, end_date, resources)
        return jsonify({'status': 'ok', 'pdf_url': pdf_url})


    return app

    @app.route('/api/oneoff_scan', methods=['POST'])
    def oneoff_scan():
        """
        { "type": "ip"|"domain"|"keyword" } 를 JSON body로 받으면
        run_oneoff_full_scan 태스크를 호출합니다.
        """
        data = request.get_json(silent=True) or {}
        res_type = data.get('type')
        if res_type not in ('ip', 'domain', 'keyword'):
            return jsonify({"error": "invalid type"}), 400

        # Celery 태스크를 단발성 호출
        task = run_oneoff_full_scan.delay(res_type)
        return jsonify({
            "status": "ok",
            "task_id": task.id,
            "type": res_type
        }), 202

if __name__ == '__main__':
    app = create_app()

    serve(app, host='0.0.0.0', port=5000)
    CORS(app)
        
    #파일 파싱 테스트
    domain_path = os.path.join(upload_dir, 'domain.csv')
    if os.path.exists(domain_path):
        domain_file_id = parse_domain_file(domain_path)
        r.set("domain_file_id", domain_file_id)

    port_path = os.path.join(upload_dir, 'port.csv')
    if os.path.exists(port_path):
        port_file_id = parse_port_file(port_path)
        r.set("port_file_id", port_file_id)

    s3_path = os.path.join(upload_dir, 's3_bucket.csv')
    if os.path.exists(s3_path):
        s3_file_id = parse_s3_file(s3_path)
        r.set("s3_file_id", s3_file_id)
    app.run(debug=True)
