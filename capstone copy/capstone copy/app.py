import sys
import os
import csv
import shutil
print("sys.path =", sys.path)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template, redirect, url_for
from task_defs import celery, make_celery, schedule_scan, analyze_shadow_components_mock, run_oneoff_full_scan  # ❗ make_celery 추가
from dns_utils import convert_domain_to_ip, convert_ip_to_domain
import json
import redis
from datetime import datetime, timedelta
import time 
from DB.cloud_info import get_or_create_cloud_info
from DB.save_scan_result import save_scan_result_start, update_scan_result_end
from DB.scan_setting import save_scan_setting, latest_scan_setting_id, latest_scan_setting
from celery import chord
from api.snapshot.snapshotList import archiving_bp
from api.snapshot.infoView import info_bp
from api.snapshot.scan_result_api import scan_result_bp
from api.archive_timeline import timeline_bp
from parses.parse_file import parse_domain_file, parse_port_file, parse_s3_file
from flask_cors import CORS
from waitress import serve
import hashlib

# capstone 디렉토리를 파이썬 경로에 추가
sys.path.append(os.path.join(os.path.dirname(__file__), 'capstone'))
from parses.parse_file import parse_domain_file, parse_port_file, parse_s3_file

r = redis.Redis(host='localhost', port=6379, db=0)

def clear_scan_cache(scan_result_id):
    for tool_id in range(1, 10):  # 필요한 도구 개수만큼 조정
        key = f"scan_result:{scan_result_id}:tool:{tool_id}"
        r.delete(key)
    for part in ["nmap", "nuclei", "s3"]:
        key = f"shadow_component:{scan_result_id}:{part}"
        r.delete(key)

upload_dir = 'csv_files'
backup_dir = 'csv_files_backup'
os.makedirs(upload_dir, exist_ok=True)
os.makedirs(backup_dir, exist_ok=True)  # 백업 디렉토리 생성

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
    app.register_blueprint(scan_result_bp)
    app.register_blueprint(timeline_bp)

    try:
        if latest_scan_setting_id() is None:
            save_scan_setting(15)  # 기본 주기 60분
    except Exception as e:
        print(f"[ERROR] 초기 ScanSetting 저장 실패: {e}")

    r.set('has_user_input', 'false')  # 사용자 입력 없음으로 초기화
    r.set('scan_status', 'idle')      # 스캔 상태도 초기화

    @app.route('/')
    def index():
        return render_template('home.html')
    
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
                
        domain_path = os.path.join(upload_dir, 'domain.csv')
        port_path = os.path.join(upload_dir, 'port.csv')
        s3_path = os.path.join(upload_dir, 's3.csv')

        if os.path.exists(domain_path):
            print("[SUBMIT] domain.csv 파싱 시작")
            domain_file_id = parse_domain_file(domain_path)
            r.set("domain_file_id", domain_file_id)

        if os.path.exists(port_path):
            print("[SUBMIT] port.csv 파싱 시작")
            port_file_id = parse_port_file(port_path)
            r.set("port_file_id", port_file_id)

        if os.path.exists(s3_path):
            print("[SUBMIT] s3.csv 파싱 시작")
            s3_file_id = parse_s3_file(s3_path)
            r.set("s3_file_id", s3_file_id)

        #cloud_info 및 scan_result_id 미리 생성
        cloud_info_id = get_or_create_cloud_info(ip_address, domain)
        scan_setting_id = save_scan_setting(15)
        scan_result_id = save_scan_result_start(cloud_info_id, scan_setting_id)
        r.set("latest_scan_result_id", scan_result_id)
        # scan_result_id = "mock-001"
        # r.set("latest_scan_result_id", scan_result_id)

        clear_scan_cache(scan_result_id)

        r.set("scheduled_ip", ip_address)
        r.set("scheduled_domain", domain)
        r.set("scheduled_keyword", keyword)
        # 사용자 입력에 따라 스케줄 타이머 시작
        r.set('scan_status', 'running')
        r.set('last_scan_time', time.time())       # datetime.now().timestamp()도 가능
        r.set('has_user_input', 'true')

        scan_setting_id = "mock-setting-id"
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
            'keyword': keyword,
            'result_scan_id': scan_result_id
        }), 202

    @app.route('/upload-data', methods=['POST'])
    def upload_data():
        def process_file(name, path, redis_key, parser_func):
            global backup_dir  # 전역 변수 선언 추가
            uploaded_file = request.files.get(name)
            if uploaded_file:

                # 파일 업로드 전에 기존 파일 백업
                if os.path.exists(path):
                    try:
                        timestamp = datetime.now().strftime('%Y-%m-%dT%H-%M-%S')
                        backup_filename = f"{os.path.splitext(os.path.basename(path))[0]}.{timestamp}.csv"
                        backup_path = os.path.join(backup_dir, backup_filename)
                        shutil.copy2(path, backup_path)
                        print(f"[BACKUP] {path} -> {backup_path}")
                    except Exception as e:
                        print(f"[ERROR] 파일 백업 실패: {str(e)}")

                try:
                    # 새 파일 저장
                    uploaded_file.save(path)
                    print(f"[SAVE] 새 파일 저장됨: {path}")
                    
                    # 항상 파싱 수행
                    print(f"[PARSE] {name} 파싱 시작")
                    result = parser_func(path)
                    print(f"[PARSE] {name} 파싱 완료, 결과: {result}")
                    
                except Exception as e:
                    print(f"[ERROR] 파일 처리 실패: {str(e)}")
                    raise

        try:
            process_file('domain_file', os.path.join(upload_dir, 'domain.csv'), 'domain_file_hash', parse_domain_file)
            process_file('port_file', os.path.join(upload_dir, 'port.csv'), 'port_file_hash', parse_port_file)
            process_file('s3_file', os.path.join(upload_dir, 's3.csv'), 's3_file_hash', parse_s3_file)
            
            return jsonify({
                "status": "ok", 
                "message": "파일 처리가 완료되었습니다."
            }), 200
            
        except Exception as e:
            print(f"[ERROR] 전체 처리 실패: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"처리 중 오류가 발생했습니다: {str(e)}"
            }), 500

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

            save_scan_setting(int(interval))

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

        # 최근 scan_result_id 가져오기
        scan_result_id = r.get("latest_scan_result_id")
        scan_result_id = scan_result_id.decode() if scan_result_id else None

        tool_results = {}
        shadow_results = {}

        if scan_result_id:
            print(f"✅ [STATUS] scan_result_id: {scan_result_id}")  # ✅
            # 도구 결과 수집
            for tool_id in range(1, 7):  # 1~6번 도구
                key = f"scan_result:{scan_result_id}:tool:{tool_id}"
                val = r.get(key)
                if val:
                    print(f"✅ [TOOL CACHE FOUND] key={key}, value={val[:200]}...")
                    tool_results[str(tool_id)] = json.loads(val)

            # Shadow 분석 결과 수집
            for part in ["nmap", "nuclei", "s3"]:
                key = f"shadow_component:{scan_result_id}:{part}"
                val = r.get(key)
                if val:
                    print(f"✅ [TOOL CACHE FOUND] key={key}, value={val[:200]}...")  # ✅ value 일부만 출력
                    shadow_results[part] = json.loads(val)

        return jsonify({
            'scan_status': scan_status,
            'last_scan_time': last_scan,
            'seconds_remaining': seconds_remaining,
            'tools': tool_results,
            'shadow': shadow_results,
            'results': [item for tool_id in tool_results for item in tool_results[tool_id]]
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

    """
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
    """

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

    @app.route('/api/timeline_nodes', methods=['POST'])
    def api_timeline_nodes():
        data = request.json
        start_date = data.get('start')
        end_date = data.get('end')
        
        # Current time reference for recent data
        current_time = datetime.now()
        
        # Generate timestamps for the last 24 hours with 1.5-hour intervals
        timestamps = []
        for i in range(15):
            dt = current_time - timedelta(hours=i*1.5)
            timestamps.append(dt.strftime("%Y-%m-%dT%H:%M:%S"))
        
        # Comprehensive recent sample data
        nodes = [
            # Most recent scans first
            {
                "date": timestamps[0],
                "rsc": "EC2",
                "dif": "i-0123456789abcdef0, unauthorized port 22 opened",
                "type": "shadow"
            },
            {
                "date": timestamps[1],
                "rsc": "S3",
                "dif": "data-backup-bucket, public access enabled",
                "type": "shadow"
            },
            {
                "date": timestamps[2],
                "rsc": "IAM",
                "dif": "admin-role, suspicious policy attached",
                "type": "shadow"
            },
            {
                "date": timestamps[3],
                "rsc": "Lambda",
                "dif": "data-processor-func, new function created",
                "type": "added"
            },
            {
                "date": timestamps[4],
                "rsc": "RDS",
                "dif": "prod-db-instance, public access detected",
                "type": "shadow"
            },
            {
                "date": timestamps[5],
                "rsc": "SecurityGroup",
                "dif": "sg-web-prod, all ports opened",
                "type": "shadow"
            },
            {
                "date": timestamps[6],
                "rsc": "CloudFront",
                "dif": "dist-prod, distribution modified",
                "type": "added"
            },
            {
                "date": timestamps[7],
                "rsc": "EC2",
                "dif": "i-9876543210fedcba, instance terminated",
                "type": "removed"
            },
            {
                "date": timestamps[8],
                "rsc": "VPC",
                "dif": "vpc-prod, new subnet added",
                "type": "added"
            },
            {
                "date": timestamps[9],
                "rsc": "Route53",
                "dif": "company.com, unauthorized DNS change",
                "type": "shadow"
            },
            {
                "date": timestamps[10],
                "rsc": "S3",
                "dif": "customer-data-bucket, versioning disabled",
                "type": "removed"
            },
            {
                "date": timestamps[11],
                "rsc": "EC2",
                "dif": "i-abcdef0123456789, unauthorized AMI",
                "type": "shadow"
            },
            {
                "date": timestamps[12],
                "rsc": "Lambda",
                "dif": "log-processor, function modified",
                "type": "added"
            },
            {
                "date": timestamps[13],
                "rsc": "RDS",
                "dif": "analytics-db, snapshot created",
                "type": "added"
            },
            {
                "date": timestamps[14],
                "rsc": "SecurityGroup",
                "dif": "sg-internal, rules modified",
                "type": "shadow"
            }
        ]
        
        # If no date range is specified, return all 15 most recent scans
        if not start_date and not end_date:
            return jsonify(nodes)  # Already sorted by most recent first
        else:
            # Filter nodes based on date range if specified
            filtered_nodes = [
                node for node in nodes
                if start_date <= node['date'] <= end_date
            ]
            return jsonify(filtered_nodes)

    @app.route('/api/timeline_diff', methods=['POST'])
    def api_timeline_diff():
        data = request.json
        start_date = data.get('start')
        end_date = data.get('end')
        
        # Comprehensive sample diff data with detailed changes
        diffs = [
            {
                "resource": "EC2",
                "description": "Security vulnerabilities detected",
                "detailedInfo": "Multiple unauthorized access points found",
                "details": {
                    "instance_id": "i-0123456789abcdef0",
                    "changes": [
                        {"type": "security_group", "old": "sg-prod-locked", "new": "sg-prod-open"},
                        {"type": "port", "action": "opened", "number": 22, "source": "0.0.0.0/0"},
                        {"type": "port", "action": "opened", "number": 3389, "source": "0.0.0.0/0"},
                        {"type": "tag", "action": "modified", "key": "Environment", "old": "prod", "new": "dev"}
                    ]
                }
            },
            {
                "resource": "S3",
                "description": "Critical security misconfiguration",
                "detailedInfo": "Public access enabled on sensitive data bucket",
                "details": {
                    "bucket_name": "data-backup-bucket",
                    "changes": [
                        {"type": "acl", "action": "modified", "old": "private", "new": "public-read"},
                        {"type": "policy", "action": "added", "effect": "Allow", "principal": "*"},
                        {"type": "versioning", "action": "disabled"},
                        {"type": "encryption", "action": "disabled"}
                    ]
                }
            },
            {
                "resource": "IAM",
                "description": "Suspicious permission changes",
                "detailedInfo": "Admin privileges granted to service role",
                "details": {
                    "role_name": "service-role",
                    "changes": [
                        {"type": "policy", "action": "attached", "name": "AdministratorAccess"},
                        {"type": "trust", "action": "modified", "service": "*"},
                        {"type": "user", "action": "added", "name": "unknown-user"}
                    ]
                }
            },
            {
                "resource": "RDS",
                "description": "Database security exposure",
                "detailedInfo": "Public access enabled on production database",
                "details": {
                    "instance_id": "prod-db-instance",
                    "changes": [
                        {"type": "network", "action": "modified", "parameter": "publicly_accessible", "old": false, "new": true},
                        {"type": "security_group", "action": "added", "group_id": "sg-db-public"},
                        {"type": "parameter_group", "action": "modified", "old": "prod-pg", "new": "default"},
                        {"type": "backup", "action": "disabled"}
                    ]
                }
            }
        ]
        
        return jsonify(diffs)

    return app

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

    s3_path = os.path.join(upload_dir, 's3.csv')
    if os.path.exists(s3_path):
        s3_file_id = parse_s3_file(s3_path)
        r.set("s3_file_id", s3_file_id)

    app.run(debug=True)
