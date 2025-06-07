from utils.pdf_generator import generate_pdf_report  
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
from api.shadow_it import shadowit_bp
from parses.parse_file import parse_domain_file, parse_port_file, parse_s3_file
from flask_cors import CORS
from waitress import serve
import hashlib
import random
from dateutil.parser import parse as parse_dt

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
    app.register_blueprint(shadowit_bp)

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

            # save_scan_setting(int(interval))

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
        latest_update_time = 0

        if scan_result_id:
            print(f"✅ [STATUS] scan_result_id: {scan_result_id}")  # 

             # 도구 결과 수집
            for tool_id in range(1, 7):  # 1~6번 도구
                key = f"scan_result:{scan_result_id}:tool:{tool_id}"
                last_update_key = f"{key}:last_update"
                
                # 마지막 업데이트 시간 확인
                last_update = r.get(last_update_key)
                if last_update:
                    last_update = float(last_update.decode())
                    latest_update_time = max(latest_update_time, last_update)
                
                val = r.get(key)
                if val:
                    try:
                        results = json.loads(val)
                        if not isinstance(results, list):
                            results = [results]
                        
                        # 타임스탬프 추가
                        for result in results:
                            if isinstance(result, dict):
                                result['timestamp'] = latest_update_time
                        
                        tool_results[str(tool_id)] = results
                        print(f"✅ [TOOL CACHE] key={key}, last_update={last_update}")
                    except json.JSONDecodeError:
                        print(f"❌ [ERROR] Invalid JSON in Redis for key: {key}")
                        continue

            # Shadow 분석 결과 수집
            for part in ["nmap", "nuclei", "s3"]:
                key = f"shadow_component:{scan_result_id}:{part}"
                val = r.get(key)
                if val:
                    try:
                        shadow_results[part] = json.loads(val)
                        print(f"✅ [SHADOW CACHE] key={key}")
                    except json.JSONDecodeError:
                        print(f"❌ [ERROR] Invalid JSON in Redis for key: {key}")
                        continue

        # 결과 정리 및 반환
        flattened_results = []
        for tool_id in tool_results:
            flattened_results.extend(tool_results[tool_id])

        return jsonify({
            'scan_status': scan_status,
            'scan_result_id': scan_result_id,
            'last_scan_time': last_scan,
            'seconds_remaining': seconds_remaining,
            'tools': tool_results,
            'shadow': shadow_results,
            'results': flattened_results
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
        return jsonify(["port", "s3", "domain"])
    
    # 리소스 타입별 관련 도구 매핑
    RESOURCE_TOOL_MAPPING = {
        "S3": ["S3Scanner", "CloudEnum", "shadow_resource"],
        "Port": ["Nmap", "shadow_network"],
        "Domain": ["Amass", "Nuclei", "shadow_domain"],
        # "IAM": ["EnumerateIAM"]
    }

    """
    def generate_mock_raw_data(start_date, end_date, resources):
        mock_data = {
            "s3": {
                "s3scanner_results": [
                    {
                    "parsed_s3scanner_result": [
                        {
                            "allusers_permission": "[]\"",
                            "authusers_permission": "[READ_ACP]",
                            "bucket_name": "sskyroute-userdata",
                            "bucket_status": "exist",
                            "command": "/home/skyroute/cloud-1/capstone/capstone/tools/S3Scanner/s3scanner -bucket-file /home/skyroute/cloud-1/capstone/capstone/tools/S3Scanner/names.txt -enumerate",
                            "end_time": "Mon, 19 May 2025 23:17:45 GMT",
                            "file_type": "",
                            "logs": "level=info msg=\"exists    | sskyroute-userdata | ap-northeast-2 | AuthUsers: [READ_ACP] | AllUsers: []\"",
                            "sensitive_files": "",
                            "start_time": "Mon, 19 May 2025 23:17:37 GMT",
                            "success_failure": "success",
                            "target": "sskyroute-userdata",
                            "tool_id": 7
                        },
                        {
                            "allusers_permission": "[READ, READ_ACP]",
                            "authusers_permission": "[]",
                            "bucket_name": "sskyroute",
                            "bucket_status": "exist",
                            "command": "/home/skyroute/cloud-1/capstone/capstone/tools/S3Scanner/s3scanner -bucket-file /home/skyroute/cloud-1/capstone/capstone/tools/S3Scanner/names.txt -enumerate",
                            "end_time": "Mon, 19 May 2025 23:17:45 GMT",
                            "file_type": "",
                            "logs": "level=info msg=\"exists    | sskyroute | ap-northeast-2 | AuthUsers: [] | AllUsers: [READ, READ_ACP] | 0 objects (0 B)\"",
                            "sensitive_files": "",
                            "start_time": "Mon, 19 May 2025 23:17:37 GMT",
                            "success_failure": "success",
                            "target": "sskyroute",
                            "tool_id": 7
                        },
                        {
                            "allusers_permission": "[READ, READ_ACP]",
                            "authusers_permission": "[READ, READ_ACP]",
                            "bucket_name": "skyroute7",
                            "bucket_status": "exist",
                            "command": "/home/skyroute/cloud-1/capstone/capstone/tools/S3Scanner/s3scanner -bucket-file /home/skyroute/cloud-1/capstone/capstone/tools/S3Scanner/names.txt -enumerate",
                            "end_time": "Mon, 19 May 2025 23:17:45 GMT",
                            "file_type": "",
                            "logs": "level=info msg=\"exists    | skyroute7 | ap-northeast-2 | AuthUsers: [READ, READ_ACP] | AllUsers: [READ, READ_ACP] | 1 objects (77 B)\"",
                            "sensitive_files": "",
                            "start_time": "Mon, 19 May 2025 23:17:37 GMT",
                            "success_failure": "success",
                            "target": "skyroute7",
                            "tool_id": 7
                        },
                        {
                            "allusers_permission": "[READ, READ_ACP]",
                            "authusers_permission": "[]",
                            "bucket_name": "sskyroute-private",
                            "bucket_status": "exist",
                            "command": "/home/skyroute/cloud-1/capstone/capstone/tools/S3Scanner/s3scanner -bucket-file /home/skyroute/cloud-1/capstone/capstone/tools/S3Scanner/names.txt -enumerate",
                            "end_time": "Mon, 19 May 2025 23:17:45 GMT",
                            "file_type": "",
                            "logs": "level=info msg=\"exists    | sskyroute-private | ap-northeast-2 | AuthUsers: [] | AllUsers: [READ, READ_ACP] | 0 objects (0 B)\"",
                            "sensitive_files": "",
                            "start_time": "Mon, 19 May 2025 23:17:37 GMT",
                            "success_failure": "success",
                            "target": "sskyroute-private",
                            "tool_id": 7
                        },
                        {
                            "allusers_permission": "[READ, READ_ACP]",
                            "authusers_permission": "[]",
                            "bucket_name": "sskyroute-test",
                            "bucket_status": "exist",
                            "command": "/home/skyroute/cloud-1/capstone/capstone/tools/S3Scanner/s3scanner -bucket-file /home/skyroute/cloud-1/capstone/capstone/tools/S3Scanner/names.txt -enumerate",
                            "end_time": "Mon, 19 May 2025 23:17:45 GMT",
                            "file_type": "",
                            "logs": "level=info msg=\"exists    | sskyroute-test | ap-northeast-2 | AuthUsers: [] | AllUsers: [READ, READ_ACP] | 0 objects (0 B)\"",
                            "sensitive_files": "",
                            "start_time": "Mon, 19 May 2025 23:17:37 GMT",
                            "success_failure": "success",
                            "target": "sskyroute-test",
                            "tool_id": 7
                        }
                    ],
                    "parsed_s3scanner_sensitive_files": [
                        {
                            "object": "hello+4.txt",
                            "object_size": "77 B",
                            "object_type": ".txt",
                            "target": "skyroute7"
                        },
                        {
                            "object": "hello2+4.txt",
                            "object_size": "77 B",
                            "object_type": ".txt",
                            "target": "skyroute7"
                        }
                    ]
                    }
                ],
                "cloud_enum_results": {
                    "cloudEnumDiscoveredFile": [
                        {
                            "file_url": "http://sskyroute.s3.ap-northeast-2.amazonaws.com/sskyroute",
                            "scan_result_id": 1
                        },
                        {
                            "file_url": "http://sskyroute-private.s3.ap-northeast-2.amazonaws.com/sskyroute-private",
                            "scan_result_id": 2
                        },
                        {
                            "file_url": "http://sskyroute-test.s3.ap-northeast-2.amazonaws.com/sskyroute-test",
                            "scan_result_id": 3
                        }
                    ],
                    "cloudEnumScanResult": [
                        {
                            "command": "python3 /home/skyroute/cloud-1/capstone/capstone/tools/cloud_enum/cloud_enum.py -k sskyroute",
                            "end_time": "2025-05-19 23:24:30",
                            "id": 1,
                            "logs": "OPEN S3 BUCKET: http://sskyroute.s3.ap-northeast-2.amazonaws.com/\u001b[0m\n    FILES:\n      ->http://sskyroute.s3.ap-northeast-2.amazonaws.com/sskyroute",
                            "start_time": "2025-05-19 23:19:12",
                            "success_failure": "success",
                            "target": "http://sskyroute.s3.ap-northeast-2.amazonaws.com/",
                            "tool_id": 6
                        },
                        {
                            "command": "python3 /home/skyroute/cloud-1/capstone/capstone/tools/cloud_enum/cloud_enum.py -k sskyroute",
                            "end_time": "2025-05-19 23:24:30",
                            "id": 2,
                            "logs": "OPEN S3 BUCKET: http://sskyroute-private.s3.ap-northeast-2.amazonaws.com/\u001b[0m\n    FILES:\n      ->http://sskyroute-private.s3.ap-northeast-2.amazonaws.com/sskyroute-private",
                            "start_time": "2025-05-19 23:19:12",
                            "success_failure": "success",
                            "target": "http://sskyroute-private.s3.ap-northeast-2.amazonaws.com/",
                            "tool_id": 6
                        },
                        {
                            "command": "python3 /home/skyroute/cloud-1/capstone/capstone/tools/cloud_enum/cloud_enum.py -k sskyroute",
                            "end_time": "2025-05-19 23:24:30",
                            "id": 3,
                            "logs": "OPEN S3 BUCKET: http://sskyroute-test.s3.ap-northeast-2.amazonaws.com/\u001b[0m\n    FILES:\n      ->http://sskyroute-test.s3.ap-northeast-2.amazonaws.com/sskyroute-test",
                            "start_time": "2025-05-19 23:19:12",
                            "success_failure": "success",
                            "target": "http://sskyroute-test.s3.ap-northeast-2.amazonaws.com/",
                            "tool_id": 6
                        }
                    ],
                    "raw_cloud_enum_result_file": "/home/skyroute/cloud-1/capstone/capstone/logs/cloud_enum_20250519_231912_671413.log",
                    "status": "success"
                }
            },
            "port": {
                "nmap_results": [
                    {
                        "domain": "ec2-15-165-170-99.ap-northeast-2.compute.amazonaws.com",
                        "ip": "15.165.170.99",
                        "original_ip": "15.165.170.99",
                        "parsed_nmap_result": [
                        {
                            "command": "/usr/bin/nmap -Pn -sV 15.165.170.99",
                            "end_time": "2025-05-22 04:35:06",
                            "logs": "Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-22 04:33 PDT\nNmap scan report for ec2-15-165-170-99.ap-northeast-2.compute.amazonaws.com (15.165.170.99)\nHost is up (0.0075s latency).\nNot shown: 998 filtered ports\nPORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)\n80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))\nService Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n\nService detection performed. Please report any incorrect results at https://nmap.org/submit/ .\nNmap done: 1 IP address (1 host up) scanned in 122.20 seconds\n",
                            "port_number": 22,
                            "port_status": "open",
                            "protocol": "tcp",
                            "service_name": "ssh",
                            "service_version": "OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)",
                            "start_time": "2025-05-22 04:33:03",
                            "success": 1,
                            "target": "ec2-15-165-170-99.ap-northeast-2.compute.amazonaws.com",
                            "tool_id": 1
                        },
                        {
                            "command": "/usr/bin/nmap -Pn -sV 15.165.170.99",
                            "end_time": "2025-05-22 04:35:06",
                            "logs": "Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-22 04:33 PDT\nNmap scan report for ec2-15-165-170-99.ap-northeast-2.compute.amazonaws.com (15.165.170.99)\nHost is up (0.0075s latency).\nNot shown: 998 filtered ports\nPORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)\n80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))\nService Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n\nService detection performed. Please report any incorrect results at https://nmap.org/submit/ .\nNmap done: 1 IP address (1 host up) scanned in 122.20 seconds\n",
                            "port_number": 80,
                            "port_status": "open",
                            "protocol": "tcp",
                            "service_name": "http",
                            "service_version": "Apache httpd 2.4.58 ((Ubuntu))",
                            "start_time": "2025-05-22 04:33:03",
                            "success": 1,
                            "target": "ec2-15-165-170-99.ap-northeast-2.compute.amazonaws.com",
                            "tool_id": 1
                        }
                    ],
                        "raw_nmap_result": "Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-22 04:33 PDT\nNmap scan report for ec2-15-165-170-99.ap-northeast-2.compute.amazonaws.com (15.165.170.99)\nHost is up (0.0075s latency).\nNot shown: 998 filtered ports\nPORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)\n80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))\nService Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n\nService detection performed. Please report any incorrect results at https://nmap.org/submit/ .\nNmap done: 1 IP address (1 host up) scanned in 122.20 seconds\n"
                    }
                                        
                ]
            },
            "domain": {
                "amass_results": [
                    {
                        "parsed_amass_results": {
                            "command": "amass enum -passive -d sskyroute.com",
                            "end_time": "2025-05-19T23:35:23.072609",
                            "logs": "www.sskyroute.com\ndata.sskyroute.com\nsskyroute.com\nwww.data.sskyroute.com",
                            "logs_full": "www.sskyroute.com\ndata.sskyroute.com\nsskyroute.com\nwww.data.sskyroute.com\n\n\nThe enumeration has finished\nDiscoveries are being migrated into the local database\n",
                            "start_time": "2025-05-19T23:34:31.856570",
                            "subdomains": "www.sskyroute.com\ndata.sskyroute.com\nsskyroute.com\nwww.data.sskyroute.com",
                            "success": 1,
                            "target": "sskyroute.com",
                            "tool_id": 2
                        }
                    }
                ],
                "nuclei_results": [
                    {
                    "nulcei_result": {
                        "command": "nuclei -u http://data.sskyroute.com -t /home/skyroute/nuclei-templates/dns/detect-dangling-s3-cname.yaml -stats",
                        "end_time": "2025-05-19T23:30:06.930446",
                        "log": "[detect-dangling-s3-cname] [dns] [info] data.sskyroute.com [\"CNAME\\tdata.sskyroute.com.s3-website.ap-northeast-2.amazonaws.com.\",\"CNAME\\ts3-website.ap-northeast-2.amazonaws.com.\"]\n[detect-dangling-s3-cname] [http] [info] http://data.sskyroute.com",
                        "risk_level": "high",
                        "start_time": "2025-05-19T23:30:02.483893",
                        "success": 1,
                        "target": "http://data.sskyroute.com",
                        "tool_id": 1,
                        "url": "CNAME\tdata.sskyroute.com.s3-website.ap-northeast-2.amazonaws.com.\nCNAME\ts3-website.ap-northeast-2.amazonaws.com.",
                        "url_list": [
                        "CNAME\tdata.sskyroute.com.s3-website.ap-northeast-2.amazonaws.com.",
                        "CNAME\ts3-website.ap-northeast-2.amazonaws.com."
                        ],
                        "vulnerability": "detect-dangling-s3-cname [dns] and [http] matched"
                    }
                    }
                ]
            },
            "mock_shadow_domain_result": {
                "dangling_dns": [
                    {
                        "resource": "d111111abcdef8.cloudfront.net",
                        "resource_type": "AWS CloudFront",
                        "resource_identifier": "d111111abcdef8",
                        "linked_domains": ["media.skyroute.com"],
                        "status": "dangling_dns"
                    }
                ],
                "potential_exposure": [
                    {
                        "resource": "bucket1.s3.amazonaws.com",
                        "resource_type": "AWS S3",
                        "resource_identifier": "bucket1",
                        "linked_domains": ["cdn.skyroute.com"],
                        "is_user_owned": False,
                        "status": "potential_exposure"
                    },
                    {
                        "resource": "static-site.github.io",
                        "resource_type": "GitHub Pages",
                        "resource_identifier": "static-site",
                        "linked_domains": ["static.skyroute.com"],
                        "status": "potential_exposure"
                    }
                ],
                "linked_known_resource": [
                    {
                        "resource": "my-owned-bucket.s3.amazonaws.com",
                        "resource_type": "AWS S3",
                        "resource_identifier": "my-owned-bucket",
                        "linked_domains": ["img.skyroute.com"],
                        "is_user_owned": True,
                        "status": "linked_known_resource"
                    }
                ]
            },
            "mock_shadow_network_result": [
                {
                    "port": 22,
                    "expected_service": "ssh",
                    "actual_service": "closed",
                    "reason": "Expected open port is closed",
                    "type": "closed_expected_port",
                    "scan_result_id": 101
                },
                {
                    "port": 3306,
                    "expected_service": None,
                    "actual_service": "mysql",
                    "reason": "Unexpected open port",
                    "type": "unexpected_open_port",
                    "scan_result_id": 101
                },
                {
                    "port": 443,
                    "expected_service": "https",
                    "actual_service": "http",
                    "reason": "Service mismatch",
                    "type": "mismatched_service",
                    "scan_result_id": 101
                }
            ],
            "mock_shadow_resource_result": [
                {
                    "bucket": "private-logs-bucket",
                    "allusers_permission": "[\"READ\", \"WRITE\"]",
                    "authusers_permission": "[]",
                    "scan_result_id": 101,
                    "reason": "not allowed open buckets"
                },
                {
                    "bucket": "audit-trails-2023",
                    "allusers_permission": "[\"FULL_CONTROL\"]",
                    "authusers_permission": "[\"READ\"]",
                    "scan_result_id": 101,
                    "reason": "not allowed open buckets"
                }
            ]

        }
        
        
        # 선택된 리소스에 대한 데이터만 반환
        result =  {k: v for k, v in mock_data.items() if k in resources}
        
        # shadow 분석 결과 조건부 포함
        if "s3" in resources:
            result["mock_shadow_resource_result"] = mock_data.get("mock_shadow_resource_result")

        if "port" in resources:
            result["mock_shadow_network_result"] = mock_data.get("mock_shadow_network_result")

        if "domain" in resources:
            result["mock_shadow_domain_result"] = mock_data.get("mock_shadow_domain_result")

        return result
    """


    def get_tools_for_resources(selected_resources):
        tools = set()
        for resource in selected_resources:
            tools.update(RESOURCE_TOOL_MAPPING.get(resource, []))
        return list(tools)

    def normalize_list_field(field):
        if isinstance(field, list):
            return field
        elif isinstance(field, str) and field.strip() == "":
            return []
        elif isinstance(field, str):
            return [field]
        elif isinstance(field, (int, float)):
            return [str(field)]
        else:
            return []

    def normalize_report_data(report_data):
        for rtype, rdata in report_data.get("resources", {}).items():
            for finding in rdata.get("findings", []):
                if "sensitive_files" in finding:
                    finding["sensitive_files"] = normalize_list_field(finding["sensitive_files"])
                if "file_type" in finding and isinstance(finding["file_type"], str) and finding["file_type"].strip() == "":
                    finding["file_type"] = "Unknown"
                if "url_list" in finding:
                    finding["url_list"] = normalize_list_field(finding["url_list"])
                if "url" in finding and isinstance(finding["url"], str) and finding["url"].strip() == "":
                    finding["url"] = "N/A"

            if rtype == "s3":
                files = rdata.get("cloud_enum_results", {}).get("files", [])
                for f in files:
                    if "file_url" in f and isinstance(f["file_url"], str) and f["file_url"].strip() == "":
                        f["file_url"] = "N/A"
                    if "bucket_index" in f and (str(f["bucket_index"]).strip() == "" or f["bucket_index"] is None):
                        f["bucket_index"] = -1

    def safe_first_date(data_list, key="start_time"):
        if isinstance(data_list, list) and len(data_list) > 0:
            first = data_list[0]
            if isinstance(first, dict):
                val = first.get(key, "")
                if isinstance(val, str):
                    parts = val.strip().split()
                    if len(parts) > 0:
                        return parts[0]
        return "N/A"

    def sanitize_filename(name: str):
        return name.replace(":", "-").replace(" ", "_")

    def in_date_range(iso_str, start_date, end_date):
        try:
            dt = datetime.fromisoformat(iso_str)
            return start_date <= dt <= end_date
        except:
            return False

    def process_raw_data(raw_data, start_date, end_date):
        # 동적으로 discovered_resources 구성
        discovered = {}

        if "s3" in raw_data:
            discovered["s3_buckets"] = 0  # 나중에 overwrite됨

        if "port" in raw_data:
            discovered["open_ports"] = 0

        if "domain" in raw_data:
            discovered["subdomains"] = 0

        report = {
            "generated_at": datetime.now().isoformat(),
            "period": {"start": start_date, "end": end_date},
            "resources": {},
            "overall_summary": {
                "discovered_resources": discovered
            }
        }

        if "s3" in raw_data:
            s3_raw = raw_data["s3"]
            scanner_wrappers = s3_raw.get("s3scanner_results", [])
            s3scanner_results = []

            for wrapper in scanner_wrappers:
                s3scanner_results.extend(wrapper.get("parsed_s3scanner_result", []))

            cloud_enum_raw = s3_raw.get("cloud_enum_results", {})
            cloud_enum_main = cloud_enum_raw.get("cloudEnumScanResult", [])
            cloud_enum_files = cloud_enum_raw.get("cloudEnumDiscoveredFile", [])

            # 버킷명 기반 민감 파일 맵 생성
            sensitive_file_map = {}
            for wrapper in scanner_wrappers:
                for sf in wrapper.get("parsed_s3scanner_sensitive_files", []):
                    bucket = sf.get("target")
                    if bucket:
                        sensitive_file_map.setdefault(bucket, []).append(sf.get("object", "Unknown"))

            # findings 재구성
            s3_findings = []
            for entry in s3scanner_results:
                bucket = entry.get("bucket_name", "Unknown")
                allusers = entry.get("allusers_permission", "[]")
                authusers = entry.get("authusers_permission", "[]")
                
                # bucket 별 민감 파일 가져오기
                sensitive_files = sensitive_file_map.get(bucket, [])
                files_str = ", ".join(sensitive_files) 
                files = sensitive_files if sensitive_files else []

                s3_findings.append({
                    "bucket": bucket,
                    "details": f"AuthUsers: {authusers}, AllUsers: {allusers}",
                    "files": files_str  # 🔁 recommendation → files 로 변경
                })

            s3_timeline = []
            first = safe_first_date(s3scanner_results)
            if first != "N/A":
                s3_timeline.append({
                    "date": first,
                    "event": f"{len(s3scanner_results)} buckets scanned"
                })

            first = safe_first_date(cloud_enum_main)
            if first != "N/A":
                s3_timeline.append({
                    "date": first,
                    "event": f"{len(cloud_enum_files)} sensitive files discovered"
                })


            report["overall_summary"]["discovered_resources"]["s3_buckets"] = len(s3scanner_results)
            report["resources"]["s3"] = {
                "summary": {
                    "total_buckets": len(s3scanner_results),
                    "public_buckets": sum(1 for x in s3scanner_results if x.get("allusers_permission")),
                    "auth_access_buckets": sum(1 for x in s3scanner_results if x.get("authusers_permission")),
                    "sensitive_files": len(cloud_enum_files)
                },
                "findings": s3_findings,
                "timeline": s3_timeline,
                "cloud_enum_results": {
                    "files": cloud_enum_files
                }
            }

            all_times = [r.get("start_time") for r in s3scanner_results if r.get("start_time")] + \
                [r.get("start_time") for r in cloud_enum_main if r.get("start_time")]
            report["resources"]["s3"]["start_time"] = get_earliest_time(all_times)

        if "port" in raw_data:
            port_raw = raw_data["port"]
            nmap_wrappers = port_raw.get("nmap_results", [])
            nmap_results = []

            for wrapper in nmap_wrappers:
                nmap_results.extend(wrapper.get("parsed_nmap_result", []))

            port_findings = []

            for result in nmap_results:
                port_number = normalize_list_field(result.get("port_number"))
                target = result.get("target", "Unknown")
                finding = {
                    "port": port_number,
                    "service_info": {
                        "protocol": normalize_list_field(result.get("protocol")),
                        "status": normalize_list_field(result.get("port_status")),
                        "service": normalize_list_field(result.get("service_name")),
                        "version": normalize_list_field(result.get("service_version"))
                    },
                    "details": f"{normalize_list_field(result.get('service_name'))}({port_number}/{normalize_list_field(result.get('protocol'))}) \uc11c\ube44\uc2a4 \ubc1c\uacac, \ubc84\uc804: {normalize_list_field(result.get('service_version'))}"
                }
                port_findings.append(finding)

            open_ports = sum(1 for x in nmap_results if x.get("port_status") == "open")
            report["overall_summary"]["discovered_resources"]["open_ports"] = open_ports

            port_timeline = []
            first = safe_first_date(nmap_results)
            if first != "N/A":
                port_timeline.append({
                    "date": first,
                    "event": f"{open_ports} open ports detected"
                })

            report["resources"]["port"] = {
                "summary": {
                    "open_ports": open_ports,
                    "services_found": len(port_findings)
                },
                "findings": port_findings,
                "timeline": port_timeline
            }

            all_times = [r.get("start_time") for r in nmap_results if r.get("start_time")]
            report["resources"]["port"]["start_time"] = get_earliest_time(all_times)


        if "domain" in raw_data:
            domain_raw = raw_data["domain"]

            # Amass
            amass_wrappers = domain_raw.get("amass_results", [])
            amass_results = []
            for wrapper in amass_wrappers:
                parsed = wrapper.get("parsed_amass_results")
                if parsed:
                    amass_results.append(parsed)

            # Nuclei
            nuclei_wrappers = domain_raw.get("nuclei_results", [])
            nuclei_results = []
            for wrapper in nuclei_wrappers:
                parsed = wrapper.get("nulcei_result")
                if parsed:
                    nuclei_results.append(parsed)

            # target = result.get("target", "Unknown")

            domain_findings = []

            for result in nuclei_results:
                vuln_msg = result.get("vulnerability", "").lower()
                risk_level = result.get("risk_level", "unknown").lower()
                target = result.get("target", "Unknown")

                if "dns" in vuln_msg and "http" in vuln_msg:
                    issue = "Dangling DNS (CNAME: DNS+HTTP matched)"
                elif "dns" in vuln_msg:
                    issue = "Potential CNAME Misconfiguration (DNS only)"
                elif "http" in vuln_msg:
                    issue = "Potential CNAME Misconfiguration (HTTP only)"
                else:
                    issue = "Unclassified CNAME Behavior"

                domain_findings.append({
                    "target": target,
                    "domain": normalize_list_field(target),
                    "issue": issue,
                    "risk_level": risk_level,
                    "details": normalize_list_field(result.get("vulnerability")),
                    "cname": result.get("url", "N/A"),
                    # "recommendation": "Remove the unused CNAME record or point it to a valid resource"
                })


            domain_timeline = []
            first = safe_first_date(amass_results)
            if first != "N/A":
                domain_timeline.append({
                    "date": first,
                    "event": f"{len(amass_results)} subdomains discovered"
                })

            first = safe_first_date(nuclei_results)
            if first != "N/A":
                domain_timeline.append({
                    "date": first,
                    "event": f"{len(domain_findings)} dangling DNS entries detected"
                })

            report["overall_summary"]["discovered_resources"]["subdomains"] = len(amass_results)
            report["resources"]["domain"] = {
                "summary": {
                    "total_subdomains": len(amass_results),
                    "active_subdomains": len(amass_results),
                    "dangling_dns": len(domain_findings)
                },
                "findings": domain_findings,
                "timeline": domain_timeline
            }
            
            all_times = [r.get("start_time") for r in nuclei_results if r.get("start_time")]
            report["resources"]["domain"]["start_time"] = get_earliest_time(all_times)


        shadow = {}

        domain_result = raw_data.get("mock_shadow_domain_result")
        if domain_result:
            summary = {
                "dangling_dns": len(domain_result.get("dangling_dns", [])),
                "potential_exposure": len(domain_result.get("potential_exposure", [])),
                "linked_known_resource": len(domain_result.get("linked_known_resource", []))
            }
            findings = domain_result.get("dangling_dns", []) + \
                    domain_result.get("potential_exposure", []) + \
                    domain_result.get("linked_known_resource", [])
            shadow["shadow_domain"] = {
                "summary": summary,
                "findings": findings
            }

        network_result = raw_data.get("mock_shadow_network_result", [])
        if network_result:
            summary = {
                "closed_expected_port": sum(1 for r in network_result if r["type"] == "closed_expected_port"),
                "unexpected_open_port": sum(1 for r in network_result if r["type"] == "unexpected_open_port"),
                "mismatched_service": sum(1 for r in network_result if r["type"] == "mismatched_service")
            }
            shadow["shadow_network"] = {
                "summary": summary,
                "findings": network_result
            }

        resource_result = raw_data.get("mock_shadow_resource_result", [])
        if resource_result:
            summary = {
                "public_buckets_exposed": len(resource_result)
            }
            shadow["shadow_resource"] = {
                "summary": summary,
                "findings": resource_result
            }

        # report에 반영
        if shadow:
            report["resources"]["shadow"] = shadow

        print("[FINAL DEBUG] resources keys:", report["resources"].keys())
        print("[FINAL DEBUG] shadow keys:", report["resources"].get("shadow", {}).keys())


        # 데이터 포맷 정리 (기존 코드 유지)
        normalize_report_data(report)
        return report

    def get_earliest_time(time_list):
        """문자열 리스트 중 가장 이른 ISO 시간 리턴"""
        dt_list = []
        for t in time_list:
            try:
                dt = parse_dt(t)
                if dt.tzinfo is not None:
                    dt = dt.replace(tzinfo=None)  # timezone 제거 → naive datetime 으로 변환
                dt_list.append(dt)
            except Exception:
                continue
        if dt_list:
            return min(dt_list).isoformat()
        return None


    @app.route('/api/generate_report', methods=['POST'])
    def api_generate_report():
        data = request.json
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        resources = data.get('resources', [])

        if not start_date or not end_date or not resources:
            return jsonify({'status': 'error', 'message': '필터가 부족합니다.'}), 400

        # 소문자 리소스명 통일
        raw_data = generate_mock_raw_data(start_date, end_date, [r.lower() for r in resources])
        report_data = process_raw_data(raw_data, start_date, end_date)

        filename = f"report_{sanitize_filename(start_date)}_{sanitize_filename(end_date)}.pdf"
        save_path = os.path.join("static", "reports", filename)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        try:
            generate_pdf_report(report_data, save_path)
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'PDF 생성 실패: {str(e)}'}), 500

        return jsonify({
            'status': 'ok',
            'pdf_url': f"/static/reports/{filename}"
        })
    
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