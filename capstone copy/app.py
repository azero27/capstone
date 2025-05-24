from flask import Flask, request, jsonify, render_template, redirect, url_for
from task_defs import celery, make_celery, schedule_scan  # ❗ make_celery 추가
from dns_utils import convert_domain_to_ip, convert_ip_to_domain
import json
import redis
from datetime import datetime
import time 

r = redis.Redis(host='localhost', port=6379, db=0)

def create_app():
    app = Flask(__name__)
    app.config.update(
        broker_url='redis://localhost:6379/0',
        result_backend='redis://localhost:6379/0'
    )
    make_celery(app)  # 필수

    r.set('has_user_input', 'false')  # 사용자 입력 없음으로 초기화
    r.set('scan_status', 'idle')      # 스캔 상태도 초기화

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/submit', methods=['POST'])
    def submit():
        ip_address = request.form.get('ip_address', '').strip()
        domain     = request.form.get('domain', '').strip()
        keyword    = request.form.get('keyword', '').strip()

        if not keyword:
            return "❌ keyword는 필수입니다.", 400
        if not ip_address and not domain:
            return "❌ IP 또는 도메인 중 하나는 반드시 입력해야 합니다.", 400

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

        r.set("scheduled_ip", ip_address)
        r.set("scheduled_domain", domain)
        r.set("scheduled_keyword", keyword)
        # 사용자 입력에 따라 스케줄 타이머 시작
        r.set('scan_status', 'running')
        # r.set('last_scan_time', time.time())       # datetime.now().timestamp()도 가능
        r.set('has_user_input', 'true')

        # 세 개의 스캔 태스크 병렬 실행
        task_ids = []
        task_ids.append(schedule_scan.delay('ip', ip_address, 'scan_job_ip'))
        # task_ids.append(schedule_scan.delay('domain', domain, 'scan_job_domain'))
        task_ids.append(schedule_scan.delay('keyword', keyword, 'scan_job_keyword'))

        # 상태 관리는 Celery 완료 콜백에서 직접 처리 x → 대신 추후 백엔드에서 모니터링 가능
        # 콜백 내부에서 상태를 무조건 idle로 바꾸면 race condition 발생 가능

        return jsonify({
            'status': 'scheduled',
            'ip': ip_address,
            'domain': domain,
            'keyword': keyword
        }), 202


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

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
