from flask import Flask, request, jsonify, render_template, redirect, url_for
from task_defs import celery, make_celery, schedule_scan  # ❗ make_celery 추가
from dns_utils import convert_domain_to_ip, convert_ip_to_domain


def create_app():
    app = Flask(__name__)
    app.config.update(
        CELERY_BROKER_URL='redis://localhost:6379/0',
        CELERY_RESULT_BACKEND='redis://localhost:6379/0'
    )
    make_celery(app)  # 필수

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
                

        schedule_scan.delay('ip', ip_address, 0)
        schedule_scan.delay('domain', domain, 0)
        schedule_scan.delay('keyword', keyword, 0)

        return jsonify({
            'status': 'scheduled',
            'ip': ip_address,
            'domain': domain,
            'keyword': keyword
        }), 202

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
