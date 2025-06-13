import redis
from celery import Celery, chord
from task_defs import schedule_scan, analyze_shadow_components
from DB.scan_setting import latest_scan_setting_id
from DB.cloud_info import get_or_create_cloud_info
from DB.save_scan_result import save_scan_result_start
from dns_utils import convert_domain_to_ip, convert_ip_to_domain
from shadow_it_analysis.extract_keyword import extract_keyword
from datetime import datetime

r = redis.Redis(host='localhost', port=6379, db=0)

celery = Celery('capstone_tasks',
                broker='redis://localhost:6379/0',
                backend='redis://localhost:6379/0')
celery.conf.timezone = 'Asia/Seoul'

def run_onetime_scan(ip_address=None, domain=None, keyword=None):

    now_ts = datetime.now().timestamp()
    print(f"\n [ONETIME SCAN] 시작: {now_ts}")

    if not ip_address and r.get("scheduled_ip"):
        ip_address = r.get("scheduled_ip").decode()
    if not domain and r.get("scheduled_domain"):
        domain = r.get("scheduled_domain").decode()
    if not keyword and r.get("scheduled_keyword"):
        keyword = r.get("scheduled_keyword").decode()

    if ip_address and not domain:
        domain = convert_ip_to_domain(ip_address)
    elif domain and not ip_address:
        ip_address = convert_domain_to_ip(domain)

    if not keyword:
        try:
            keyword = extract_keyword('csv_files/domain.csv')
            if keyword:
                r.set('scheduled_keyword', keyword)
        except Exception as e:
            print(f"[ERROR] extract_keyword 실패: {e}")

    cloud_info_id = get_or_create_cloud_info(ip_address, domain)
    scan_setting_id = latest_scan_setting_id()
    scan_result_id = save_scan_result_start(cloud_info_id, scan_setting_id)

    pipe = r.pipeline()
    pipe.set('has_user_input', 'false')   
    pipe.set('scan_status', 'running')    
    pipe.set('last_scan_time', str(now_ts))  
    pipe.set('latest_scan_result_id', str(scan_result_id))
    pipe.execute()

    scan_tasks = []
    if ip_address:
        scan_tasks.append(
            schedule_scan.s('ip',      ip_address, scan_setting_id, 1, scan_result_id)
        )
    if domain:
        scan_tasks.append(
            schedule_scan.s('domain',  domain,     scan_setting_id, 1, scan_result_id)
        )
    if keyword:
        scan_tasks.append(
            schedule_scan.s('keyword', keyword,    scan_setting_id, 1, scan_result_id)
        )

    if scan_tasks:
        chord(scan_tasks)( analyze_shadow_components.s(scan_result_id) )
        print(f"[OK] One-time scan tasks scheduled (ScanResult ID={scan_result_id})")
    else:
        print("[WARN] 실행할 스캔 태스크 없음 — IP/도메인/키워드 확인 필요")

    return scan_result_id

