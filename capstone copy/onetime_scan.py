# oneoff_full_scan.py
import redis
from celery import Celery
from task_defs import schedule_scan
from DB.scan_setting import latest_scan_setting_id
from DB.save_scan_result import save_scan_result_start

# Redis 연결 (기존에 쓰는 동일한 DB/키를 공유)
r = redis.Redis(host='localhost', port=6379, db=0)

# Celery 인스턴스 (기존 설정과 동일하게 맞춰 주세요)
celery = Celery('capstone_tasks',
                broker='redis://localhost:6379/0',
                backend='redis://localhost:6379/0')
celery.conf.timezone = 'Asia/Seoul'

def run_full_scan_once():
    """
    1) 최신 scan_setting_id 조회
    2) Redis에 저장된 scheduled_ip / scheduled_domain / scheduled_keyword 전부 꺼내서
       하나하나 schedule_scan 태스크로 등록
    3) 실행 후 Redis 의 has_user_input 플래그를 false 로 돌려둠
    """
    # 1) 최신 스캔 설정 ID
    scan_setting_id = latest_scan_setting_id()

    # 2) Redis 에 있는 값들 조회
    ip = r.get('scheduled_ip')
    domain = r.get('scheduled_domain')
    keyword = r.get('scheduled_keyword')

    # 3) 실제로 한번만 호출
    if ip:
        schedule_scan.delay('ip', ip.decode(), scan_setting_id)
        print(f"[ONEOFF] IP 일회성 스캔 예약 → {ip.decode()}")
    if domain:
        schedule_scan.delay('domain', domain.decode(), scan_setting_id)
        print(f"[ONEOFF] Domain 일회성 스캔 예약 → {domain.decode()}")
    if keyword:
        schedule_scan.delay('keyword', keyword.decode(), scan_setting_id)
        print(f"[ONEOFF] Keyword 일회성 스캔 예약 → {keyword.decode()}")

    # 4) 다시 일회성 모드로 재진입 방지
    r.set('has_user_input', 'false')
    print("[ONEOFF] 일회성 전체 스캔 태스크 등록 끝")


if __name__ == '__main__':
    run_full_scan_once()
