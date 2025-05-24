import json
import time
import redis
from celery.beat import Scheduler
from task_defs import schedule_scan

class DynamicScheduler(Scheduler):
    def __init__(self, *args, **kwargs):
        self._last_loaded_interval = None
        self._interval = 300
        self.r = redis.Redis(host='localhost', port=6379, db=0)

        # 서버 시작 시 초기화
        self.r.set('has_user_input', 'false')
        self.r.set('scan_status', 'idle')
        self.r.delete('last_scan_time')

        super().__init__(*args, **kwargs)

    def load_interval(self):
        try:
            with open("schedule_config.json", "r") as f:
                config = json.load(f)
                interval = float(config.get("interval_seconds", 300))
                print(f"[DEBUG] 불러온 interval: {interval}")
                return interval
        except Exception as e:
            print(f"[ERROR] load_interval 실패: {e}")
            return 300

    def tick(self):
        print("[DEBUG] tick 호출됨")
        now = time.time()

        has_input = self.r.get('has_user_input')
        if not has_input:
            print("[DEBUG] has_user_input 키가 없음 → 사용자 입력 없음으로 간주")
            self.r.delete('last_scan_time')
            return 10.0

        try:
            has_input_value = has_input.decode('utf-8').strip().lower()
        except Exception as e:
            print(f"[DEBUG] decode 실패: {e} → 사용자 입력 없음으로 간주")
            self.r.delete('last_scan_time')
            return 10.0

        if has_input_value != 'true':
            print(f"[DEBUG] has_user_input 값이 '{has_input_value}' → 입력 아직 안 됨")
            # elf.r.delete('last_scan_time')
            return 10.0

        new_interval = self.load_interval()

        # interval이 변경된 경우 → last_scan_time을 보정
        if self._interval != new_interval:
            self._interval = new_interval
            last_scan_raw = self.r.get('last_scan_time')
            if last_scan_raw:
                try:
                    last_scan = float(last_scan_raw.decode())
                    elapsed = now - last_scan
                    adjusted_last_scan = now - min(elapsed, new_interval)
                    self.r.set('last_scan_time', adjusted_last_scan)
                    print(f"[DEBUG] interval 변경 감지 → last_scan_time 보정됨: {adjusted_last_scan}")
                except Exception as e:
                    print(f"[ERROR] last_scan_time 보정 실패: {e}")
            # self._interval = new_interval

        last_scan_raw = self.r.get('last_scan_time')
        print("[DEBUG] last_scan_time =", last_scan_raw)

        if not last_scan_raw:
            self.r.set('last_scan_time', now)
            print("[DEBUG] last_scan_time이 없어 현재 시간으로 설정만 함 (실행하지 않음)")
            return self._interval  # 첫 주기 이후 실행되도록 설정

        last_scan = float(last_scan_raw.decode())
        elapsed = now - last_scan

        print(f"[DEBUG] now: {now}, last_scan: {last_scan}, elapsed: {elapsed:.2f}, interval: {self._interval}")

        if elapsed >= self._interval:
            print("[DEBUG] 주기 경과됨 → schedule_scan 실행")
            self.r.set('last_scan_time', now)

            ip_address = self.r.get("scheduled_ip")
            domain = self.r.get("scheduled_domain")
            keyword = self.r.get("scheduled_keyword")

            if ip_address:
                schedule_scan.delay('ip', ip_address.decode(), 'beat_job_ip')
            
            # if domain:
            #    schedule_scan.delay('domain', domain.decode(), 'beat_job_domain')
            if keyword:
                schedule_scan.delay('keyword', keyword.decode(), 'beat_job_keyword')

            # self.r.set('has_user_input', 'false')

            return self._interval  # 즉시 다음 tick 체크

        else:
            remaining = self._interval - elapsed
            print(f"[DEBUG] 아직 {remaining:.2f}초 남음")
            return min(remaining, 15.0)

