from celery import Celery, Task
from resource_tool_map import RESOURCE_TOOL_MAP, classify_resource, custom_preprocess
from flask import Flask
from datetime import datetime
import requests
import re
import subprocess
from shadow_it_analysis.shadow_domain import build_resource_subdomain_map  
from celery.schedules import crontab
import redis
import json 

r = redis.Redis(host='localhost', port=6379, db=0)

# Celery 인스턴스 정의
celery = Celery('capstone_tasks', broker='redis://localhost:6379/0', backend='redis://localhost:6379/0')
celery.conf.timezone = 'Asia/Seoul'

def make_celery(app: Flask):
    celery.conf.update(app.config)
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    celery.Task = ContextTask
    return celery

class ContextTask(Task):
    def __call__(self, *args, **kwargs):
        from flask import current_app
        with current_app.app_context():
            return self.run(*args, **kwargs)
celery.Task = ContextTask

def build_meta(tool_id, raw):
    if tool_id == 1:  # nmap
        return {
            "tool_id": tool_id,
            "output": raw.get("output"),
            "command": raw.get("command"),
            "status": raw.get("status")
        }
    elif tool_id == 2:  # cloud_enum
        return {
            "tool_id": tool_id,
            "output_file": raw.get("output_file"),
            "command": raw.get("command"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    elif tool_id == 3:  # amass
        return {
            "tool_id": tool_id,
            "output": raw.get("output"),
            "output_log": raw.get("output_log"),
            "command": raw.get("command"),
            "target_url": raw.get("target_url"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    elif tool_id == 4:  # s3scanner
        return {
            "tool_id": tool_id,
            "output": raw.get("output"),
            "command": raw.get("command"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    elif tool_id == 5:  # enumerate-iam
        return {
            "tool_id": tool_id,
            "output_file": raw.get("output_file"),
            "command": raw.get("command"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    elif tool_id == 6:  # nuclei
        return {
            "tool_id": tool_id,
            "output": raw.get("output"),
            "command": raw.get("command"),
            "target_url": raw.get("target_url"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    else:
        return {"tool_id": tool_id, **raw}  # fallback

@celery.task(name='tasks.schedule_scan')
def schedule_scan(resource_type, value, scan_job_id):

    print(f"\n🚀 [SCHEDULE SCAN START] 주기적 스캔 시작됨")
    print(f"[{datetime.now()}] 🚀 [SCHEDULE SCAN START] type={resource_type}, value={value}, job_id={scan_job_id}")
    # r.set('last_scan_time', datetime.now().timestamp())

    visited = set()
    queue = [(resource_type, value)]

    while queue:
        resource_type, value = queue.pop(0)

        if (resource_type, value) in visited:
            continue
        visited.add((resource_type, value))

        mappings = RESOURCE_TOOL_MAP.get(resource_type, [])
        for m in mappings:
            tool_id = m.get("tool_id", -1)

            input_values = []
            for arg in m.get("input_args", []):
                for k, v in arg.items():
                    input_values.append(value if v == "value" else v)

            raw = m["tool"](*input_values)
            meta = build_meta(tool_id, raw)

            parser_args = [
                raw if arg == "raw"
                else meta if arg == "meta"
                else meta.get(arg)
                for arg in m.get("parser_args", [])
            ]

            print(f"[SCAN] 실행 도구: {m['tool'].__name__}")
            print("==[DEBUG]==")
            print("Tool:", m["tool"].__name__)
            print("Args:", parser_args)
            print("Raw output keys:", list(raw.keys()))
            print("Meta:", meta)
            print("====================")

            parsed = m["parser"](*parser_args)
            print("[DEBUG] Parsed Result:", parsed)

            # 튜플이면 두 리스트를 병합
            if isinstance(parsed, tuple):
                parsed_list = []
                for item in parsed:
                    if isinstance(item, list):
                        parsed_list.extend(item)
            else:
                parsed_list = parsed if isinstance(parsed, list) else [parsed]

            for part in parsed_list:
                if not isinstance(part, dict):
                    continue

                for nxt_key in m.get("next_resource", []):
                    next_values = part.get(nxt_key)
                    if not next_values:
                        continue
                    if isinstance(next_values, str):
                        next_values = [next_values]

                    for nxt_val in next_values:
                        
                        nxt_val = custom_preprocess(nxt_val, nxt_key, m["tool"].__name__)
                        print(f"[DEBUG] next value after preprocess: {nxt_val}")

                        nxt_type = classify_resource(nxt_val)
                        # print(f"[DEBUG] classified resource type: {nxt_type}")

                        if nxt_type and (nxt_type, nxt_val) not in visited:
                            print(f"[DEBUG] 다음 자원 발견 → type: {nxt_type}, value: {nxt_val}")
                            queue.append((nxt_type, nxt_val))
                            print("===========")

    print("[DEBUG] 전체 스캔 흐름 종료. 더 이상 실행할 도구 없음.")
    # if depth == 0:
    #    print("[DEBUG] 모든 스캔 완료 후 Shadow IT 분석 시작")
    #    analyze_shadow_it.delay(scan_job_id)

@celery.task(name='tasks.analyze_shadow_it')
def analyze_shadow_it(scan_job_id):
    from shadow_it_analysis.loader import fetch_nuclei_results
    from shadow_it_analysis.reporter import save_shadowit_mapping

    nuclei_results = fetch_nuclei_results(scan_job_id)
    mapping = build_resource_subdomain_map(nuclei_results)
    save_shadowit_mapping(mapping, scan_job_id)
    print(f"[SHADOW IT] 분석 완료 - 리소스 {len(mapping)}개")


