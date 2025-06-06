from celery import Celery, Task
from resource_tool_map import RESOURCE_TOOL_MAP, classify_resource, custom_preprocess
from flask import Flask
from datetime import datetime
import requests
import re
import subprocess
import sys
import os
import csv
import tldextract
from DB.save_nmap import save_nmap_result
#from shadow_it_analysis.shadow_domain import build_resource_subdomain_map
from dns_utils import convert_domain_to_ip, convert_ip_to_domain
from DB.cloud_info import get_or_create_cloud_info
from DB.save_scan_result import save_scan_result_start, update_scan_result_end
from DB.scan_setting import save_scan_setting, latest_scan_setting, latest_scan_setting_id
from DB.save_nuclei import save_nuclei_result
from DB.save_diff import save_nmap_diff, save_amass_diff, save_cloudenum_diff, save_nuclei_diff, save_s3scanner_diff, save_shadow_diff
from celery.schedules import crontab
import redis
import json 

from shadow_it_analysis.shadow_domain import analyze_nuclei_shadow_domains
from shadow_it_analysis.shadow_network import analyze_shadow_network
from shadow_it_analysis.shadow_resource import analyze_shadow_resources

r = redis.Redis(host='localhost', port=6379, db=0)

def cache_result_for_dashboard(scan_result_id, tool_id, parsed_result, summary=None, ttl=600):
    key = f"scan_result:{scan_result_id}:tool:{tool_id}"
    try:
        serialized = json.dumps(parsed_result, default=str)

        if ttl and ttl > 0:
            r.setex(key, ttl, serialized)
        else:
            r.set(key, serialized)  # TTL이 0 이하일 경우 무기한 저장

        print(f"[CACHE] 저장 완료 → key: {key}")
    except Exception as e:
        print(f"[CACHE] 저장 실패 → key: {key}, 에러: {e}")


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
            "status": raw.get("status"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
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
            "status": raw.get("status", "success"), 
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
            "target_url": raw.get("target"),
            "output": raw.get("output"),
            "command": raw.get("command"),
            "target_url": raw.get("target_url"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    else:
        return {"tool_id": tool_id, **raw}  # fallback

def normalize_parsed_result(parsed, tool_id, step, tool_name=None):
    # 리스트가 아닐 경우 리스트로 변환
    if not isinstance(parsed, list):
        parsed = [parsed]

    # 중복 로그 블록 제거용 세트
    unique_log_blocks = set()
    filtered_parsed = []

    for item in parsed:
        if isinstance(item, dict):
            log_data = item.get("logs", "")
            key = (item.get("tool_id"), log_data)
        else:  # 문자열 등 다른 형식
            log_data = str(item)
            key = (tool_id, log_data)

        if key not in unique_log_blocks:
            unique_log_blocks.add(key)
            filtered_parsed.append(item)

    parsed = filtered_parsed

    logs = []

    # 도구명 변환 처리
    name_map = {
        "run_nmap_port_scan": "nmap",
        "run_nuclei_from_db": "nuclei"
    }
    raw_name = tool_name or f"Tool{tool_id}"
    display_name = name_map.get(raw_name, raw_name.replace("run_", "", 1) if raw_name.startswith("run_") else raw_name)

    for item in parsed:
        if isinstance(item, dict):
            raw_log = item.get("logs", "")
        else:
            raw_log = str(item)

        # 로그 라인 분리
        if display_name == "cloud_enum" and isinstance(raw_log, str):
            lines = raw_log.split(",")
        elif isinstance(raw_log, list):
            lines = raw_log
        elif isinstance(raw_log, str):
            lines = raw_log.strip().splitlines()
        else:
            lines = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            # cloud_enum 로그에서 S3 발견 시 구분용 줄바꿈
            if display_name == "cloud_enum" and line.startswith("OPEN S3 BUCKET:") and logs:
                logs.append("")
            logs.append(line)

    # 상태 및 요약 처리
    if parsed and isinstance(parsed[0], dict):
        raw_status = parsed[0].get("status", "")
    else:
        raw_status = ""

    if raw_status == "in_progress":
        status = "in_progress"
        summary = "Running..."
    else:
        status = "success" if logs else "fail"
        summary = "Complete"

    return [{
        "step": step,
        "tool": display_name,
        "tool_id": tool_id,
        "status": status,
        "summary": summary,
        "log": "\n".join(logs)
    }]


@celery.task(name='tasks.schedule_scan')
def schedule_scan(resource_type, value, scan_setting_id, step=1, scan_result_id=None):
    print(f"\n🚀 [SCHEDULE SCAN START] 주기적 스캔 시작됨")
    print(f"[{datetime.now()}] 🚀 [SCHEDULE SCAN START] type={resource_type}, value={value}, scan_setting_id={scan_setting_id}")

    visited = set()
    queue = [(resource_type, value, step, True)]  # is_initial=True

    if scan_result_id is None:
        step = 1
        ip_address, domain_name = None, None

        if resource_type == "ip":
            ip_address = value
            domain_name = convert_ip_to_domain(value)
        elif resource_type == "domain":
            domain_name = value
            ip_address = convert_domain_to_ip(value)
        elif resource_type == "keyword":
            ip_address = r.get("scheduled_ip").decode() if r.get("scheduled_ip") else None
            domain_name = r.get("scheduled_domain").decode() if r.get("scheduled_domain") else None

        if ip_address and domain_name:
            cloud_info_id = get_or_create_cloud_info(ip_address, domain_name)
            scan_setting_id = save_scan_setting(15)
            scan_result_id = save_scan_result_start(cloud_info_id, scan_setting_id)

        # scan_result_id = "mock-scan-id"

    while queue:
        resource_type, value, job_name, is_initial = queue.pop(0)

        if (resource_type, value) in visited:
            continue
        visited.add((resource_type, value))

        mappings = RESOURCE_TOOL_MAP.get(resource_type, [])
        for m in mappings:
            tool_id = m.get("tool_id", -1)
            tool_name = m.get("tool_name", m["tool"].__name__)

            input_values = []
            for arg in m.get("input_args", []):
                for k, v in arg.items():
                    input_values.append(value if v == "value" else v)

            current_step = step if is_initial else step + 1

            # 도구 실행 전 → 상태 캐시 (in_progress)
            normalized = normalize_parsed_result(
                {"status": "in_progress", "summary": f"Running...", "logs": ""},
                tool_id,
                current_step,
                tool_name
            )
            cache_result_for_dashboard(scan_result_id, tool_id, normalized, ttl=600)


            raw = m["tool"](*input_values)
            meta = build_meta(tool_id, raw)
            

            parser_args = []
            parsed = []

            parser_args = [
                eval(arg, {}, {"raw": raw, "meta": meta})
                if isinstance(arg, str) and ("[" in arg or "." in arg)
                else raw if arg == "raw"
                else meta if arg == "meta"
                else meta.get(arg)
                for arg in m.get("parser_args", [])
            ]
            parsed = m["parser"](*parser_args)


            print(f"[SCAN] 실행 도구: {m['tool'].__name__}")
            print("==[DEBUG]==")
            print("Tool:", m["tool"].__name__)
            print("Args:", parser_args)
            print("Raw output keys:", list(raw.keys()))
            print("Meta:", meta)
            print("====================")

  
            print("[DEBUG] Parsed Result:", parsed)
            try:
                if tool_id == 1:
                    from DB.save_nmap import save_nmap_result
                    save_nmap_result(raw, value, tool_id, scan_result_id, current_step)
                    save_nmap_diff(scan_result_id)

                    parsed_list = []
                    if isinstance(parsed, tuple):
                        for item in parsed:
                            if isinstance(item, list):
                                parsed_list.extend(item)
                    else:
                        parsed_list = parsed if isinstance(parsed, list) else [parsed]

                    normalized = normalize_parsed_result(parsed_list, tool_id, current_step, tool_name)
                    cache_result_for_dashboard(scan_result_id, tool_id, normalized, ttl=0)

                elif tool_id == 2:
                    from DB.save_cloud_enum import save_cloud_enum_result
                    buckets, files = parsed
                    save_cloud_enum_result(buckets, files, scan_result_id, current_step)
                    save_cloudenum_diff(scan_result_id)

                    combined = {
                        "buckets": buckets,
                        "files": files
                    }

                    combined_list = []
                    if isinstance(buckets, list):
                        combined_list.extend(buckets)
                    if isinstance(files, list):
                        combined_list.extend(files)

                    normalized = normalize_parsed_result(combined_list, tool_id, current_step, tool_name)
                    cache_result_for_dashboard(scan_result_id, tool_id, normalized, ttl=0)

                elif tool_id == 3:
                    from DB.save_amass import save_amass_result
                    save_amass_result(parsed, scan_result_id, current_step)
                    save_amass_diff(scan_result_id)

                    parsed_list = []
                    if isinstance(parsed, tuple):
                        for item in parsed:
                            if isinstance(item, list):
                                parsed_list.extend(item)
                    else:
                        parsed_list = parsed if isinstance(parsed, list) else [parsed]

                    normalized = normalize_parsed_result(parsed_list, tool_id, current_step, tool_name)
                    cache_result_for_dashboard(scan_result_id, tool_id, normalized, ttl=0)


                elif tool_id == 4:
                    from DB.save_s3scanner import save_s3scanner_result
                    save_s3scanner_result(parsed, scan_result_id, current_step)
                    save_s3scanner_diff(scan_result_id)
                
                    entries, sensitive_file_entries = parsed

                    combined = {
                        "buckets": entries,
                        "sensitive_files": sensitive_file_entries
                    }

                    combined_list = []
                    if isinstance(entries, list):
                        combined_list.extend(entries)
                    if isinstance(sensitive_file_entries, list):
                        combined_list.extend(sensitive_file_entries)

                    normalized = normalize_parsed_result(combined_list, tool_id, current_step, tool_name)
                    cache_result_for_dashboard(scan_result_id, tool_id, normalized, ttl=0)


                elif tool_id == 5:
                    from DB.save_enumerate_iam import save_enumerate_iam_result
                    save_enumerate_iam_result(parsed, scan_result_id, current_step)
                
                    parsed_list = []
                    if isinstance(parsed, tuple):
                        for item in parsed:
                            if isinstance(item, list):
                                parsed_list.extend(item)
                    else:
                        parsed_list = parsed if isinstance(parsed, list) else [parsed]

                    normalized = normalize_parsed_result(parsed_list, tool_id, current_step, tool_name)
                    cache_result_for_dashboard(scan_result_id, tool_id, normalized, ttl=0)

                elif tool_id == 6:
                    for result in parsed:  # parsed는 list of dict
                        save_nuclei_result(result, scan_result_id, current_step)

                        parsed_list = []
                        if isinstance(parsed, tuple):
                            for item in parsed:
                                if isinstance(item, list):
                                    parsed_list.extend(item)
                        else:
                            parsed_list = parsed if isinstance(parsed, list) else [parsed]

                        normalized = normalize_parsed_result(parsed_list, tool_id, current_step, tool_name)
                        cache_result_for_dashboard(scan_result_id, tool_id, normalized, ttl=0)

                print(f"[+] 도구 {tool_id} 결과 저장 완료")
            except Exception as e:
                print(f"[ERROR] 도구 {tool_id} 결과 저장 실패: {e}")

            parsed_list = []
            if isinstance(parsed, tuple):
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

                        # step 2까지만 허용
                        if step + 1 > 2:
                            print(f"[SKIP] step 2 초과: ({nxt_type}, {nxt_val}, step={step + 1})")
                            continue

                        # (type, value, step) 기준으로 중복 방지
                        if nxt_type and (nxt_type, nxt_val, step + 1) not in visited:
                            print(f"[DEBUG] 다음 자원 발견 → type: {nxt_type}, value: {nxt_val}, step: {step + 1}")
                            queue.append((nxt_type, nxt_val, step + 1, False))
                            visited.add((nxt_type, nxt_val, step + 1))
                            print("===========")

    template_path = "/home/skyroute/nuclei-templates/dns/detect-dangling-s3-cname.yaml"
    r = redis.Redis(host='localhost', port=6379, db=0)
    

    if tool_id == 6 and not is_initial and resource_type == "url":
        # Redis에서 이미 nuclei 실행했는지 확인
        nuclei_flag_key = f"nuclei_done:{scan_result_id}"
        if not r.get(nuclei_flag_key):
            print("[*] DB 기반 Nuclei 실행 시작")
            from tools.nuclei import run_nuclei_from_db
            all_result = run_nuclei_from_db(template_path)
            results = all_result.get("results", [])
            for result in results:
                save_nuclei_result(result, scan_result_id, current_step)
                normalized = normalize_parsed_result(result, tool_id, current_step, tool_name)
                cache_result_for_dashboard(scan_result_id, tool_id, normalized)
            print("[+] DB 기반 Nuclei 저장 완료")
            r.set(nuclei_flag_key, "1")  # 실행 완료 표시
            save_nuclei_diff(scan_result_id)
        else:
            print(f"[!] nuclei already run for scan_result_id={scan_result_id}")

    print("[DEBUG] 전체 스캔 흐름 종료. 더 이상 실행할 도구 없음.")

    if scan_result_id is not None:
        update_scan_result_end(scan_result_id)
        print(f"[+] 스캔 종료 시간 저장 완료 (ScanResult ID={scan_result_id})")
    else:
        print("[MOCK] scan_result_id 없음 - DB 저장 생략")

    return scan_result_id



@celery.task(name='tasks.analyze_shadow_components_mock')
def analyze_shadow_components_mock(scan_result_ids):
    print(f"[SHADOW IT MOCK 분석 시작] ScanResult ID 목록: {scan_result_ids}")

    """
    # ========== MOCK 1. nuclei + 사용자 소유 버킷 ==========
    parsed_nuclei_results = [
        {"target": "cdn.skyroute.com", "url_list": ["CNAME\tbucket1.s3.amazonaws.com"], "vulnerability": "detect-dangling-s3-cname [dns] matched"},
        {"target": "img.skyroute.com", "url_list": ["CNAME\tmy-owned-bucket.s3.amazonaws.com"], "vulnerability": "detect-dangling-s3-cname [dns] matched"},
        {"target": "static.skyroute.com", "url_list": ["CNAME\tstatic-site.github.io"], "vulnerability": "detect-dangling-s3-cname [dns] matched"},
        {"target": "media.skyroute.com", "url_list": ["CNAME\td111111abcdef8.cloudfront.net"], "vulnerability": "detect-dangling-s3-cname [dns] and [http] matched"}
    ]
    user_resources = {"my-owned-bucket"}

    print("\n===== 1. analyze_nuclei_shadow_domains() 결과 =====")
    nuclei_result = analyze_nuclei_shadow_domains(parsed_nuclei_results, user_resources)
    print(json.dumps(nuclei_result, indent=2, ensure_ascii=False))

    cache_shadow_component(scan_result_ids, "nuclei", nuclei_result)
    """

    # ========== MOCK 2. Nmap 결과 및 허용 포트 ==========

    nmap_result = analyze_shadow_network()
    #cache_shadow_component(scan_result_ids, "nmap", nmap_result)

    # ========== MOCK 3. S3scanner + 공개정책 ==========

    print("\n===== 3. show_violating_buckets_verbose() 결과 =====")
    s3_result = analyze_shadow_resources()
    #cache_shadow_component(scan_result_ids, "s3", s3_result)

    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor(dictionary=True)

    # 1. 최신 ScanResult ID 가져오기
    cursor.execute("SELECT MAX(id) as latest_id FROM ScanResult")
    latest_result_id = cursor.fetchone()["latest_id"]

    save_shadow_diff(latest_result_id)


@celery.task(name="tasks.dummy_task")
def dummy_task():
    pass


@celery.task(name='tasks.run_oneoff_full_scan')
def run_oneoff_full_scan(resource_type):
    """
    버튼 클릭 시점에 한 번만 호출되는 태스크.
    resource_type: 'ip' | 'domain' | 'keyword'
    """
    # 1) 최신 스캔 설정 ID
    scan_setting_id = latest_scan_setting_id()
    # scan_setting_id = "mock-setting-id"

    # 2) Redis에서 대상 값 가져오기
    raw = None
    if resource_type == 'ip':
        raw = r.get('scheduled_ip')
    elif resource_type == 'domain':
        raw = r.get('scheduled_domain')
    elif resource_type == 'keyword':
        raw = r.get('scheduled_keyword')
    if not raw:
        # 없으면 바로 리턴
        return

    value = raw.decode()

    # 3) schedule_scan 태스크 한 번만 호출
    # 기존의 주기 스캔 로직(schedule_scan)을 재사용
    schedule_scan.apply_async(args=(resource_type, value, scan_setting_id))