from celery import Celery, Task
from resource_tool_map import RESOURCE_TOOL_MAP, classify_resource, custom_preprocess
from flask import Flask
from datetime import datetime
import requests
import re
import subprocess
import csv
import tldextract
import json
from celery_worker import celery
# DB 생기면 그떄 연결                     
#from db_module import save_scan_result, extract_resources


@celery.task
def extract_keywords_task(csv_path: str) -> str:
    """
    주어진 CSV 파일에서 도메인 키워드를 추출하여 JSON 문자열로 반환합니다.
    """
    keywords = set()

    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get('domain', '').strip()
            if not domain:
                continue
            ext = tldextract.extract(domain)
            if ext.domain:
                keywords.add(ext.domain)

    result = sorted(list(keywords))
    return json.dumps(result)

task = extract_keywords_task.delay('/home/mac/Desktop/capstone/domain_names.csv')
result_json = task.get(timeout=200)
keywords = json.loads(result_json)

print(keywords)

