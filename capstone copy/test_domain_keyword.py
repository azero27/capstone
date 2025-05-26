
import json

from task_defs import extract_keywords_task, detect_domain_s3

# DB 생기면 그떄 연결                     
#from db_module import save_scan_result, extract_resources


task = extract_keywords_task.delay('/capstone/csv_files/domain.csv')
result_json = task.get(timeout=200)
result = json.loads(result_json)

print("[DOMAIN KEYWORD ANALYSIS]", result)


task = detect_domain_s3.delay('//capstone/csv_files/domain.csv', '/capstone/csv_files/s3_bucket.csv')
result_json = task.get(timeout=200)
result = json.loads(result_json)

print("[S3 ANALYSIS]", result)
