
import json
from shadow_it_analysis.extract_keyword import extract_keyword # detect_domain_s3
from task_defs import schedule_scan

task = extract_keyword.delay('csv_files/domain.csv')
keyword_json = task.get(timeout=200)
keyword = json.loads(keyword_json)

print("[DOMAIN KEYWORD ANALYSIS]", keyword)

for kw in keyword:
    schedule_scan.delay("keyword", kw, f"scan_job_{kw}")
