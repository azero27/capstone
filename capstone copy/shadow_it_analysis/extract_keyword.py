import csv
import tldextract
import json
from celery import shared_task


@shared_task(name="tasks.extract_keyword")
def extract_keyword(csv_path: str) -> str:
    """
    도메인 CSV 파일에서 도메인 키워드 추출 후 JSON 문자열로 반환
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

