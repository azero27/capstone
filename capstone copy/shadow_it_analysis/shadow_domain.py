import re
from collections import defaultdict
import json

import csv
import tldextract
import json
from celery_worker import celery  # 반드시 celery 인스턴스를 import 해야 함

def extract_keywords_task(csv_path: str) -> str:
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
    return json.dumps(result)  # Celery가 안전하게 전달할 수 있도록 JSON 직렬화


def extract_resource_identifier(resource: str) -> str:
    """
    리소스의 고유 식별자 추출 (예: S3 버킷 이름, CloudFront ID, GitHub 사용자 등)
    """
    parts = resource.split('.')
    return parts[0] if parts else ""

def identify_resource_type(resource: str) -> str:
    """
    도메인 패턴을 기반으로 리소스 유형을 식별
    """
    if "s3-website" in resource or "s3.amazonaws.com" in resource:
        return "AWS S3"
    elif "cloudfront.net" in resource:
        return "AWS CloudFront"
    elif "github.io" in resource:
        return "GitHub Pages"
    # elif "netlify.app" in resource:
    #    return "Netlify"
    #elif "vercel.app" in resource:
    #    return "Vercel"
    else:
        return "Unknown"

def analyze_nuclei_shadow_domains(parsed_results, user_resources):
    """
    nuclei 결과와 사용자 입력(S3 버킷 이름)을 비교하여 다음을 분류:
    - dangling_dns: [dns]+[http] 매칭된 위험 리소스
    - potential_exposure: S3 중 소유하지 않은 DNS 매칭 리소스
    - linked_known_resource: S3 중 소유한 DNS 매칭 리소스
    """
    resource_map = defaultdict(set)
    exposure_results = []
    confirmed_dangling = []
    known_links = []

    for result in parsed_results:
        target = result.get("target", "")
        url_list = result.get("url_list", [])
        vuln_msg = result.get("vulnerability", "").lower()

        for entry in url_list:
            if not entry.startswith("CNAME\t"):
                continue

            resource = entry.replace("CNAME\t", "").strip(".").lower()
            resource_type = identify_resource_type(resource)
            resource_identifier = extract_resource_identifier(resource)
            resource_map[resource].add(target)

            base_entry = {
                "resource": resource,
                "resource_type": resource_type,
                "resource_identifier": resource_identifier,
                "linked_domains": sorted(resource_map[resource])
            }

            # AWS S3인 경우에만 사용자 소유 여부 판단 및 포함
            if resource_type == "AWS S3":
                base_entry["is_user_owned"] = resource_identifier in user_resources

            if "[dns] and [http] matched" in vuln_msg:
                base_entry["status"] = "dangling_dns"
                confirmed_dangling.append(base_entry)

            elif "[dns] matched" in vuln_msg and "[http]" not in vuln_msg:
                if resource_type == "AWS S3" and resource_identifier in user_resources:
                    base_entry["status"] = "linked_known_resource"
                    known_links.append(base_entry)
                else:
                    base_entry["status"] = "potential_exposure"
                    exposure_results.append(base_entry)

    return {
        "dangling_dns": confirmed_dangling,
        "potential_exposure": exposure_results,
        "linked_known_resource": known_links
    }

parsed_nuclei_results = [
    {
        "target": "cdn.skyroute.com",
        "url_list": ["CNAME\tbucket1.s3.amazonaws.com"],
        "vulnerability": "detect-dangling-s3-cname [dns] matched"
    },
    {
        "target": "img.skyroute.com",
        "url_list": ["CNAME\tmy-owned-bucket.s3.amazonaws.com"],
        "vulnerability": "detect-dangling-s3-cname [dns] matched"
    },
    {
        "target": "static.skyroute.com",
        "url_list": ["CNAME\tstatic-site.github.io"],
        "vulnerability": "detect-dangling-s3-cname [dns] matched"
    },
    {
        "target": "media.skyroute.com",
        "url_list": ["CNAME\td111111abcdef8.cloudfront.net"],
        "vulnerability": "detect-dangling-s3-cname [dns] and [http] matched"
    }
]

user_resources = {"my-owned-bucket"}  # 사용자가 소유한 S3 버킷 이름 목록

results = analyze_nuclei_shadow_domains(parsed_nuclei_results, user_resources)
print(json.dumps(results, indent=2))

