import re
from collections import defaultdict
from typing import List, Dict
import csv, json, dns.resolver
import tldextract

def extract_subdomain(url: str) -> str:
    """
    Remove protocol from the URL and return the subdomain.
    """
    return re.sub(r"^https?://", "", url).strip("/")

def extract_resource(cname_line: str) -> str:
    """
    Extract the core resource from a CNAME line.
    """
    cname_value = cname_line.replace("CNAME\t", "").strip(".")
    return cname_value

def build_resource_subdomain_map(nuclei_results: List[Dict]) -> List[Dict]:
    """
    Build a mapping of resource -> linked subdomains from a list of nuclei results.
    """
    resource_map = defaultdict(set)

    for item in nuclei_results:
        result = item.get("nulcei_result", {})
        target = result.get("target", "")
        url_list = result.get("url_list", [])

        subdomain = extract_subdomain(target)
        for cname in url_list:
            resource = extract_resource(cname)
            resource_map[resource].add(subdomain)

    structured_results = []
    for resource, subdomains in resource_map.items():
        resource_type = identify_resource_type(resource)
        structured_results.append({
            "resource": resource,
            "resource_type": resource_type,
            "linked_subdomains": sorted(list(subdomains))
        })

    return structured_results

def identify_resource_type(resource: str) -> str:
    """
    Identify the type of cloud resource based on patterns.
    """
    #if re.search(r"^s3[.-][a-z0-9-]+\.amazonaws\.com$", resource) or "s3-website" in resource:
    if "s3-website" in resource:
        return "AWS S3"
    elif "cloudfront.net" in resource:
        return "AWS CloudFront"
    # elif "herokuapp.com" in resource:
    #     return "Heroku"
    elif "github.io" in resource:
        return "GitHub Pages"
    # elif "netlify.app" in resource:
    #    return "Netlify"
    #elif "vercel.app" in resource:
    #    return "Vercel"
    else:
        return "Unknown"


def extract_keywords_task(csv_path: str) -> str:
    """
    주어진 CSV 파일에서 도메인 키워드를 추출하여 JSON 문자열로 리턴
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


def detect_domain_s3(domain_csv_path: str, bucket_csv_path: str) -> str:
    """
    도메인 검사. 1, 2차 dangling DNS, DNS 탈취 및 미관리 버킷 가능성 검사
    """

    user_buckets = set()
    public_user_buckets = set()
    known_domains = set()
    results = []

    print("[START] Shadow IT 분석 시작")
    print(f"도메인 파일: {domain_csv_path}")
    print(f"S3 버킷 파일: {bucket_csv_path}")

    # 사용자 버킷 정보 로딩
    try:
        with open(bucket_csv_path, newline='') as bfile:
            reader = csv.DictReader(bfile)
            for row in reader:
                bucket = row.get('s3_bucket', '').strip().lower()
                is_public = row.get('public_s3_bucket', '').strip().upper()
                if bucket:
                    user_buckets.add(bucket)
                    if is_public == 'TRUE':
                        public_user_buckets.add(bucket)
        print(f"[DEBUG] 전체 버킷 수: {len(user_buckets)}, 공개 버킷 수: {len(public_user_buckets)}")
    except Exception as e:
        print(f"[ERROR] 버킷 파일 로딩 실패: {e}")
        return json.dumps({"error": "bucket file read failed"})

    # 도메인 리스트 로딩
    try:
        with open(domain_csv_path, newline='') as dfile:
            reader = csv.DictReader(dfile)
            for row in reader:
                domain = row.get('domain', '').strip().lower()
                if not domain:
                    continue
                known_domains.add(domain)
    except Exception as e:
        print(f"[ERROR] 도메인 파일 로딩 실패: {e}")
        return json.dumps({"error": "domain file read failed"})

    # CNAME 보유 도메인만 검사
    for domain in known_domains:
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            cname1 = str(answers[0].target).rstrip('.').lower()
            cname1 = cname1.replace("http://", "").replace("https://", "")
            print(f"[DEBUG] CNAME: {domain} → {cname1}")
        except dns.resolver.NoAnswer:
            print(f"[INFO] CNAME 없음 (검사 제외): {domain}")
            continue
        except Exception as e:
            print(f"[WARNING] CNAME 조회 실패: {domain} → {e}")
            continue

        # 1차 Dangling 검사
        if 's3.amazonaws.com' in cname1 or 's3-website' in cname1:
            parts = cname1.split('.')
            if len(parts) >= 4:
                bucket = '.'.join(parts[:-4]).strip().lower()
                if bucket not in user_buckets:
                    results.append({
                        "domain": domain,
                        "cname": cname1,
                        "bucket": bucket,
                        "status": "unowned_or_dangling",
                        "is_public": bucket in public_user_buckets
                    })
                    continue  # 이미 1차에서 Dangling 확정되었으면 2차 검사 생략
                else:
                    print(f"[DEBUG] 소유한 S3 버킷: {bucket}")
            else:
                print(f"[WARNING] CNAME 구조 이상: {cname1}")

        # 2차 Dangling DNS 검사
        if cname1 not in known_domains:
            try:
                second = dns.resolver.resolve(cname1, 'CNAME')
                cname2 = str(second[0].target).rstrip('.').lower()
                print(f"[DEBUG] 2차 CNAME 성공: {cname1} → {cname2}")
            except dns.resolver.NXDOMAIN:
                print(f"2차 Dangling DOMAIN: {domain} → {cname1}")
                results.append({
                    "domain": domain,
                    "intermediate_cname": cname1,
                    "status": "2nd_dangling_dns"
                })
            except dns.resolver.NoAnswer:
                print(f"[INFO] 2차 CNAME 없음 (정상일 수 있음): {cname1}")
            except Exception as e:
                print(f"[WARNING] 2차 CNAME 조회 실패: {cname1} → {e}")

    return json.dumps(results, indent=2)
