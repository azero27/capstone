import sys
import os
sys.path.append(os.path.abspath("."))  # 현재 디렉토리를 모듈 경로에 추가

from shadow_it_analysis.shadow_domain import build_resource_subdomain_map

# nuclei 실행 결과 흉내낸 더미 데이터
nuclei_results = [
    {
        "nulcei_result": {
            "target": "http://data.sskyroute.com",
            "url_list": [
                "CNAME\tdata.sskyroute.com.s3-website.ap-northeast-2.amazonaws.com.",
                "CNAME\ts3-website.ap-northeast-2.amazonaws.com."
            ]
        }
    },
    {
        "nulcei_result": {
            "target": "http://cdn.example.com",
            "url_list": [
                "CNAME\tcdn.example.com.d3abcd12345.cloudfront.net.",
                "CNAME\td3abcd12345.cloudfront.net."
            ]
        }
    }
]

# 분석 함수 실행
result = build_resource_subdomain_map(nuclei_results)

# 결과 확인
for entry in result:
    print(f"📦 Resource: {entry['resource']}")
    print(f"   Type: {entry['resource_type']}")
    print(f"   Linked Subdomains: {entry['linked_subdomains']}")
    print()
