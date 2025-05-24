def fetch_nuclei_results(scan_job_id):
    # 테스트용 nuclei 결과 mock
    return [
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
