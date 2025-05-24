from tools.nmap import run_nmap_port_scan
from tools.s3scanner import run_s3scanner
from tools.amass import run_amass
from tools.nuclei import run_nuclei
from tools.enumerate_iam import run_enumerate_iam
from tools.cloud_enum import run_cloud_enum

from parses.parse_nmap import parse_nmap_port_scan_output
from parses.parse_s3scanner import parse_s3scanner_output
from parses.parse_amass import parse_amass_output
from parses.parse_nuclei import parse_nuclei_output
from parses.parse_enumerate_iam import parse_enumerate_iam_output
from parses.parse_cloud_enum import parse_cloud_enum_output

import re
import os

RESOURCE_TOOL_MAP = {
    #도메인인 이유가 있나? ip로 바꿔도 되나?
   
    #"domain": [
    #    {   
    #        "tool_id": 1,
    #        "tool": run_nmap_port_scan,
    #        "input_args" : [{"ip_address": "value"}],
    #        "parser": parse_nmap_port_scan_output,
    #        "parser_args": ["output", "command", "status", "start_time", "end_time", "tool_id"],
    #        "next_resource": []  # nmap은 취약점 정보로 끝
    #    }
    #],
    
    "ip": [
        {
            "tool_id": 1,
            "tool": run_nmap_port_scan,
            "input_args" : [{"ip_address": "value"}],
            "parser": parse_nmap_port_scan_output,
            "parser_args": ["output", "command", "status", "start_time", "end_time", "tool_id"],
            "next_resource": []  # nmap은 취약점 정보로 끝
        }
    ],
    "keyword": [
        {
            "tool_id": 2,
            "tool": run_cloud_enum,
            "input_args" : [{"keyword": "value"}],
            "parser": parse_cloud_enum_output,
            "parser_args": ["output_file", "command", "start_time", "end_time", "tool_id"],
            "next_resource": ["target"]  # 퍼블릭 S3 버킷 식별
        },
        {
            "tool_id": 3,
            "tool": run_amass,
            "input_args" : [{"keyword": "value"}],
            "parser": parse_amass_output,
            "parser_args": ["output", "meta"],
            "next_resource": ["subdomain_list"]  # 서브도메인 → nuclei로
        }
    ],
    "url": [
        {
            "tool": run_nuclei,
            "input_args": [
                {"url": "value"},
                {"template_path": "/home/skyroute/nuclei-templates/dns/detect-dangling-s3-cname.yaml"}
            ],
            "parser": parse_nuclei_output,
            "parser_args": ["output", "meta"],
            "next_resource": ["url_list"]  # dangling S3 CNAME 식별됨
        }
    ],
    "s3": [
        {
            "tool": run_s3scanner,
            "input_args" : [],
            "parser": parse_s3scanner_output,
            "parser_args": ["output", "tool", "command", "start_time", "end_time"],
            "next_resource": ["object_paris"]  # S3 내부에서 key 발견 시
        }
    ],
    "credentials": [
        {
            "tool": run_enumerate_iam,
            "input_args": [
                {"access_key": "value"},
                {"secret_key": "value"}
            ],
            "parser": parse_enumerate_iam_output,
            "parser_args": ["output_file", "tool", "command", "start_time", "end_time"],
            "next_resource": []  # IAM 함수 확인으로 끝
        }
    ]
}

def classify_resource(value: str) -> str:
    if value.startswith("http") and "s3" and ".amazonaws.com" in value:
        return "s3"
    elif value.startswith("http"):
        return "url"
    elif value.startswith("AKIA") or value.startswith("ASIA") or value.startswith("AWS"):
        return "credentials"
    # elif "." in value and not value.startswith("http"):
    #    return "domain"
    # elif any(keyword in value.lower() for keyword in ["bucket", "log", "audit", "cloud", "search"]):
    #    return "keyword"
    else:
        return None

def custom_preprocess(nxt_val: str, nxt_key: str, tool_name: str) -> str:
    # for cloud_enum → s3scanner
    if tool_name == "run_cloud_enum" and nxt_key == "target":
        cleaned = nxt_val.rstrip("/")
        match = re.search(r"https?://([^.]+)\.s3\.", cleaned)
        if match:
            bucket_name = match.group(1)
            names_path = os.path.join(
                os.path.expanduser("~"),
                "cloud-1", "capstone", "capstone", "tools", "S3Scanner", "names.txt"
            )

            # 파일 초기화 후 첫 번째 버킷 추가
            if not os.path.exists(names_path) or os.path.getsize(names_path) == 0:
                # 파일이 없거나 비어 있다면 새로 작성
                with open(names_path, "w") as f:
                    f.write(bucket_name + "\n")
            else:
                # 이미 버킷이 쓰여진 경우는 append만
                with open(names_path, "r") as f:
                    existing = set(line.strip() for line in f)
                if bucket_name not in existing:
                    with open(names_path, "a") as f:
                        f.write(bucket_name + "\n")

        return cleaned

    if tool_name == "run_amass" and nxt_key == "subdomain_list":
        return f"http://{nxt_val}"

    return nxt_val

def handle_next_tools(parsed_result: dict):
    """
    현재 파싱 결과에서 next_resource 키들을 기준으로 다음 도구 실행 흐름 결정.
    """
    for result_key in parsed_result.get("next_resources", []):
        resource_items = parsed_result.get(result_key)

        if not resource_items:
            continue

        # 여러 개일 수 있음 (예: subdomains 리스트, file_url 리스트 등)
        if isinstance(resource_items, str):
            resource_items = [resource_items]

        for item in resource_items:
            resource_type = classify_resource(item)

            if resource_type and resource_type in RESOURCE_TOOL_MAP:
                for tool_def in RESOURCE_TOOL_MAP[resource_type]:
                    tool_func = tool_def["tool"]
                    parser_func = tool_def["parser"]
                    parser_args = tool_def["parser_args"]

                    # 도구 실행
                    raw_output = tool_func(item)

                    # 파싱
                    if isinstance(parser_args, list):
                        parsed_output = parser_func(*(raw_output.get(arg) for arg in parser_args))
                    else:
                        parsed_output = parser_func(raw_output)

                    # 재귀적으로 다음 흐름 처리
                    parsed_output["next_resources"] = tool_def.get("next_resource", [])
                    handle_next_tools(parsed_output)

