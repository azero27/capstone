import re
from collections import defaultdict

def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)

def extract_target_url(command):
    match = re.search(r"-u\s+(http[s]?://\S+)", command)
    return match.group(1) if match else None

def extract_core_logs(log_text):
    return "\n".join(
        line for line in log_text.splitlines()
        if line.startswith("[detect-dangling-s3")
    )

def infer_success(log_text):
    matches = re.findall(r"Matched:\s*(\d+)", log_text)
    return int(matches[-1]) if matches else 0 # 마지막 matched 값으로 판단

def extract_all_cname_records(log_text, base_domain):
    """
    CNAME\t<도메인> 형식 그대로 추출하고 리스트로 반환
    """
    # 대상 도메인의 DNS 매핑 블록 찾기
    pattern = re.search(rf"\[dns\]\s+\[info\]\s+{re.escape(base_domain)}\s+\[(.*?)\]", log_text)
    if pattern:
        raw_cname_block = pattern.group(1)
        matches = re.findall(r'CNAME\\t([^\"]+)', raw_cname_block)
        return [f"CNAME\t{c}" for c in matches] if matches else []
    return []

def parse_nuclei_output(stdout: str, meta: dict):
    # 1. ANSI 코드 제거
    clean_stdout = strip_ansi(stdout)

    # 2. DNS/HTTP 매칭 확인용 도메인 분리
    lines = clean_stdout.strip().splitlines()
    detections = defaultdict(set)

    for line in lines:
        if "[detect-dangling-s3-cname]" in line:
            if "[dns]" in line:
                match = re.search(r"\[dns\].*?(http[s]?://\S+|\S+)", line)
                if match:
                    domain = match.group(1).replace("http://", "").replace("https://", "")
                    detections[domain].add("dns")
            elif "[http]" in line:
                match = re.search(r"\[http\].*?(http[s]?://\S+)", line)
                if match:
                    domain = match.group(1).replace("http://", "").replace("https://", "")
                    detections[domain].add("http")

    # 3. matched 수 기반 분석
    matched_count = infer_matched_count(clean_stdout)
    final_success = 1 if matched_count >= 1 else 0

    # 4. CNAME 레코드 추출
    base_domain = meta.get("target_url", "").replace("http://", "").replace("https://", "")
    cname_records = extract_all_cname_records(clean_stdout, base_domain)

    # 5. 위험도 및 취약점 메시지 결정
    if matched_count == 0:
        vuln_msg = "No CNAME record detected"
        risk = "info"
    elif matched_count == 1:
        vuln_msg = "detect-dangling-s3-cname [dns] matched"
        risk = "medium"
    else:
        vuln_msg = "detect-dangling-s3-cname [dns] and [http] matched"
        risk = "high"

    return {
        "tool_id": 1,
        "target": meta.get("target_url"),
        "command": meta.get("command"),
        "success": final_success,
        "vulnerability": vuln_msg,
        "risk_level": risk,
        "url": "\n".join(cname_records),       # 문자열 (DB용)
        "url_list": cname_records,             # 리스트 (프론트용)
        "log": extract_core_logs(clean_stdout),
        "start_time": meta.get("start_time"),
        "end_time": meta.get("end_time")
    }
