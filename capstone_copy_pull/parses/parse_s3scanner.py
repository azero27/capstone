import os
import re
from urllib.parse import unquote, quote_plus
from datetime import datetime

def parse_s3scanner_output(log_text, tool_id, command, start_time, end_time):
    entries = []
    sensitive_file_entries = []

    lines = log_text.strip().splitlines()
    current_bucket_name = ""
    auth_perm = ""
    all_perm = ""
    full_log = log_text.strip()

    for idx, line in enumerate(lines):
        line = line.strip()

        # exists 처리
        if "exists" in line and "|" in line:
            parts = line.split("|")
            if len(parts) >= 5:
                current_bucket_name = parts[1].strip()
                auth_perm = parts[3].split(":", 1)[-1].strip()
                all_perm = parts[4].split(":", 1)[-1].strip()

                entries.append({
                    "tool_id": tool_id,
                    "target": current_bucket_name,
                    "command": command,
                    "success_failure": "success",
                    "bucket_status": "exist",
                    "bucket_name": current_bucket_name,
                    "authusers_permission": auth_perm,
                    "allusers_permission": all_perm,
                    "sensitive_files": "",
                    "file_type": "",
                    "logs": line,
                    "start_time": start_time,
                    "end_time": end_time
                })

        # not_exist 처리
        elif "not_exist" in line and "|" in line:
            parts = line.split("|")
            if len(parts) >= 2:
                current_bucket_name = parts[1].strip().strip('"')

                entries.append({
                    "tool_id": tool_id,
                    "target": current_bucket_name,
                    "command": command,
                    "success_failure": "success",  # 도구 실행 성공으로 간주
                    "bucket_status": "not_exist",
                    "bucket_name": current_bucket_name,
                    "authusers_permission": "",
                    "allusers_permission": "",
                    "sensitive_files": "",
                    "file_type": "",
                    "logs": line,
                    "start_time": start_time,
                    "end_time": end_time
                })

        # 객체 정보 파싱
        elif "[object]" in line:
            object_match = re.search(r"\[object\]\s+(.*?)\s+\((.*?)\)", line)
            if object_match and current_bucket_name:
                filename = unquote(object_match.group(1).strip())
                size = object_match.group(2).strip()
                ext = os.path.splitext(filename)[-1] if '.' in filename and not filename.endswith('/') else ""

                url = f"https://{current_bucket_name}.s3.ap-northeast-2.amazonaws.com/{quote_plus(filename)}"

                sensitive_file_entries.append({
                    "target": current_bucket_name,
                    "object": filename,
                    "object_type": ext,
                    "object_size": size,
                    "url": url,
                })

    return entries, sensitive_file_entries 