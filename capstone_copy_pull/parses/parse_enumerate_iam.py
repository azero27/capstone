import re

def parse_enumerate_iam_output(file_path, tool_id, command, start_time, end_time):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except Exception as e:
        return []

    parsed_rows = []
    for line in lines:
        match = re.search(r"--\s*([a-z0-9]+)\.([a-z0-9_]+)\(\)\s*worked!", line, re.IGNORECASE)
        if match:
            service, function = match.groups()
            parsed_rows.append({
                "tool_id": tool_id,
                "target": service,
                "command": command,
                "success_failure": "success",
                "discovered_info": f"{service}.{function}",
                "logs": line.strip(),
                "start_time": start_time,
                "end_time": end_time
            })
    
    # 파일 삭제
    try:
        os.remove(file_path)
    except Exception as e:
        print(f"[WARN] Failed to delete log file: {file_path} → {e}")

    return parsed_rows
