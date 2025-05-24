from datetime import datetime
import re
import os

def parse_cloud_enum_output(output_file_path: str, keyword_command: str, start_time: datetime, end_time: datetime, tool_id=6):
    results_main = []
    results_files = []

    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    with open(output_file_path, 'r', encoding='utf-8') as f:
        cloud_enum_output = f.read()

    blocks = re.split(r'OPEN S3 BUCKET: ', cloud_enum_output)[1:]

    for idx, block in enumerate(blocks):
        lines = block.strip().splitlines()

        raw_target = lines[0].strip()
        target = ansi_escape.sub('', raw_target)
        log_lines = ["OPEN S3 BUCKET: " + raw_target]
        discovered_info_list = []
        in_files_section = False

        for line in lines[1:]:
            if "FILES:" in line:
                log_lines.append("    FILES:")
                in_files_section = True
                continue

            if in_files_section:
                if line.strip().startswith("->"):
                    url = line.strip()[2:].strip()
                    discovered_info_list.append(url)
                    log_lines.append("      ->" + url)
                else:
                    break
            else:
                log_lines.append(line)

        scan_result_id = idx + 1

        result_main = {
            "id": scan_result_id,
            "tool_id": tool_id,
            "target": target,
            "command": keyword_command,
            "success_failure": "success" if discovered_info_list else "failure",
            "logs": '\n'.join(log_lines),
            "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        results_main.append(result_main)

        for url in discovered_info_list:
            results_files.append({
                "scan_result_id": scan_result_id,
                "file_url": url
            })

    # 파일 삭제
    try:
        os.remove(output_file_path)
        print(f"[INFO] Temporary file {output_file_path} deleted.")
    except Exception as e:
        print(f"[WARNING] Could not delete {output_file_path}: {e}")

    return results_main, results_files
