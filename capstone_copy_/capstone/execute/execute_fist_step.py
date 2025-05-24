from flask import Flask, request, jsonify, render_template, redirect, url_for
from tools.nmap import run_nmap  # nmap.py에서 만든 모듈을 임포트
from tools.s3scanner import run_s3scanner  # s3scanner 실행
# from tools.amass import run_amass  # amass 실행
from tools.nuclei import run_nuclei  # nuclei 실행
from tools.enumerate_iam import run_enumerate_iam  # nuclei 실행
from tools.cloud_enum import run_cloud_enum  # cloud_enum 실행
# from parses.parse_amass import parse_amass_output 
from parses.parse_cloud_enum import parse_cloud_enum_output 
from parses.parse_nuclei import parse_nuclei_output 
from parses.parse_s3scanner import parse_s3scanner_output 
from parses.parse_enumerate_iam import parse_enumerate_iam_output 
from parses.parse_nmap import parse_nmap_output 
from dns_utils import convert_domain_to_ip
from dns_utils import convert_ip_to_domain
import socket
import re
import os


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    # 사용자가 제출한 IP 주소를 가져오기
    ip_address = request.form['ip_address']
    
    # 여기서 IP 주소를 처리하는 로직을 추가할 수 있습니다
    # 예를 들어, nmap 스캔을 실행하거나 다른 작업을 수행할 수 있습니다.
    
    # 임시 응답으로 입력된 IP 주소를 보여줍니다.
    return redirect(url_for('scan', ip=ip_address))


@app.route('/scan', methods=['GET'])
def scan():
    """
    클라이언트로부터 IP 주소를 받아 Nmap을 실행하고 결과를 반환하는 엔드포인트.
    """
    ip = request.args.get('ip')
    keyword = request.args.get('keyword', '')

    if not ip:
        return jsonify({"status": "error", "message": "IP address is required"}), 400
    
    # convert 
    domain = convert_ip_to_domain(ip)        # 예: ec2-15-165-170-99.ap-northeast-2.compute.amazonaws.com.
    check_ip = convert_domain_to_ip(domain)  # 다시 IP로 확인

    domain = domain.rstrip('.') if domain else "unknown"          # 여기서 마침표 제거가 맞음!

    # Nmap 실행
    # nmap_result = run_nmap(ip)
    
    #if nmap_result["status"] == "success":
    #    parsed_nmap_result = parse_nmap_output(
    #        nmap_output=nmap_result["output"],
    #        command=nmap_result["command"],
    #        tool_id=1
    #    )
    #else:
    #    parsed_nmap_result = []
    

    # s3scanner 실행 
    # bucket_name = "hwanghyekying"
    # s3scanner_raw_result = run_s3scanner(bucket_name)
    # s3scanner_parsed_result, s3scanner_sensitive_files = parse_s3scanner_output(
    #    log_text=s3scanner_raw_result["output"],
    #    tool_id=7,
    #    command=s3scanner_raw_result["command"],  
    #    start_time=s3scanner_raw_result["start_time"],
    #    end_time=s3scanner_raw_result["end_time"]
    #)

    # 도구 실행
    # amass_output, top_domain, command, start_time, end_time = run_amass(
    #    domain=domain,
    #    keyword=keyword
    #)

    # 파싱
    # parsed_amass = parse_amass_output(
    #    filtered_lines=amass_output,
    #    tool_id=1,
    #    target=top_domain,
    #    command=command,
    #    start_time=start_time,
    #    end_time=end_time
    #)


    # nuclei 실행
    target_url = f"http://yourdata.sskyroute.com"
    template_path = "/home/skyroute/nuclei-templates/dns/detect-dangling-s3.yaml"

    nuclei_result = run_nuclei(target_url, template_path)
    parsed_nuclei_result = parse_nuclei_output(nuclei_result["output"], nuclei_result)

   

    # enumerate_iam 실행 
    # access_key = "A"
    # secret_key = ""
    # enumerate_iam_raw_result = run_enumerate_iam(access_key, secret_key)

    # if enumerate_iam_raw_result["status"] == "success":
    #    parsed_iam_result = parse_enumerate_iam_output(
    #        file_path=enumerate_iam_raw_result["output_file"],  # 파일 기반 파싱
    #        tool_id=7,
    #        command=enumerate_iam_raw_result["command"],
    #        start_time=enumerate_iam_raw_result["start_time"],
    #        end_time=enumerate_iam_raw_result["end_time"]
    #    )
        
        # 파싱 끝났으면 log 파일 삭제
    #    try:
    #        os.remove(enumerate_iam_raw_result["output_file"])
    #    except Exception as e:
    #        print(f"[WARN] 로그 파일 삭제 실패: {enumerate_iam_raw_result['output_file']} ({e})")
    #else:
    #    parsed_iam_result = []
    

    # cloud_enum 실행
    # keyword = "sskyroute"

    # cloud_enum_result = run_cloud_enum(keyword)

    # if cloud_enum_result["status"] == "success":
    #    parsed_main, parsed_files = parse_cloud_enum_output(
    #        output_file_path=cloud_enum_result["output_file"],
    #        keyword_command=cloud_enum_result["command"],
    #        start_time=cloud_enum_result["start_time"],
    #        end_time=cloud_enum_result["end_time"]
    #    )
    #else:
    #    parsed_main, parsed_files = [], []

    return jsonify({
        # ip <-> 도메인 변환 확인
        "domain": domain,
        "ip": check_ip,
        "original_ip": ip,

        # nmap 결과 표시 
        # "raw_nmap_result": nmap_result["output"], 
        # "parsed_nmap_result": parsed_nmap_result

        # amass 결과 표시 
        # "parsed_amass_results": parsed_amass,
        # "raw_amass_result": amass_output

        # enumerate-iam 결과 표시 
        # "parsed_enumerate_iam_result": parsed_iam_result,
        # "log_file_path": enumerate_iam_raw_result["output_file"]
        
        # s3scanner 결과 표시 
        # "raw_s3scanner_result": s3scanner_raw_result,
        # "parsed_s3scanner_result": s3scanner_parsed_result,
        # "parsed_s3scanner_sensitive_files": s3scanner_sensitive_files

        # cloud_enum 결과 표시 
        # "cloudEnumScanResult": parsed_main,
        # "cloudEnumDiscoveredFile": parsed_files,
        # "raw_cloud_enum_result_file": cloud_enum_result["output_file"],  # ✅ 수정: 파일 경로를 반환
        # "status": cloud_enum_result["status"]

        # nulcei 결과 표시 
        "nuclei_result": parsed_nuclei_result,
        "raw_nuclei_result": nuclei_result
        # "enumerate_result": enumerate_iam_result
        # "cloue_enum_result": cloud_enum_result
    })
    

