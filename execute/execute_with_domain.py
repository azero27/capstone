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

def execute_with_address():

    # Nmap 실행
    nmap_result = run_nmap(ip)
    
    if nmap_result["status"] == "success":
        parsed_nmap_result = parse_nmap_output(
            nmap_output=nmap_result["output"],
            command=nmap_result["command"],
            tool_id=1
        )
    else:
        parsed_nmap_result = []
    

    # amass 실행
    amass_output, top_domain, command, start_time, end_time = run_amass(
        domain=domain,
        keyword=keyword
    )

    parsed_amass = parse_amass_output(
        filtered_lines=amass_output,
        tool_id=1,
        target=top_domain,
        command=command,
        start_time=start_time,
        end_time=end_time
    )


    # nuclei 실행
    target_url = f"http://yourdata.sskyroute.com"
    template_path = "/home/skyroute/nuclei-templates/dns/detect-dangling-s3.yaml"

    nuclei_result = run_nuclei(target_url, template_path)
    parsed_nuclei_result = parse_nuclei_output(nuclei_result["output"], nuclei_result)


    return jsonify({
    
        # nmap 결과 표시 
        "raw_nmap_result": nmap_result["output"], 
        "parsed_nmap_result": parsed_nmap_result,

        # amass 결과 표시 
        "parsed_amass_results": parsed_amass,
        "raw_amass_result": amass_output,

        # nulcei 결과 표시 
        "nuclei_result": parsed_nuclei_result,
        "raw_nuclei_result": nuclei_result
        # "enumerate_result": enumerate_iam_result
        # "cloue_enum_result": cloud_enum_result
    })
    


