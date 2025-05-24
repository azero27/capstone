from flask import Flask, request, jsonify, render_template, redirect, url_for
from tools.s3scanner import run_s3scanner  # s3scanner 실행
from parses.parse_s3scanner import parse_s3scanner_output 
import socket
import re
import os

def execute_with_s3(bucket_name):
    
    # s3scanner 실행 
    bucket_name = "hwanghyekying"
    s3scanner_raw_result = run_s3scanner(bucket_name)
    s3scanner_parsed_result, s3scanner_sensitive_files = parse_s3scanner_output(
        log_text=s3scanner_raw_result["output"],
        tool_id=7,
        command=s3scanner_raw_result["command"],  
        start_time=s3scanner_raw_result["start_time"],
        end_time=s3scanner_raw_result["end_time"]
    )

    return jsonify({

        # s3scanner 결과 표시 
        "raw_s3scanner_result": s3scanner_raw_result,
        "parsed_s3scanner_result": s3scanner_parsed_result,
        "parsed_s3scanner_sensitive_files": s3scanner_sensitive_files

    })
    

