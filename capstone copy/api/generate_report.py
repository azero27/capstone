# api/generate_report.py

from flask import Blueprint, request, jsonify
from utils.pdf_generator import generate_pdf_report
from DB.load_report_data import load_report_data_from_db
import os
from datetime import datetime
import mysql.connector

generate_report_bp = Blueprint('generate_report', __name__)

@generate_report_bp.route('/api/generate_report', methods=['POST'])
def generate_report():
    try:
        data = request.get_json()

        # 날짜와 리소스 타입 파싱
        start_date = data.get("start_date")
        end_date = data.get("end_date")
        resource_types = data.get("resources", [])  # ["port", "domain", "s3"]

        if not start_date or not end_date or not resource_types:
            return jsonify({"status": "fail", "message": "날짜나 리소스가 누락되었습니다."}), 400

        # 스캔 결과 ID 리스트 찾기 (시간 필터 기반)
        conn = mysql.connector.connect(
            host="localhost", user="DBA", password="1234", database="SKYROUTE"
        )
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id FROM ScanResult
            WHERE start_time BETWEEN %s AND %s
        """, (start_date, end_date))
        scan_result_ids = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()

        if not scan_result_ids:
            return jsonify({"status": "fail", "message": "해당 기간 내 스캔 결과가 없습니다."}), 404

        # 데이터 불러오기
        report_data = load_report_data_from_db(
            scan_result_ids=scan_result_ids,
            start_time=start_date,
            end_time=end_date,
            resource_types=resource_types
        )

        # 저장 경로 설정
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        save_path = os.path.join("static", "reports", filename)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        # PDF 생성
        generate_pdf_report(report_data, save_path)

        # 반환
        return jsonify({
            "status": "ok",
            "pdf_url": f"/static/reports/{filename}"
        })

    except Exception as e:
        print("[ERROR] PDF 생성 실패:", e)
        return jsonify({"status": "fail", "message": str(e)}), 500
