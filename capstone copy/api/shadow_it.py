from flask import Blueprint, jsonify
import mysql.connector

shadowit_bp = Blueprint("shadowit_bp", __name__)

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )

@shadowit_bp.route('/api/scan/<int:scan_id>/shadowit', methods=['GET'])
def get_shadowit(scan_id):
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        # 결과 조회
        cursor.execute("""
            SELECT port, actual_service, expected_service, reason
            FROM ShadowNetwork
            WHERE scan_result_id = %s
        """, (scan_id,))
        shadow_net = cursor.fetchall()

        cursor.execute("""
            SELECT bucket_name, allusers_permission, authusers_permission, reason
            FROM ShadowResource
            WHERE scan_result_id = %s
        """, (scan_id,))
        shadow_res = cursor.fetchall()

        result = {
            "status": "success",
            "found": []
        }

        # 결과가 비어 있으면 탐지된 Shadow IT 없음
        if not shadow_net and not shadow_res:
            return jsonify(result)  # found = [], status = success

        # 결과 구성
        for row in shadow_net:
            result["found"].append(
                f"Shadow Network 발견\n포트: {row['port']}\n실제 서비스: {row['actual_service']}\n예상 서비스: {row['expected_service']}"
            )

        for row in shadow_res:
            perms = []
            if row["allusers_permission"]:
                perms.append(f"AllUsers: {row['allusers_permission']}")
            if row["authusers_permission"]:
                perms.append(f"AuthUsers: {row['authusers_permission']}")
            perm_str = "; ".join(perms)
            result["found"].append(
                f"Shadow Resource 발견\n이름: {row['bucket_name']}\n권한: {perm_str}" if perms
                else f"Shadow Resource 발견\n이름: {row['bucket_name']}\n권한: Private"
            )

        return jsonify(result)

    except Exception as e:
        print("[SHADOWIT ERROR]", e)  # ❗ 꼭 찍어보기
        return jsonify({"status": "fail", "error": str(e), "found": []}), 500
    finally:
        cursor.close()
        conn.close()