import mysql.connector
import csv

def parse_domain_file(file_path: str) -> int:
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()
    file_id = None

    try:
        cursor.execute("DELETE FROM DomainList")

        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            try:
                next(reader)
            except StopIteration:
                return 0

            for row in reader:
                domain = row[0].strip()
                cursor.execute("INSERT INTO DomainList (domain) VALUES (%s)", (domain,))
                file_id = cursor.lastrowid

        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.close()

    return file_id or 0

def parse_port_file(file_path: str) -> int:
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()
    file_id = None

    try:
        cursor.execute("DELETE FROM PortList")

        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            try:
                next(reader)
            except StopIteration:
                return 0

            for row in reader:
                port = int(row[0].strip())
                service = row[1].strip()
                cursor.execute(
                    "INSERT INTO PortList (port, service) VALUES (%s, %s)",
                    (port, service)
                )
                file_id = cursor.lastrowid

        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.close()

    return file_id or 0

def parse_s3_file(file_path: str) -> int:
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()
    file_id = None

    try:
        cursor.execute("DELETE FROM S3List")

        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            try:
                next(reader)
            except StopIteration:
                return 0

            for row in reader:
                bucket_name = row[0].strip()
                is_public = 1 if row[1].strip().upper() == "TRUE" else 0
                cursor.execute(
                    "INSERT INTO S3List (s3_bucket, public) VALUES (%s, %s)",
                    (bucket_name, is_public)
                )
                file_id = cursor.lastrowid

        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.close()

    return file_id or 0