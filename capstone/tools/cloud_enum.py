import subprocess

def run_cloud_enum(ip):
    """
    Parameters:
    ip (str): 분석할 IP 주소
    
    Returns:
    dict: Cloud-Enum 결과를 포함한 딕셔너리
    """
    command = ["cloud-enum", "--provider", "aws", "--access-key, access_key, "--secret-key", secret_key]
    result = subprocess.run(command, capture_output=True, text=True)

    """
    command = ["cloud-enum", "--provider", "aws", "--enumerate", "ec2"]
    command = ["cloud-enum", "--provider", "aws", "--enumerate", "s3"]

    """ 
    if result.returncode == 0:
        return {
            "tool": "cloud_enum",
            "output": result.stdout,
            "status": "success"
        }
    else:
        return {
            "tool": "cloud_enum",
            "output": result.stderr,
            "status": "error"
        }
