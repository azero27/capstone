import subprocess

def run_enumerate_iam(ip, access_key, secret_key):
    """
   
    Parameters:
    ip (str): 분석할 IP 주소
    access_key (str): AWS 접근 키
    secret_key (str): AWS 비밀 키
    
 
    """
    command = ["enumerate-iam", "--access-key", access_key, "--secret-key", secret_key, "--target", ip]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        return {
            "tool": "enumerate_iam",
            "output": result.stdout,
            "status": "success"
        }
    else:
        return {
            "tool": "enumerate_iam",
            "output": result.stderr,
            "status": "error"
        }
