import subprocess
import os
from datetime import datetime

def run_nmap_port_scan(ip_address: str) -> dict:
    command = ["/usr/bin/nmap", "-Pn", "-sV", ip_address]

    env = os.environ.copy()
    env["HOME"] = "/home/skyroute"
    env["PATH"] += ":/usr/share/nmap/scripts"

    start_time = datetime.now()

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        end_time = datetime.now()

        return {
            "status": "success",
            "command": ' '.join(command),
            "output": result.stdout,
            "start_time": start_time,
            "end_time": end_time
        }
    except subprocess.CalledProcessError as e:
        end_time = datetime.now()
        return {
            "status": "error",
            "command": ' '.join(command),
            "output": e.output,
            "start_time": start_time,
            "end_time": end_time
        }