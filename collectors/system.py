import platform
import socket
import getpass
import psutil

def collect_system_info():
    return {
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "operating_system": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": psutil.cpu_count(),
        "memory_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
        "boot_time": psutil.boot_time(),
    }