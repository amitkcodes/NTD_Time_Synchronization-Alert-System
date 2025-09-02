import socket
import threading
import datetime
import struct
import time
import os
import csv

class Config:
    NTP_SERVER = "192.168.251.32"
    NTD_IPS = {
        "172.16.26.10": "Testing in Room No. 31",
        "172.16.26.7": "Conference room metrology"
    }
    LOG_FILE = r"C:\Users\acer\Desktop\AMITY\NPL CODES\logs\NTDs_Display_synchronization_log.csv"
    BIAS = 0
    SYNC_INTERVAL = 1800  # 30 minutes
    TCP_TIMEOUT = 10

def get_ntp_time(server):
    """Fetch time from NTP server with retries."""
    for attempt in range(3):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5)
        try:
            ntp_packet = b"\x1b" + 47 * b"\0"
            client.sendto(ntp_packet, (server, 123))
            response, _ = client.recvfrom(48)
            unpacked = struct.unpack("!12I", response)
            ntp_time = unpacked[10] + unpacked[11] / (2 ** 32)
            return ntp_time - 2208988800  # NTP to Unix
        except Exception as e:
            print(f"Attempt {attempt+1} failed: {e}")
            time.sleep(2)
        finally:
            client.close()
    return None

def create_time_payload(timestamp):
    """Create NTD-compatible time packet."""
    ntp_date = datetime.datetime.fromtimestamp(timestamp)
    return (
        b"\x55\xaa\x00\x00\x01\x01\x00\xc1\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x0f\x00\x10\x00\x00\x00\x00\x00\x00\x00"
        + ntp_date.year.to_bytes(2, "little")
        + bytes([ntp_date.month, ntp_date.day, ntp_date.hour,
                 ntp_date.minute, ntp_date.second])
        + b"\x00\x00\x0d\x0a"
    )

def log_sync_result(ip, status):
    """Log synchronization attempts."""
    log_dir = os.path.dirname(Config.LOG_FILE)
    os.makedirs(log_dir, exist_ok=True)

    local_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    
    with open(Config.LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            local_time,
            ip,
            status,
            Config.BIAS,
            Config.NTD_IPS.get(ip, "Unknown")
        ])

def sync_ntd(ip, payload):
    """Handle single NTD synchronization."""
    location = Config.NTD_IPS.get(ip, "Unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(Config.TCP_TIMEOUT)
            s.connect((ip, 10000))
            s.sendall(payload)
            response = s.recv(1024)
            log_sync_result(ip, "Synchronized")
            print(f"{location}: Sync successful")
    except Exception as e:
        error_msg = f"Not Synchronized: {str(e)}"
        log_sync_result(ip, error_msg)
        print(f"{location}: {error_msg}")

def sync_all():
    """Main synchronization routine."""
    while True:
        print("\n--- Starting synchronization cycle ---")
        ntp_time = get_ntp_time(Config.NTP_SERVER)

        if ntp_time:
            payload = create_time_payload(ntp_time)
            for ip in Config.NTD_IPS.keys():
                threading.Thread(target=sync_ntd, args=(ip, payload)).start()

        time.sleep(Config.SYNC_INTERVAL)

if __name__ == "__main__":
    sync_all()
