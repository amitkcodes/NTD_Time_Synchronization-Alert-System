import socket
import threading
import datetime
import struct
import time
import os
import csv
import requests

class Config:
    NTP_SERVER = "192.168.251.33"
    NTD_IPS = {
        "172.16.26.10": "Testing in Room No. 31",
        "172.16.26.7": "Conference room metrology"
    }
    LOG_FILE = r"C:\Users\acer\Desktop\AMITY\NPL CODES\logs\NTDs_Display_synchronization_log.csv"
    BIAS = 0
    SYNC_INTERVAL = 1800  # 30 minutes
    TCP_TIMEOUT = 10

    API_SECRET = "c59a9a09acd020a020f906e33903901446462dec"
    DEVICE_ID = "00000000-0000-0000-b537-d050d47dc40a"
    PHONES = ['+919520010920']
    ALERT_LOG = r"C:\Users\acer\Desktop\AMITY\NPL CODES\logs\NTDs_SMSAlart_log.csv"
    CHECK_INTERVAL = 3600  # 1 hour
    ALERT_WINDOW = (10, 18)  # 10AM-6PM


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


def log_alert(timestamp, phone, ip, location, status):
    """Record SMS alert attempts."""
    with open(Config.ALERT_LOG, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, phone, ip, location, status])


def send_alert(ip, location):
    """Send SMS via smschef API."""
    current_hour = datetime.datetime.now().hour
    if not (Config.ALERT_WINDOW[0] <= current_hour < Config.ALERT_WINDOW[1]):
        print(f"Alert suppressed for {ip} (outside hours)")
        return

    message = f"Alert! {location} (IP: {ip}) is Not Synchronized."

    for phone in Config.PHONES:
        retries = 1
        while retries > 0:
            try:
                response = requests.post(
                    "https://www.cloud.smschef.com/api/send/sms",
                    params={
                        "secret": Config.API_SECRET,
                        "mode": "devices",
                        "device": Config.DEVICE_ID,
                        "sim": 1,
                        "priority": 1,
                        "phone": phone,
                        "message": message
                    },
                    timeout=10
                )
                result = response.json()
                status_response = result.get('status', 'failed')
                message_response = result.get('message', '').lower()

                # Treat 'queued' or 'success' as successful submission
                if status_response == 'success' or 'queued' in message_response:
                    status_message = "SMS queued for sending" if 'queued' in message_response else "SMS sent successfully"
                    retries = 0  # Exit retry loop immediately
                else:
                    status_message = f"SMS failed: {message_response}"
                    retries -= 1
                    time.sleep(2)  # Retry delay

            except Exception as e:
                status_message = f"error: {str(e)}"
                retries -= 1

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_alert(timestamp, phone, ip, location, status_message)  # Log meaningful status
        print(f"SMS to {phone}: {status_message}")




def check_sync_status():
    """Monitor synchronization logs and send deduplicated alerts."""
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=1)
    already_alerted_ips = set()

    try:
        with open(Config.LOG_FILE, 'r') as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if len(row) < 5:  # Ensure at least enough columns exist (Timestamp, IP, Status...)
                    continue
                
                try:
                    log_time = datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f')
                    ip = row[1]   # Correct index for IP

                    if log_time > cutoff and "Not Synchronized" in row[2]:
                        location = row[4]   # Correct index for Location

                        if ip in already_alerted_ips:  # Skip duplicate alerts for the same IP
                            continue

                        send_alert(ip, location)   # Send alert for unsynchronized IP
                        already_alerted_ips.add(ip) # Mark it as alerted

                except ValueError as e:
                    print(f"Invalid timestamp in row {i}: {e}")
                except Exception as e:
                    print(f"Error processing row {i}: {e}")
    
    except FileNotFoundError:
        print(f"Log file missing: {Config.LOG_FILE}")
    
def sync_all_and_alert():
    """Combine sync and alert checks."""
    while True:
        print("--- Starting synchronization cycle ---")
        ntp_time = get_ntp_time(Config.NTP_SERVER)

        if ntp_time:
            payload = create_time_payload(ntp_time)
            for ip in Config.NTD_IPS:
                threading.Thread(target=sync_ntd, args=(ip, payload)).start()

        print("Checking synchronization status for alerts...")
        check_sync_status()

        time.sleep(Config.SYNC_INTERVAL)

if __name__ == "__main__":
    sync_all_and_alert()
