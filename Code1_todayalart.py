import requests
import time
import csv
from datetime import datetime, timedelta

class AlertConfig:
    API_SECRET = "c59a9a09acd020a020f906e33903901446462dec"
    DEVICE_ID = "00000000-0000-0000-b537-d050d47dc40a"
    PHONES = ['+919520010920']
    SYNC_LOG = r"C:\Users\acer\Desktop\AMITY\NPL CODES\logs\NTDs_Display_synchronization_log.csv"
    ALERT_LOG = r"C:\Users\acer\Desktop\AMITY\NPL CODES\logs\NTDs_SMSAlart_log.csv"
    CHECK_INTERVAL = 3600  # 1 hour
    ALERT_WINDOW = (10, 18)  # 10AM-6PM

def log_alert(timestamp, phone, ip, location, status):
    """Record SMS alert attempts."""
    with open(AlertConfig.ALERT_LOG, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, phone, ip, location, status])

def send_alert(ip, location):
    """Send SMS via smschef API."""
    current_hour = datetime.now().hour
    if not (AlertConfig.ALERT_WINDOW[0] <= current_hour < AlertConfig.ALERT_WINDOW[1]):
        print(f"Alert suppressed for {ip} (outside hours)")
        return

    message = f"Alert! {location} (IP: {ip}) is Not Synchronized."

    for phone in AlertConfig.PHONES:
        retries = 1
        while retries > 0:
            try:
                response = requests.post(
                    "https://www.cloud.smschef.com/api/send/sms",
                    params={
                        "secret": AlertConfig.API_SECRET,
                        "mode": "devices",
                        "device": AlertConfig.DEVICE_ID,
                        "sim": 1,
                        "priority": 1,
                        "phone": phone,
                        "message": message
                    },
                    timeout=10
                )
                result = response.json()
                
                # Get both status and message from response
                status = result.get('status', 'failed')
                msg = result.get('message', 'No message').lower()
                
                # Handle SMS Chef's queued response
                if status == 'success' or 'queued' in msg:
                    status_message = "SMS queued for sending"
                    retries = 0  # Exit retry loop immediately
                else:
                    status_message = f"SMS failed: {msg}"
                    retries -= 1
                    time.sleep(2)

            except Exception as e:
                status_message = f"error: {str(e)}"
                retries -= 1

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_alert(timestamp, phone, ip, location, status_message)
        print(f"SMS to {phone}: {status_message}")

def check_sync_status():
    """Monitor synchronization logs and send deduplicated alerts."""
    cutoff = datetime.now() - timedelta(hours=1)
    already_alerted_ips = set()

    try:
        with open(AlertConfig.SYNC_LOG, 'r') as f:
            for row in csv.reader(f):
                if len(row) < 5:  # Ensure at least 5 columns exist (Timestamp, IP, Status, Bias, Location)
                    continue
                
                try:
                    log_time = datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f')
                    if log_time > cutoff and "Not Synchronized" in row[2]:
                        ip = row[1]
                        location = row[4]  # Corrected index for Location

                        if ip in already_alerted_ips:  # Skip duplicate alerts for the same IP
                            continue

                        send_alert(ip, location)
                        already_alerted_ips.add(ip)

                except ValueError as e:
                    print(f"Invalid timestamp {row[0]}: {e}")
    except FileNotFoundError:
        print(f"Log file missing: {AlertConfig.SYNC_LOG}")

if __name__ == "__main__":
    while True:
        print("\nChecking synchronization status...")
        check_sync_status()
        time.sleep(AlertConfig.CHECK_INTERVAL)
