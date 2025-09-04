#Team NPL Amit Kaushik,Divya Singh Yadav,Dr.Deepak Sharma,Dr. Ashish Agrawal,Dr. Subhasis Panja
import socket
import threading
import datetime
import struct
import time
import os
import csv
import logging
import smtplib
from email.mime.text import MIMEText

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Config:
    """
    A class to store configuration settings for the NTD synchronization process.
    """
    # Multiple NTP servers (Local + Public fallback)
    LOCAL_NTP_SERVERS = [
        "192.168.251.32",
        "192.168.251.33",
        "192.168.251.38",
        "192.168.251.39"
    ]
    PUBLIC_NTP_SERVERS = [
        "time.google.com",
        "pool.ntp.org",
        "time.windows.com"
    ]

    NTD_IPS = {
       # "172.16.26.14": "Outside NTDs main_Gate",
        "172.16.26.10": "Library",
        "172.16.26.9": "Outside head IST",
        "172.16.26.12": "Electrical_section",
        "172.16.26.16": "Reception of auditorium",
        "172.16.26.17": "Inside NTDs auditorium"
    }

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    LOG_FILE = os.path.join(LOG_DIR, 'NTDs_Display_synchronization_log.csv')
    ALERT_LOG = os.path.join(LOG_DIR, 'NTDs_EmailAlert_log.csv')

    BIAS = 0
    SYNC_INTERVAL = 300
    TCP_TIMEOUT = 10

    EMAIL = "amitnplindia21@gmail.com"
    PASSWORD = "ctmweznzewgtypup"  # App-specific password
    EMAIL_RECIPIENTS = ['amitnplindia21@gmail.com','divyaforself@gmail.com']
    CHECK_INTERVAL = 600
    ALERT_WINDOW = (9, 18)

last_sync_time = {}
last_alert_time = {}

# ---------------- NTP TIME FUNCTIONS ---------------- #
def try_servers(servers):
    """Try a list of NTP servers until one responds."""
    for server in servers:
        for attempt in range(3):
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(5)
            try:
                ntp_packet = b"\x1b" + 47 * b"\0"
                client.sendto(ntp_packet, (server, 123))
                response, _ = client.recvfrom(48)
                unpacked = struct.unpack("!12I", response)
                ntp_time = unpacked[10] + unpacked[11] / (2 ** 32)
                logging.info(f"✅ Time received from {server}")
                return ntp_time - 2208988800
            except Exception as e:
                logging.error(f"❌ {server} attempt {attempt+1} failed: {e}")
                time.sleep(2)
            finally:
                client.close()
    return None

def get_ntp_time():
    """Try local servers first, then public servers."""
    logging.info("🌐 Trying LOCAL NTP servers...")
    ntp_time = try_servers(Config.LOCAL_NTP_SERVERS)
    if ntp_time:
        return ntp_time

    logging.warning("⚠️ Local servers failed, trying PUBLIC servers...")
    ntp_time = try_servers(Config.PUBLIC_NTP_SERVERS)
    if ntp_time:
        return ntp_time

    logging.critical("🚨 All LOCAL & PUBLIC NTP servers failed!")
    send_alert_general("All NTP servers (local + public) are unreachable!")
    return None

# ---------------- NTD SYNC FUNCTIONS ---------------- #
def create_time_payload(timestamp):
    ntp_date = datetime.datetime.fromtimestamp(timestamp)
    return (
        b"\x55\xaa\x00\x00\x01\x01\x00\xc1\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x0f\x00\x10\x00\x00\x00\x00\x00\x00\x00"
        + ntp_date.year.to_bytes(2, "little")
        + bytes([ntp_date.month, ntp_date.day, ntp_date.hour,
                 ntp_date.minute, ntp_date.second])
        + b"\x00\x00\x0d\x0a"
    )

def log_sync_result(ip, status):
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    local_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    with open(Config.LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([local_time, ip, status, Config.BIAS, Config.NTD_IPS.get(ip, "Unknown")])

def sync_ntd(ip, payload):
    location = Config.NTD_IPS.get(ip, "Unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(Config.TCP_TIMEOUT)
            s.connect((ip, 10000))
            s.sendall(payload)
            response = s.recv(1024)
            log_sync_result(ip, "Synchronized")
            logging.info(f"{location}: Synchronized successful")
            last_sync_time[ip] = datetime.datetime.now()
    except Exception as e:
        error_msg = f"Not Synchronized: {str(e)}"
        log_sync_result(ip, error_msg)
        logging.error(f"{location}: {error_msg}")

# ---------------- ALERT FUNCTIONS ---------------- #
def log_alert(timestamp, email, ip, location, status):
    with open(Config.ALERT_LOG, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, email, ip, location, status])

def send_alert(ip, location):
    current_hour = datetime.datetime.now().hour
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not (Config.ALERT_WINDOW[0] <= current_hour < Config.ALERT_WINDOW[1]):
        status_message = "Alert suppressed (outside active hours)"
        log_alert(timestamp, Config.EMAIL_RECIPIENTS[0], ip, location, status_message)
        logging.info(f"Alert suppressed for {ip} (outside hours)")
        return

    current_time = datetime.datetime.now()
    if ip in last_alert_time and (current_time - last_alert_time[ip]).total_seconds() < 3600:
        logging.info(f"Alert skipped for {ip}: Within 1-hour cooldown")
        return

    message = f"Alert! {location} (IP: {ip}) is Not Synchronized.\nTime: {timestamp}"

    for email in Config.EMAIL_RECIPIENTS:
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(Config.EMAIL, Config.PASSWORD)
                msg = MIMEText(message)
                msg['Subject'] = 'NTD Synchronization Alert'
                msg['From'] = Config.EMAIL
                msg['To'] = email
                server.send_message(msg)
            status_message = f"Email sent successfully to {email}"
            last_alert_time[ip] = current_time
        except Exception as e:
            status_message = f"error: Failed to send email: {str(e)}"

        log_alert(timestamp, email, ip, location, status_message)
        logging.info(f"Email to {email}: {status_message}")

def send_alert_general(message):
    """Send a general alert when all servers fail."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for email in Config.EMAIL_RECIPIENTS:
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(Config.EMAIL, Config.PASSWORD)
                msg = MIMEText(message)
                msg['Subject'] = 'General NTP Alert'
                msg['From'] = Config.EMAIL
                msg['To'] = email
                server.send_message(msg)
            logging.info(f"📧 General alert email sent to {email}")
        except Exception as e:
            logging.error(f"❌ Failed to send general email to {email}: {e}")

# ---------------- MONITORING ---------------- #
def check_sync_status():
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=1)
    try:
        with open(Config.LOG_FILE, 'r') as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if len(row) < 5:
                    continue
                try:
                    log_time = datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f')
                    ip = row[1]
                    if log_time > cutoff and "Not Synchronized" in row[2]:
                        location = row[4]
                        current_time = datetime.datetime.now()
                        if ip in last_alert_time and (current_time - last_alert_time[ip]).total_seconds() < 3600:
                            continue
                        send_alert(ip, location)
                        last_alert_time[ip] = current_time
                except ValueError as e:
                    logging.error(f"Invalid timestamp in row {i}: {e}")
                except Exception as e:
                    logging.error(f"Error processing row {i}: {e}")
    except FileNotFoundError:
        logging.error(f"Log file missing: {Config.LOG_FILE}")

# ---------------- MAIN LOOP ---------------- #
def sync_all_and_alert():
    while True:
        logging.info("--- Starting synchronization cycle ---")
        ntp_time = get_ntp_time()
        if ntp_time:
            payload = create_time_payload(ntp_time)
            for ip in Config.NTD_IPS:
                threading.Thread(target=sync_ntd, args=(ip, payload)).start()
        logging.info("Checking synchronization status for alerts...")
        check_sync_status()
        time.sleep(Config.SYNC_INTERVAL)

if __name__ == "__main__":
    sync_all_and_alert()
