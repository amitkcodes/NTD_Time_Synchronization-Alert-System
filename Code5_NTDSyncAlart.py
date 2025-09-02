import socket
import threading
import datetime
import struct
import time
import os
import csv
import requests
import logging

# Configure logging to output messages with timestamps and severity levels.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Config:
    # Configuration for NTP server and NTD IPs.
    NTP_SERVER = "192.168.251.32"
    NTD_IPS = {
        "172.16.26.10": "Testing in Room No. 31",
        "172.16.26.14": "Inside NTDs main_Gate",
        "172.16.26.3": "Outside NTDs main_Gate",
        "172.16.26.9": "Outside head IST",
        "172.16.26.12": "Electrical_section",
        "172.16.26.16": "Reception of auditorium",
        "172.16.26.17": "Inside NTDs auditorium",
        "172.16.26.7": "Conference room metrology"
    }
    
    # File paths for logging synchronization results and SMS alerts.
    LOG_FILE = r"C:\Users\acer\Desktop\AMITY\NPL CODES\logs\NTDs_Display_synchronization_log.csv"
    ALERT_LOG = r"C:\Users\acer\Desktop\AMITY\NPL CODES\logs\NTDs_SMSAlart_log.csv"
    
    # Other configuration settings.
    BIAS = 0
    SYNC_INTERVAL = 1800  # Sync every 30 minutes.
    TCP_TIMEOUT = 10  # Timeout for TCP connections.
    
    # SMS Chef API configuration.
    API_SECRET = "c59a9a09acd020a020f906e33903901446462dec"
    DEVICE_ID = "00000000-0000-0000-b537-d050d47dc40a"
    PHONES = ['+919520010920']  # List of phone numbers to receive alerts.
    
    CHECK_INTERVAL = 3600  # Check synchronization status every hour.
    ALERT_WINDOW = (10, 18)  # Send alerts only between 10 AM and 6 PM.

def get_ntp_time(server):
    """Fetch time from NTP server with retries."""
    for attempt in range(3):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5)  # Set a timeout for the socket operation.
        try:
            ntp_packet = b"\x1b" + 47 * b"\0"  # NTP request packet.
            client.sendto(ntp_packet, (server, 123))  # Send request to the NTP server.
            response, _ = client.recvfrom(48)  # Receive response from the server.
            unpacked = struct.unpack("!12I", response)  # Unpack the response.
            ntp_time = unpacked[10] + unpacked[11] / (2 ** 32)  # Calculate NTP time in Unix format.
            return ntp_time - 2208988800  # Convert NTP time to Unix time (subtract NTP epoch).
        except Exception as e:
            logging.error(f"Attempt {attempt+1} failed: {e}")  # Log any errors encountered during the attempt.
            time.sleep(2)  # Wait before retrying.
        finally:
            client.close()  # Ensure the socket is closed after use.
    return None

def create_time_payload(timestamp):
    """Create NTD-compatible time packet."""
    ntp_date = datetime.datetime.fromtimestamp(timestamp)  # Convert timestamp to datetime object.
    
    return (
        b"\x55\xaa\x00\x00\x01\x01\x00\xc1\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x0f\x00\x10\x00\x00\x00\x00\x00\x00\x00"
        + ntp_date.year.to_bytes(2, "little")   # Year in little-endian format.
        + bytes([ntp_date.month, ntp_date.day, ntp_date.hour,
                 ntp_date.minute, ntp_date.second])   # Month, day, hour, minute, second as bytes.
        + b"\x00\x00\x0d\x0a"   # End of packet marker.
    )

def log_sync_result(ip, status):
    """Log synchronization attempts."""
    log_dir = os.path.dirname(Config.LOG_FILE)   # Get directory of log file.
    os.makedirs(log_dir, exist_ok=True)   # Create directory if it doesn't exist.

    local_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')   # Get current timestamp.

    with open(Config.LOG_FILE, "a", newline="") as f:   # Open log file in append mode.
        writer = csv.writer(f)
        writer.writerow([
            local_time,
            ip,
            status,
            Config.BIAS,
            Config.NTD_IPS.get(ip, "Unknown")   # Get location description from IP mapping.
        ])

def sync_ntd(ip, payload):
    """Handle single NTD synchronization."""
    location = Config.NTD_IPS.get(ip, "Unknown")   # Get location based on IP address.
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(Config.TCP_TIMEOUT)   # Set timeout for TCP connection.
            s.connect((ip, 10000))   # Connect to the NTD at port 10000.
            s.sendall(payload)   # Send the time payload to the NTD.
            response = s.recv(1024)   # Receive response from the NTD (not used here).
            log_sync_result(ip, "Synchronized")   # Log successful synchronization.
            logging.info(f"{location}: Synchronized successful")   # Log success message to console.

    except Exception as e:
        error_msg = f"Not Synchronized: {str(e)}"   # Prepare error message on failure.
        log_sync_result(ip, error_msg)   # Log synchronization failure result.
        logging.error(f"{location}: {error_msg}")   # Log error message to console.

def log_alert(timestamp, phone, ip, location, status):
    """Record SMS alert attempts."""
    with open(Config.ALERT_LOG, 'a', newline='') as f:   # Open alert log file in append mode.
        writer = csv.writer(f)
        writer.writerow([timestamp, phone, ip, location, status])   # Write alert details to log.

def send_alert(ip, location):
    """Send SMS via smschef API."""
    current_hour = datetime.datetime.now().hour
    if not (Config.ALERT_WINDOW[0] <= current_hour < Config.ALERT_WINDOW[1]):
        logging.info(f"Alert suppressed for {ip} (outside hours)")   # Suppress alerts outside active hours.
        return

    message = f"Alert! {location} (IP: {ip}) is Not Synchronized."   # Prepare alert message.

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
                result = response.json()   # Parse JSON response from SMS Chef API.
                status_response = result.get('status', 'failed')   # Get status from response.
                message_response = result.get('message', '').lower()   # Get message from response.

                if status_response == 'success' or 'queued' in message_response:   # Treat queued or success as successful submission
                    status_message = "SMS queued for sending" if 'queued' in message_response else "SMS sent successfully"
                    break  # Exit retry loop immediately
                else:
                    status_message = f"SMS failed: {message_response}"   # Prepare failure message if not successful
                    retries -= 1
                    time.sleep(2)  # Retry delay

            except Exception as e:
                status_message = f"error: {str(e)}"   # Capture any exceptions that occur during sending
                retries -= 1

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
        log_alert(timestamp, phone, ip, location, status_message)  # Log meaningful status
        logging.info(f"SMS to {phone}: {status_message}")   # Log SMS sending status to console

def check_sync_status():
    """Monitor synchronization logs and send deduplicated alerts."""
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=1)
    already_alerted_ips = set()   # Set to keep track of alerted IPs

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

                        if ip in already_alerted_ips:  
                            continue  

                        send_alert(ip, location)   
                        already_alerted_ips.add(ip) 

                except ValueError as e:
                    logging.error(f"Invalid timestamp in row {i}: {e}") 
                except Exception as e:
                    logging.error(f"Error processing row {i}: {e}")
    
    except FileNotFoundError:
        logging.error(f"Log file missing: {Config.LOG_FILE}")

def sync_all_and_alert():
    """Combine sync and alert checks."""
    while True:
        logging.info("--- Starting synchronization cycle ---")
        ntp_time = get_ntp_time(Config.NTP_SERVER)

        if ntp_time:
            payload = create_time_payload(ntp_time)
            for ip in Config.NTD_IPS:
                threading.Thread(target=sync_ntd, args=(ip, payload)).start()

        logging.info("Checking synchronization status for alerts...")
        check_sync_status()

        time.sleep(Config.SYNC_INTERVAL)

if __name__ == "__main__":
    sync_all_and_alert()
