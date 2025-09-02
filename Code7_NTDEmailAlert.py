#Team NPL Amit Kaushik,Divya Singh Yadav,Dr.Deepak Sharma,Dr. Ashish Agrawal,Dr. Subhasis Panja
import socket  # Import the socket library for network communication
import threading  # Import the threading library for concurrent execution
import datetime  # Import the datetime library for date and time operations
import struct  # Import the struct library for packing and unpacking binary data
import time  # Import the time library for time-related functions
import os  # Import the os library for operating system-related tasks
import csv  # Import the csv library for working with CSV files
import logging  # Import the logging library for logging messages
import smtplib  # For sending emails via Gmail SMTP
from email.mime.text import MIMEText  # For formatting email messages

# Configure logging to display timestamps, log levels, and messages
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Config:
    """
    A class to store configuration settings for the NTD synchronization process.
    """
    NTP_SERVER = "192.168.251.32"  # The IP address of the NTP server to synchronize with
    NTD_IPS = {  # A dictionary mapping NTD IP addresses to their locations
        # "172.16.26.7": "Conference room metrology",
        # "172.16.26.3": "Inside NTDs main_Gate",
        "172.16.26.14": "Outside NTDs main_Gate",
        "172.16.26.10": "Library",
        "172.16.26.9": "Outside head IST",
        "172.16.26.12": "Electrical_section",
        "172.16.26.16": "Reception of auditorium",
        "172.16.26.17": "Inside NTDs auditorium"
        
    }
    # Dynamically creates log file path relative to script location
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Get the directory where the current script is located
    LOG_DIR = os.path.join(BASE_DIR, 'logs')  # Create a 'logs' directory in the same directory as the script
    LOG_FILE = os.path.join(LOG_DIR, 'NTDs_Display_synchronization_log.csv')  # Synchronization log file path
    ALERT_LOG = os.path.join(LOG_DIR, 'NTDs_EmailAlert_log.csv')  # Email alert log file path

    BIAS = 0  # Time bias (in seconds) to adjust the NTP time
    SYNC_INTERVAL = 300  # Synchronization interval in seconds (5 minutes)
    TCP_TIMEOUT = 10  # Timeout for TCP socket connections in seconds

    EMAIL = "amitnplindia21@gmail.com"  # Gmail address for sending alerts
    PASSWORD = "ctmweznzewgtypup"  # App-specific password for Gmail SMTP
    EMAIL_RECIPIENTS = ['amitnplindia21@gmail.com','divyaforself@gmail.com']  # List of email addresses to send alerts to
    CHECK_INTERVAL = 600  # Interval to check synchronization status in seconds (10 min)
    ALERT_WINDOW = (9, 18)  # Time window (hours) to send email alerts (9 AM to 6 PM)

# Track the last synchronization time for each IP address
last_sync_time = {}
# Track the last alert time for each IP address to avoid duplicate alerts
last_alert_time = {}

def get_ntp_time(server):
    """
    Fetches the current time from an NTP server.

    Args:
        server (str): The IP address or hostname of the NTP server.

    Returns:
        float: The NTP time as a Unix timestamp, or None if the time could not be retrieved.
    """
    for attempt in range(3):  # Retry up to 3 times
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket
        client.settimeout(5)  # Set a timeout of 5 seconds for the socket
        try:
            ntp_packet = b"\x1b" + 47 * b"\0"  # Create an NTP request packet
            client.sendto(ntp_packet, (server, 123))  # Send the NTP request to the server on port 123
            response, _ = client.recvfrom(48)  # Receive the response from the server (48 bytes)
            unpacked = struct.unpack("!12I", response)  # Unpack the response as 12 unsigned integers
            ntp_time = unpacked[10] + unpacked[11] / (2 ** 32)  # Extract the NTP time from the response
            return ntp_time - 2208988800  # Convert NTP time to Unix timestamp (seconds since 1970)
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed: {e}")  # Log the error message
            time.sleep(2)  # Wait for 2 seconds before retrying
        finally:
            client.close()  # Close the socket
    return None  # Return None if all attempts failed

def create_time_payload(timestamp):
    """
    Creates a time payload in a format compatible with NTD devices.

    Args:
        timestamp (float): The Unix timestamp to be converted into the payload.

    Returns:
        bytes: The time payload as a bytes object.
    """
    ntp_date = datetime.datetime.fromtimestamp(timestamp)  # Convert the timestamp to a datetime object
    return (
        b"\x55\xaa\x00\x00\x01\x01\x00\xc1\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x0f\x00\x10\x00\x00\x00\x00\x00\x00\x00"
        + ntp_date.year.to_bytes(2, "little")  # Convert the year to bytes (2 bytes, little-endian)
        + bytes([ntp_date.month, ntp_date.day, ntp_date.hour,
                 ntp_date.minute, ntp_date.second])  # Convert month, day, hour, minute, second to bytes
        + b"\x00\x00\x0d\x0a"  # Add the trailer bytes
    )

def log_sync_result(ip, status):
    """
    Logs the synchronization result to a CSV file.

    Args:
        ip (str): The IP address of the NTD device.
        status (str): The synchronization status message.
    """
    os.makedirs(Config.LOG_DIR, exist_ok=True)  # Create the log directory if it doesn't exist
    local_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')  # Get the current time
    with open(Config.LOG_FILE, "a", newline="") as f:  # Open the log file in append mode
        writer = csv.writer(f)  # Create a CSV writer object
        writer.writerow([  # Write the log entry to the CSV file
            local_time, ip, status, Config.BIAS, Config.NTD_IPS.get(ip, "Unknown")
        ])

def sync_ntd(ip, payload):
    """
    Synchronizes a single NTD device with the given time payload.

    Args:
        ip (str): The IP address of the NTD device.
        payload (bytes): The time payload to send to the NTD device.
    """
    location = Config.NTD_IPS.get(ip, "Unknown")  # Get the location of the NTD device
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # Create a TCP socket
            s.settimeout(Config.TCP_TIMEOUT)  # Set the socket timeout
            s.connect((ip, 10000))  # Connect to the NTD device on port 10000
            s.sendall(payload)  # Send the time payload to the NTD device
            response = s.recv(1024)  # Receive the response from the NTD device
            log_sync_result(ip, "Synchronized")  # Log the successful synchronization
            logging.info(f"{location}: Synchronized successful")  # Log the successful synchronization
            last_sync_time[ip] = datetime.datetime.now()  # Update the last synchronization time
    except Exception as e:
        error_msg = f"Not Synchronized: {str(e)}"  # Create an error message
        log_sync_result(ip, error_msg)  # Log the failed synchronization
        logging.error(f"{location}: {error_msg}")  # Log the failed synchronization

def log_alert(timestamp, email, ip, location, status):
    """
    Records email alert attempts to a CSV file.

    Args:
        timestamp (str): The timestamp of the alert.
        email (str): The recipient email address.
        ip (str): The IP address of the NTD device.
        location (str): The location of the NTD device.
        status (str): The status of the alert attempt.
    """
    with open(Config.ALERT_LOG, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, email, ip, location, status])

def send_alert(ip, location):
    """
    Sends an email alert if the device is not synchronized.

    Args:
        ip (str): The IP address of the NTD device.
        location (str): The location of the NTD device.
    """
    current_hour = datetime.datetime.now().hour  # Get the current hour
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Capture timestamp

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

def check_sync_status():
    """
    Monitors synchronization logs and sends deduplicated alerts.
    """
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

def sync_all_and_alert():
    """
    Combines synchronization and alert checks.
    """
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