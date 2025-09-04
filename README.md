# Network Time Display Synchronization-Alert System

This repository contains scripts for synchronizing Network Time Display (NTD) devices with NTP servers and sending alerts for synchronization failures.

## Overview
The primary script, `Code8_NTPServerfallback.py`, implements a robust system to:
- Synchronize NTD devices with both local and public NTP servers.
- Provide fallback to public servers (e.g., `time.google.com`, `pool.ntp.org`) if local servers fail.
- Log synchronization results and send email alerts to designated recipients.
- Manage NTD devices across various locations (e.g., Library, Auditorium).

## Features
- **NTP Server Fallback**: Tries local servers first (`192.168.251.32`, etc.), then public servers.
- **Synchronization**: Updates NTD devices (e.g., `172.16.26.10`, `172.16.26.16`) via TCP on port 10000.
- **Alerting**: Sends email notifications (to `amitnplindia21@gmail.com`, `divyaforself@gmail.com`) for failures, with a 1-hour cooldown.
- **Logging**: Saves data to `logs/NTDs_Display_synchronization_log.csv` and `logs/NTDs_EmailAlert_log.csv`.

## Setup
1. Clone the repository: `git clone https://github.com/amitkcodes/Network_Time_Display_Synchronization-Alert-System.git`
2. Install dependencies (e.g., Python with `socket`, `threading`, `smtplib`).
3. Configure email settings in the `Config` class (update `EMAIL` and `PASSWORD` with app-specific credentials).
4. Run the script: `python Code8_NTPServerfallback.py`

## Contributors
- Amit Kaushik
- Divya Singh Yadav
- Dr. Deepak Sharma
- Dr. Ashish Agrawal
- Dr. Subhasis Panja

## License
No license specified yet. Consider adding one (e.g., MIT) if applicable.

## Future Improvements
- Add configuration file support.
- Enhance error handling for network issues.
- Include unit tests.NTP Display Sync server-192.168.251.32/33


