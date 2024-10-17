import os
import re
import sys
import sqlite3
import requests
import logging
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from sqlite3 import Connection, Cursor
from logger_helper import setup_logger
from dotenv import load_dotenv

# Setup logger for logging messages
setup_logger()

# Determine the base path based on whether the script is running as an executable
if getattr(sys, 'frozen', False):
    # If running as a PyInstaller executable
    base_path = sys._MEIPASS
else:
    # If running in a regular Python environment
    base_path = os.path.dirname(os.path.abspath(__file__))

# Load environment variables from the .env file
load_dotenv(os.path.join(base_path, '.env'))

# VirusTotal API key
API_KEY: str = os.getenv('API_KEY')

# Email Credentials
SMTP_SERVER: str = os.getenv('SMTP_SERVER')
SMTP_PORT: int = int(os.getenv('SMTP_PORT', 587))
APP_EMAIL: str = os.getenv('APP_EMAIL')
APP_PW: str = os.getenv('APP_PW')
EMAIL_SUBJECT: str = os.getenv('EMAIL_SUBJECT')
MY_EMAIL: str = os.getenv('MY_EMAIL')

# Time limits for VirusTotal API
HOURLY_LIMIT: int = int(os.getenv('HOURLY_LIMIT', 0))
MINUTE_LIMIT: int = int(os.getenv('MINUTE_LIMIT', 1))
DAILY_LIMIT: int = int(os.getenv('DAILY_LIMIT', 0))

# Calculate time between checks based on minute limit
TIME_BETWEEN_CHECKS: int = 60 // MINUTE_LIMIT

# SQLite database name
SQLITE_DB: str = os.getenv('SQLITE_DB')

# Rate limiting variable
# List to store timestamps of requests
request_timestamps: list = []


def get_dns_cache() -> list[str]:
    """Retrieve the DNS cache from the system."""

    logging.info("Attempting to retrieve DNS cache from system...")

    try:
        # Run 'ipconfig /displaydns' command to get DNS cache.
        output: str = os.popen('ipconfig /displaydns').read()

        # Extract IPs from output using regex.
        ips: list[str] = re.findall(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', output)
        if not ips:
            logging.warning("No IPs found in DNS cache")

            # Early return if no IPs are found
            return []
        logging.info("Retrieved DNS cache from system")
    except Exception as e:
        logging.error(f"Error retrieving DNS cache from system: {e}")
        return []

    return ips

def store_dns_cache(ips: list[str]) -> None:
    """Store retrieved IPs in the SQLite database."""

    conn: Connection = None
    try:
        logging.info("Attempting to connect to SQLite database...")
        conn = sqlite3.connect(SQLITE_DB) # Connect to the SQLite database
        logging.info("Successfully connected to sqlite db.")
        cursor: Cursor = conn.cursor()

        # Create dns_cache table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS dns_cache (ip TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        if ips:
            for ip in ips:
                # Insert IPs into the database
                cursor.execute('INSERT INTO dns_cache (ip) VALUES (?)', (ip,))

        # Commit changes to the database
        conn.commit()
        logging.info(f"Successfully added {len(ips)} IP(s) to SQLite database")

    except Exception as e:
        logging.error(f"Error storing DNS caches: {e}")
    finally:
        logging.info("Closing SQLite connection")
        if conn:
            # Ensure the database connection is closed
            conn.close()

def check_virustotal(ip: str) -> bool:
    """Check the provided IP against the VirusTotal API for malicious activity."""

    global request_timestamps
    current_time = time.time()

    # Rate limit handling: remove timestamps older than 1 hour
    request_timestamps = [t for t in request_timestamps if current_time - t < 3600]

    if len(request_timestamps) >= HOURLY_LIMIT:
        wait_time = 3600 - (current_time - request_timestamps[0])
        logging.warning(f"Rate limit reached. Waiting for {wait_time:.2f} seconds.")
        time.sleep(wait_time)
        request_timestamps = []

    try:
        logging.info("Attempting to connect to VirusTotal API")
        url: str = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
        parms: dict[str, str] = {'apikey': API_KEY, 'ip': ip}
        response = requests.get(url, params = parms)
        response.raise_for_status()

        # Log the timestamp of this request
        request_timestamps.append(time.time())

        # Check if the response is JSON and contains detected URLs
        if response.headers['Content-Type'] == 'application/json':
            logging.info("Successfully connected to VirusTotal API")
            result = response.json()
            if result.get('detected_urls'):
                logging.warning(f"Detected Malicious ip: {ip}")
                return True
            else:
                logging.info(f"Non-Malicious ip: {ip}")
        else:
            logging.info("Unexpected response content type.")
            return False
    
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error connecting to VirusTotal API: {e}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error connecting to VirusTotal API: {e}")
    except Exception as e:
        logging.error(f"Error connecting to VirusTotal API: {e}")

    return False

def alert_malicious_ip(ip_list: list[str]) -> None:
    """Send an email alert for detected malicious IPs."""

    # Create a multipart email message
    msg = MIMEMultipart()
    msg['From'] = APP_EMAIL
    msg['To'] = MY_EMAIL
    msg['subject'] = EMAIL_SUBJECT
    msg_body: str = f"""Dear User,\n\nThe following IP address(es) have been detected as malicious in your DNS cache:\n\nMalicious IPs:{'\n'.join(f"- {ip}" for ip in ip_list)}\n\nPlease take appropriate action to mitigate any potential threats.\n\nBest regards,\nDNS Cache Monitoring App"""
    # Attach the message body to the email
    msg.attach(MIMEText(msg_body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls() # Start TLS for security
            server.login(APP_EMAIL, APP_PW) # Log in to the email server
            server.send_message(msg) # Send the email
            logging.info("Email sent successfully!")
    except Exception as e:
        logging.error(f"Unable to send email: {e}")
    

def main() -> None:
    """Main function to run the DNS monitoring and alerting."""

    try:
        while True:
            # Get the current DNS cache
            ip_list: list[str] = get_dns_cache()
            logging.info(f"Retrieved IPs: {ip_list}")

            if len(ip_list) > HOURLY_LIMIT:
                # Remove IPs exceeding the hourly limit and log them
                removed_ip_list = ip_list[HOURLY_LIMIT:]
                logging.warning(f"Removed {len(removed_ip_list)} IP(s) due to hourly limit: {', '.join(removed_ip_list)}")

                # Log right after removal to confirm execution
                logging.info("Proceeding with the remaining IPs for further checks.")

                # Trim the list to the hourly limit
                ip_list = ip_list[:HOURLY_LIMIT]

            if ip_list:
                malicious_ip_list  = [] # List to store detected malicious IPs

                # Store the current IPs in the database
                store_dns_cache(ip_list)

                for ip in ip_list:
                    if check_virustotal(ip): # Check each IP against VirusTotal
                        # Append malicious IPs to the list
                        malicious_ip_list .append(ip)

                    # Wait between checks to avoid hitting the API too quickly
                    time.sleep(TIME_BETWEEN_CHECKS)

                if malicious_ip_list:   
                    # Alert for any detected malicious IPs
                    alert_malicious_ip(malicious_ip_list )
            
                logging.info("Completed cycle, waiting for next run...")
            time.sleep(3600)  # Wait 1 hour before the next run
    except Exception as e:
        logging.error(f"An error occurred in the main loop: {e}")

def is_running():
    """Check if another instance of this script is running."""

    lock_file = 'script.lock'
    if os.path.isfile(lock_file):
        return True
    open(lock_file, 'a').close()  # Create lock file
    return False

def cleanup():
    """Remove the lock file on exit."""

    if os.path.isfile('script.lock'):
        os.remove('script.lock')

if __name__ == '__main__':
    if is_running():
        logging.warning("Another instance is already running")
        sys.exit()

    try:
        logging.info("Starting the DNS monitoring script...")
        main()

    finally:
        cleanup()