from scapy.all import sniff, ARP, TCP, IP
from collections import defaultdict
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import schedule
import time
from email.mime.base import MIMEBase
from email import encoders
import mysql.connector as sql
from datetime import datetime
import yagmail


# Initialize text file for storing the output
output_file = 'C:/Users/nikhi/Desktop/VS Code/IDS/IDS_output.txt'


# Initialize Database Connection
db = sql.connect(host="localhost", user="root", password="20ls3a1028@root", database="IDS")
cursor = db.cursor()
query = "SELECT * FROM signature"

# Define the block_ip function
def block_ip(ip_address):
    # Ensure proper privilege and execution environment to run iptables commands
    pass

# Function to write output to file
def write_to_file(output):
    with open(output_file, "a") as file:
        file.write(output + "\n")

# Creating the class for IDS
class IDS:
    def __init__(self):
        self.arp_cache = defaultdict(set)
        self.port_scan_threshold = 10
        self.port_scan_alerts = set()
        self.signatures = {}  # initialize this with actual signatures from database

    def arp_spoof_alert(self, packet):
        try:
            if ARP in packet and packet[ARP].psrc != packet[ARP].hwsrc:
                spoofing_msg = f"[ALERT] Possible ARP spoofing detected: {packet[ARP].psrc} is claiming to be {packet[ARP].hwsrc} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                print(spoofing_msg)
                block_ip(packet[ARP].psrc)  # Block the suspicious IP
                write_to_file(spoofing_msg)
        except Exception as e:
            error_msg = f"Error in ARP spoof alert: {e}"
            print(error_msg)
            write_to_file(error_msg)

    def port_scan_alert(self, packet):
        try:
            if IP in packet:
                ip_src = packet[IP].src
                if TCP in packet:
                    tcp_dport = packet[TCP].dport
                    self.arp_cache[ip_src].add(tcp_dport)
                    if len(self.arp_cache[ip_src]) > self.port_scan_threshold:
                        self.port_scan_alerts.add(ip_src)
                        print("[ALERT] Port scan detected from: " + ip_src)
                        block_ip(ip_src)  # Block the suspicious IP
                        write_to_file("[ALERT] Port scan detected from: " + ip_src.format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        except Exception as e:
            print("Error in port scan alert:", e)

    def signature_based_detection(self, packet):
        try:
            raw_data = bytes(packet)
            for signature, pattern in self.signatures.items():
                if pattern in raw_data:
                    print(f"[ALERT] Signature '{signature}' detected in packet from {packet[IP].src}")
                    block_ip(packet[IP].src)  # Block the suspicious IP
                    write_to_file(f"[ALERT] Signature '{signature}' detected in packet from {packet[IP].src}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        except Exception as e:
            print("Error in signature-based detection:", e)

    @staticmethod
    def detect_xss(payload):
        xss_pattern = r"<script[^>]*>.*?</script>|<\s*img[^>]*src=[^>]+javascript:[^>]*>|<\s*a[^>]*href=[^>]+javascript:[^>]*>|<\s*iframe[^>]*src=[^>]+javascript:[^>]*>"
        if re.search(xss_pattern, payload, re.IGNORECASE):
            return True
        else:
            return False

    def detect_brute_force(self, attempts, threshold):
        ssh_failure_regex = r"Failed password for .* from .* port \d+ ssh2"
        failed_attempts = 0
        for attempt in attempts:
            if re.match(ssh_failure_regex, attempt):
                failed_attempts += 1
        if failed_attempts >= threshold:
            print("[ALERT] : Brute force attack detected!")
            write_to_file("[ALERT] : Brute force attack detected! {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        else:
            return False

    @staticmethod
    def process_packet(packet_data):
        max_packet_size = 1024
        if len(packet_data) > max_packet_size:
            print(f"[ALERT] Packet size exceeds maximum allowed size. Potential buffer overflow detected.")
            write_to_file(f"[ALERT] Packet size exceeds maximum allowed size. Potential buffer overflow detected.".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        else:
            print("Processing packet:", packet_data)

    def analyze_packet(self, packet):
        try:
            self.arp_spoof_alert(packet)
            self.port_scan_alert(packet)
            self.signature_based_detection(packet)
        except Exception as e:
            print("Error in analyzing packet:", e)

# Initialize IDS
ids = IDS()

# Sniff packets and pass them to the IDS for analysis
try:
    sniff(prn=lambda packet: ids.analyze_packet(packet), store=0)
except Exception as e:
    print("Error in sniffing packets:", e)
    
    

# Email configuration
sender_email = "Your email here"
receiver_email = "Receivers email here"
password = "Password here"


# Function to send email
def send_email():
    with yagmail.SMTP(sender_email, password) as yag:
        subject = "Alert from IDS".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        contents = "Suspicious activity detected on your network. See attached log file for details."
        output_file = "C:/Users/nikhi/Desktop/VS Code/IDS/IDS_output.txt"  # Replace with your path (assuming Windows)
        yag.send(receiver_email, subject, contents, attachments=output_file)
        print(f"Email sent successfully!")


# Schedule the task to send email every hour
schedule.every(1).hour.do(send_email)

# Run the scheduler
while True:
    schedule.run_pending()
    time.sleep(1)

