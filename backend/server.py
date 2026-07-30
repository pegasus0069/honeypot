from flask import Flask, request, jsonify
import msal
import requests
import os 
import sys
import json
from flask_cors import CORS
import re
import netifaces
from scapy.all import sniff, IP, TCP, ICMP
from datetime import datetime
from threading import Thread, Lock
import subprocess
import logging
import threading
import time


# Thread-safe tracking of IPs with timestamps
ip_lock = Lock()
past_ips = {}  # Dictionary to store IPs with timestamp: {ip: expiry_time}
IP_TIMEOUT = 1.5  # Seconds before an IP can trigger a new alert

# Path to the JSON file
duplicate = None
autoblock = "OFF"

# Function to clean up expired IPs from the tracking dictionary
def cleanup_expired_ips():
    with ip_lock:
        current_time = time.time()
        expired_ips = [ip for ip, expiry in past_ips.items() if current_time > expiry]
        for ip in expired_ips:
            del past_ips[ip]
    
    # Schedule next cleanup
    cleanup_timer = threading.Timer(IP_TIMEOUT, cleanup_expired_ips)
    cleanup_timer.daemon = True
    cleanup_timer.start()

# Start the initial cleanup timer
cleanup_timer = threading.Timer(IP_TIMEOUT, cleanup_expired_ips)
cleanup_timer.daemon = True
cleanup_timer.start()

def resource_path(filename):
    """Returns the correct path to the resource (e.g., JSON file)."""
    if getattr(sys, 'frozen', False):
        # Running in a PyInstaller bundle
        base_path = os.path.dirname(sys.executable)
    else:
        # Running as script
        base_path = os.path.dirname(__file__)
    
    return os.path.join(base_path, filename)

if getattr(sys, 'frozen', False):
    # Running in PyInstaller bundle
    base_path = os.path.dirname(sys.executable)
else:
    # Running as script
    base_path = os.path.dirname(__file__)

data_file_path = os.path.join(base_path, 'data.json')

# Load initial data from JSON file
with open(data_file_path, 'r') as f:
    data = json.load(f)
    password = data.get('password')
    autoblock = data.get('autoblock')
    RECIPIENT_EMAIL = data.get('receiver_email', '')
    print(RECIPIENT_EMAIL)
    if not RECIPIENT_EMAIL:
        print('Receiver email is required')

# Email Part & Sender details
CLIENT_ID = ""
CLIENT_SECRET = ""
TENANT_ID = ""
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["https://graph.microsoft.com/.default"]
SENDER_EMAIL = ""

# Get Access Token
def get_access_token():
    app = msal.ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET)
    token_response = app.acquire_token_for_client(scopes=SCOPES)
    
    if "access_token" in token_response:
        return token_response["access_token"]
    else:
        raise Exception(f"Failed to get token: {token_response}")

# Send Email using Microsoft Graph API
def send_email(message_body):
    token = get_access_token()
    url = "https://graph.microsoft.com/v1.0/users/{}/sendMail".format(SENDER_EMAIL)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    email_data = {
        "message": {
            "subject": "UKCS Honeytrap Alert",
            "body": {
                "contentType": "Text",
                "content": message_body
            },
            "toRecipients": [
                {"emailAddress": {"address": RECIPIENT_EMAIL}}
            ]
        }
    }
    response = requests.post(url, headers=headers, json=email_data)
    
    if response.status_code == 202:
        print("Email sent successfully!")
    else:
        print(f"Failed to send email: {response.status_code}, {response.text}")

# Flask app setup
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    filename="dhcp_manager.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Configuration paths
DHCPD_CONF = "/etc/dhcp/dhcpd.conf"
DHCPD_LEASES = "/var/lib/dhcp/dhcpd.leases"
LOG_FILE = "/var/log/messages"

# List to safely share the latest event data between threads
latest_events = []

# JSON and log file paths
json_file_path = "events.json"
log_file_path = "events.log"

# Store the last recorded event to prevent duplicate writes
last_event = None

def add_to_blacklist(src_ip, mac_address, file_path='blacklist.json'):
    # Resolve the correct path to the file (in case it's bundled)
    file_path = resource_path(file_path)
    
    """
    Adds a new entry to the blacklist JSON file.
    Returns 1 if the entry was added successfully, 0 if the MAC address already exists.
    """
    new_entry = {
        "src_ip": src_ip,
        "mac_address": mac_address
    }

    try:
        # Read the existing data from the JSON file
        with open(file_path, 'r') as file:
            blacklist = json.load(file)
    except FileNotFoundError:
        # If the file does not exist, start with an empty list
        blacklist = []

    # Check if the MAC address already exists in the blacklist
    if any(entry["mac_address"] == mac_address for entry in blacklist):
        return  # MAC address already exists

    # Append the new entry to the blacklist
    blacklist.append(new_entry)

    # Write the updated data back to the JSON file
    with open(file_path, 'w') as file:
        json.dump(blacklist, file, indent=4)

def remove_from_blacklist_by_mac(mac_address, file_path='blacklist.json'):
    # Resolve the correct path to the file (in case it's bundled)
    file_path = resource_path(file_path)
    try:
        # Read the existing data from the JSON file
        with open(file_path, 'r') as file:
            blacklist = json.load(file)
    except FileNotFoundError:
        # If the file does not exist, nothing to remove
        return
    
    # Remove entries with the given mac_address
    blacklist = [entry for entry in blacklist if entry['mac_address'] != mac_address]
    
    # Write the updated data back to the JSON file
    with open(file_path, 'w') as file:
        json.dump(blacklist, file, indent=4)

def get_default_gateway():
    try:
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0]  # Get the IPv4 default gateway
    except Exception as e:
        print(f"Error getting default gateway: {e}")
        return None

ROUTER_IP = get_default_gateway()

# Get the Raspberry Pi's own IP addresses for both eth0 and wlan1
def get_own_ips():
    own_ips = []
    interfaces = ["eth0","wlan1"]
    for interface in interfaces:
        try:
            addresses = netifaces.ifaddresses(interface)
            ipv4_info = addresses.get(netifaces.AF_INET)
            if ipv4_info:
                own_ips.append(ipv4_info[0]['addr'])
        except ValueError as e:
            print(f"Error getting IP for {interface}: {e}")
    own_ips.append(ROUTER_IP)
    return own_ips

OWN_IPS = get_own_ips()

def get_mac(ip):
    """Fetch the MAC address for a given IP address."""
    try:
        result = os.popen(f"arp -an | grep '({ip})'").read()
        mac_address = re.search(r"([0-9a-fA-F:]{17})", result)
        return mac_address.group(0) if mac_address else "Unknown MAC"
    except Exception as e:
        return f"Error: {e}"

def save_event(event_data):
    """Save the captured event data to both JSON and log files, ensuring no duplicates."""
    global last_event

    # Check if the new event is the same as the last recorded one
    if last_event == event_data:
        return  # No new event, skip saving

    # Update last recorded event
    last_event = event_data

    # Save to JSON file
    try:
        with open(json_file_path, "a") as json_file:
            json.dump(event_data, json_file)
            json_file.write("\n")  # Write each event on a new line
    except Exception as e:
        print(f"Error saving to JSON file: {e}")

    # Save to log file (plain text format)
    try:
        with open(log_file_path, "a") as log_file:
            log_file.write(f"{event_data['timestamp']} - {event_data['type']} - {event_data['src_ip']} - {event_data['mac_address']}\n")
    except Exception as e:
        print(f"Error saving to log file: {e}")

def packet_callback(packet):
    """Process sniffed packets and return JSON with details, ignoring own IP."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        print(f"Packet received from: {src_ip}")

        # Ignore packets from the Raspberry Pi itself
        if src_ip in OWN_IPS:
            print(f"Ignoring packet from own IP: {src_ip}")
            return

        mac_address = get_mac(src_ip)
        if mac_address == "Unknown MAC":
            print(f"Unknown MAC address for IP: {src_ip}")
            return
        
        event_type = 1

        if packet.haslayer(TCP) and packet[TCP].dport == 22:
            event_type = "SSH"
        elif packet.haslayer(ICMP):
             event_type = "PING"

        if event_type:
            # Get the current timestamp
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Create the JSON data
            latest_event = {
                "timestamp": timestamp,
                "type": event_type,
                "src_ip": src_ip,
                "mac_address": mac_address
            }
            
            # Thread-safe check for duplicates using lock and update timestamp
            current_time = time.time()
            expiry_time = current_time + IP_TIMEOUT
            
            with ip_lock:
                duplicate = src_ip in past_ips
                # Always update the timestamp (either new entry or reset timer)
                past_ips[src_ip] = expiry_time
            
            if autoblock=="ON":
                # Save the event data to JSON and log files (whether duplicate or not)
                save_event(latest_event)
                
                # Only notify and add to latest_events if not a duplicate
                if not duplicate:
                    latest_events.append(latest_event)
                    message = f"Connection attempted from MAC: {mac_address}, IP: {src_ip}"
                    send_email(message)
                    print("Mail attempted")
                
                block_mac_auto(mac_address, src_ip)
            else:
                # Only notify and add to latest_events if not a duplicate
                if not duplicate:
                    latest_events.append(latest_event)
                    message = f"Connection attempt from MAC: {mac_address}, IP: {src_ip}"
                    send_email(message)
                    print(f"Captured event: {json.dumps(latest_event)}")
                    print("Mail attempted")

def restart_dhcp_server():
    """Restarts the isc-dhcp-server service."""
    try:
        subprocess.run(["sudo", "systemctl", "restart", "isc-dhcp-server"], check=True)
        logging.info("isc-dhcp-server restarted.")
        return "DHCP server restarted successfully."
    except subprocess.CalledProcessError as e:
        logging.error(f"Error restarting isc-dhcp-server: {e}")
        return "Error restarting DHCP server. Check logs for details."

def block_mac(mac_address, ip):
    """Blocks the specified MAC address using dhcpd.conf while preserving subnet settings."""
    try:
        # Read the current configuration
        with open(DHCPD_CONF, "r") as f:
            config_content = f.readlines()

        # Check if the MAC address is already blocked
        if any(f"subclass \"black-hole\" {mac_address};" in line for line in config_content):
            return f"MAC Address {mac_address} is already blocked."

        # Check if the "black-hole" class exists
        black_hole_class_exists = any("class \"black-hole\"" in line for line in config_content)

        # Add the "black-hole" class if it doesn't exist
        if not black_hole_class_exists:
            black_hole_class = """
class "black-hole" {
  match substring (hardware, 1, 6);
  ignore booting;
}

"""
            config_content.append(black_hole_class)

        # Add the subclass for the MAC address
        mac_subclass = f"subclass \"black-hole\" {mac_address};\n"
        config_content.append(mac_subclass)

        # Write the updated configuration back to the file
        with open(DHCPD_CONF, "w") as f:
            f.writelines(config_content)

        logging.info(f"Added MAC {mac_address} to black-hole class in {DHCPD_CONF}")
        add_to_blacklist(ip, mac_address)

        return 1
    except Exception as e:
        logging.error(f"Error blocking MAC {mac_address}: {e}")
        return 0


def block_mac_auto(mac_address, ip):
    """Blocks the specified MAC address using dhcpd.conf while preserving subnet settings."""
    try:
        # Read the current configuration
        with open(DHCPD_CONF, "r") as f:
            config_content = f.readlines()

        # Check if the MAC address is already blocked
        if any(f"subclass \"black-hole\" {mac_address};" in line for line in config_content):
            return f"MAC Address {mac_address} is already blocked."

        # Check if the "black-hole" class exists
        black_hole_class_exists = any("class \"black-hole\"" in line for line in config_content)

        # Add the "black-hole" class if it doesn't exist
        if not black_hole_class_exists:
            black_hole_class = """
class "black-hole" {
  match substring (hardware, 1, 6);
  ignore booting;
}

"""
            config_content.append(black_hole_class)

        # Add the subclass for the MAC address
        mac_subclass = f"subclass \"black-hole\" {mac_address};\n"
        config_content.append(mac_subclass)

        # Write the updated configuration back to the file
        with open(DHCPD_CONF, "w") as f:
            f.writelines(config_content)

        logging.info(f"Added MAC {mac_address} to black-hole class in {DHCPD_CONF}")
        
        restart_dhcp_server()
        deauth_client(mac_address)
        add_to_blacklist(ip, mac_address)

        return 1
    except Exception as e:
        logging.error(f"Error blocking MAC {mac_address}: {e}")
        return 0

def unblock_mac(mac_address):
    """Unblocks the specified MAC address."""
    try:
        # Update dhcpd.conf
        with open(DHCPD_CONF, "r") as f:
            lines = f.readlines()
        with open(DHCPD_CONF, "w") as f:
            for line in lines:
                if f"subclass \"black-hole\" {mac_address};" not in line:
                    f.write(line)
        logging.info(f"Removed MAC {mac_address} from black-hole class in {DHCPD_CONF}")
        remove_from_blacklist_by_mac(mac_address)
        restart_dhcp_server()
        return f"MAC address {mac_address} unblocked successfully."
    except Exception as e:
        logging.error(f"Error unblocking MAC {mac_address} in ub function: {e}")
        return f"Error unblocking MAC {mac_address}. Error in ub function. Check logs for details."

# Start the sniffing process in a separate thread
def start_sniffing():
    print(f"Monitoring SSH and Ping attempts... Ignoring own IPs: {OWN_IPS}")

    def sniff_interface(interface):
        print(f"Starting sniffing on interface: {interface}")
        sniff(filter="port 22 or icmp", iface=interface, prn=packet_callback, store=0)

    # Start sniffing on eth0 and wlan1 in separate threads
    eth0_thread = Thread(target=sniff_interface, args=("eth0",))
    wlan1_thread = Thread(target=sniff_interface, args=("wlan1",))

    eth0_thread.daemon = True
    wlan1_thread.daemon = True

    eth0_thread.start()
    wlan1_thread.start()

    # Keep the threads alive
    eth0_thread.join()
    wlan1_thread.join()
    
# --- Deauth Functions ---
def deauth_client(target_mac):
    try:
        interface = get_wireless_interface()
        if not interface:
            print("No second wireless interface found.")
            return
    except Exception as e:
        print(f"Error getting wireless interface: {e}")
        return

    try:
        ap_mac = get_ap_mac(interface)
        if not ap_mac:
            print("No access point MAC found.")
            return
    except Exception as e:
        print(f"Error getting access point MAC: {e}")
        return

    try:
        channel = get_wifi_channel(interface)
        if not channel:
            print("Could not determine Wi-Fi channel.")
            return 0
    except Exception as e:
        print(f"Error getting Wi-Fi channel: {e}")
        return 0

    try:
        mon_interface = enable_monitor_mode(interface)
        if not mon_interface:
            print("Could not enable monitor mode.")
            return
    except Exception as e:
        print(f"Error enabling monitor mode: {e}")
        return 0

    try:
        send_deauth_attack(ap_mac, target_mac, mon_interface, channel)
        return 1
    except Exception as e:
        return 0

def get_wireless_interface():
    """Gets the name of the second wireless interface."""
    try:
        iwconfig_output = subprocess.check_output(['iwconfig'], universal_newlines=True)
        interfaces = []
        for line in iwconfig_output.split('\n'):
            if 'IEEE 802.11' in line:
                interface = line.split()[0]
                interfaces.append(interface)
        
        if len(interfaces) >= 2:
            second_interface = interfaces[1]  # Select the second interface
            print("Second Wireless Interface:", second_interface)
            return second_interface
        else:
            print("Less than 2 wireless interfaces found.")
            return None
    except Exception as e:
        print(f"Error getting wireless interface: {e}")
        return None
    
def get_ap_mac(interface):
    """Gets the MAC address of the connected access point (router) using iw dev."""
    try:
        iw_output = subprocess.check_output(['iw', 'dev', interface, 'link'], universal_newlines=True)
        match = re.search(r'Connected to ([0-9A-Fa-f:]+)', iw_output)
        if match:
            ap_mac = match.group(1)
            print("Router MAC:", ap_mac)
            return ap_mac
        else:
            print("Could not find Access Point MAC.")
            return None
    except Exception as e:
        print(f"Error getting AP MAC: {e}")
        return None
    
def get_wifi_channel(interface):
    """Gets the Wi-Fi channel of the connected access point using iw dev."""
    try:
        iw_output = subprocess.check_output(['iw', 'dev', interface, 'info'], universal_newlines=True)
        match = re.search(r'channel\s+(\d+)', iw_output)
        if match:
            channel = match.group(1)
            print("Wi-Fi Channel:", channel)
            return channel
        else:
            print("Could not determine channel.")
            return None
    except Exception as e:
        print(f"Error getting Wi-Fi channel: {e}")
        return None
    
def enable_monitor_mode(interface):
    """Enables monitor mode on the specified interface using iw."""
    try:
        # Disable the interface first
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True)
        # Set the interface to monitor mode
        subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'monitor'], check=True)
        # Enable the interface again
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True)
        
        mon_interface = interface
        print(f"Monitor mode enabled: {mon_interface}")
        return mon_interface
    except Exception as e:
        print(f"Error enabling monitor mode: {e}")
        return None
    
def send_deauth_attack(bssid, target_mac, interface, channel):
    """Sends deauthentication packets to the target device."""
    try:
        # Set interface to the correct channel
        subprocess.run(['sudo', 'iwconfig', interface, 'channel', channel], check=True)
        print(f"Set {interface} to channel {channel}")

        # Send deauthentication packets
        print(f"Sending deauth attack to {target_mac} on {bssid} via {interface}")
        subprocess.run(['sudo', 'aireplay-ng', '-0', '4', '-a', bssid, '-c', target_mac, interface], check=True)
        print("Deauth attack completed.")
    except Exception as e:
        print(f"Error sending deauth attack: {e}")

# API Routes
@app.route('/change_email', methods=['POST'])
def change_email():
    data = request.get_json()
    new_email = data.get('new_email', '')
    if not new_email:
        return 'New email is required', 400
    # Update the email in the data.json file
    with open(data_file_path, 'r') as f:
        data = json.load(f)
    data['receiver_email'] = new_email
    with open(data_file_path, 'w') as f:
        json.dump(data, f)
    return 'Email updated successfully', 200

@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.get_json()
    new_password = data.get('new_password', '')
    if not new_password:
        return 'New password is required', 400
    # Update the password in the data.json file
    with open(data_file_path, 'r') as f:
        data = json.load(f)
    data['password'] = new_password
    with open(data_file_path, 'w') as f:
        json.dump(data, f)
    global password
    password = new_password
    return 'Password updated successfully', 200

@app.route('/verify_password', methods=['POST'])
def verify_password():
    data = request.get_json()
    submitted_password = data.get('password', '')
    # Read the stored password from the data.json file
    with open(data_file_path, 'r') as f:
        data = json.load(f)
        stored_password = data.get('password', '')
    if submitted_password == stored_password:
        return jsonify({'status': '1'}), 200
    else:
        return jsonify({'status': '0'}), 401
    
@app.route('/change_autoblock', methods=['POST'])
def change_autoblock():
    data = request.get_json()
    new_autoblock = data.get('autoblock', '')
    if new_autoblock not in ['ON', 'OFF']:
        return 'Invalid autoblock value', 400
    # Update the autoblock in the data.json file
    with open(data_file_path, 'r') as f:
        data = json.load(f)
    data['autoblock'] = new_autoblock
    with open(data_file_path, 'w') as f:
        json.dump(data, f)
    global autoblock
    autoblock = new_autoblock
    return 'Autoblock updated successfully', 200

@app.route('/get_password', methods=['GET'])
def get_password():
    # Read the password from the data.json file
    with open(data_file_path, 'r') as f:
        data = json.load(f)
        password = data.get('password', '')
    return jsonify({'password': password}), 200

@app.route('/get_email', methods=['GET'])
def get_email():
    # Read the receiver email from the data.json file
    with open(data_file_path, 'r') as f:
        data = json.load(f)
        receiver_email = data.get('receiver_email', '')
    return jsonify({'receiver_email': receiver_email}), 200

@app.route('/get_autoblock', methods=['GET'])
def get_autoblock():
    # Read the autoblock from the data.json file
    with open(data_file_path, 'r') as f:
        data = json.load(f)
        autoblock = data.get('autoblock')
    return jsonify({'autoblock': autoblock}), 200

@app.route("/unblock_mac", methods=["POST"])
def unblock_mac_api():
    data = request.get_json()
    mac_to_unblock = data.get('mac_address')
    if not mac_to_unblock:
        return jsonify({"error": "MAC address is required"}), 400
    
    result = unblock_mac(mac_to_unblock)
    remove_from_blacklist_by_mac(mac_to_unblock)
    
    return jsonify(result), 200

@app.route("/block_mac", methods=["POST"])
def block_mac_api():
    data = request.get_json()
    mac_to_block = data.get('mac_address')
    ip = data.get('ip_address')
    if not mac_to_block:
        return jsonify({"error": "MAC address is required"}), 400
    block_mac(mac_to_block, ip)
    restart_dhcp_server()
    deauth_client(mac_to_block)
    return jsonify({"message": "MAC address blocked and deauthenticated"})

@app.route("/get_latest_event", methods=["GET"])
def get_latest_event():
    try:
        # Fetch the latest event from the queue (non-blocking call)
        if len(latest_events) > 0:
            # Get the latest event and remove it from the list
            latest_event = latest_events.pop(0)
            return jsonify(latest_event)
        else:
            return jsonify({"message": "No event detected yet"}), 200
    except Exception as e:
        return jsonify({"message": f"Error fetching latest event: {e}"}), 404
    
@app.route("/get_blacklist", methods=["GET"])
def get_blacklist():
    # Resolve the correct path to the file (in case it's bundled)
    file_path = resource_path('blacklist.json')
    try:
        # Read the existing data from the JSON file
        with open(file_path, 'r') as file:
            blacklist = json.load(file)
        return jsonify(blacklist), 200
    except FileNotFoundError:
        return jsonify({"message": "Blacklist file not found"}), 404
    except Exception as e:
        return jsonify({"message": f"Error reading blacklist file: {e}"}), 500

@app.route("/remove_from_blacklist_by_mac", methods=["POST"])
def remove_from_blacklist_by_mac_api():
    data = request.get_json()
    mac_address = data.get('mac_address')
    if not mac_address:
        return jsonify({"error": "MAC address is required"}), 400
    
    remove_from_blacklist_by_mac(mac_address)
    return jsonify({"message": f"MAC address {mac_address} removed from blacklist"}), 200

if __name__ == '__main__':
    try:
        # Start sniffing in a separate thread or process
        sniff_thread = Thread(target=start_sniffing)
        sniff_thread.daemon = True
        sniff_thread.start()
        
    except Exception as e:
        print(e)
        print(e.__traceback__)
    app.run(debug=True)
