#!/usr/bin/env python3
# Ubuntu ProTEC Automation Script
# Version: 1.0

import os
import subprocess
import time
import sys
import argparse

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}\n{e.stderr}")
        sys.exit(1)

def check_root():
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root. Please run again with 'sudo'.")
        sys.exit(1)

def prompt_user(message):
    input(f"{message} [Press Enter to continue...]")

def install_prerequisites():
    print("Installing required packages...")
    run_command("apt update && apt install -y opensc pcscd libccid libnss3-tools network-manager")
    print("Prerequisite installation complete.")

def detect_cac_reader():
    print("Detecting Smart Card Reader...\n")
    while True:
        output = run_command("opensc-tool -l")
        if "No smart card readers found" not in output:
            print(output)  # Report detected reader even if no card is inserted
            break
        print("Waiting for smart card reader...")
        time.sleep(3)

def detect_smart_card():
    print("Waiting for CAC insertion...\n")
    while True:
        output = run_command("opensc-tool -l")
        if "Card present" in output:
            print("Smart card detected.")
            break
        print("Waiting for CAC insertion...")
        time.sleep(3)

def extract_certificates():
    print("Extracting CAC Certificate...\n")
    run_command("pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -O")
    cert_id = input("Enter the ID of the certificate you wish to extract: ")
    run_command(f"pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --read-object --type cert --id {cert_id} --output-file user_cert.der")
    run_command("openssl x509 -inform DER -in user_cert.der -out user_cert.pem")
    print("Certificate extracted successfully as 'user_cert.pem'.")

def configure_pam():
    print("Configuring PAM for CAC login...\n")
    pam_config = "/etc/pam.d/common-auth"
    pam_line = "auth [success=2 default=ignore] pam_pkcs11.so\n"
    
    # Create a backup of the PAM configuration
    run_command(f"cp {pam_config} {pam_config}.backup.$(date +%Y%m%d%H%M%S)")
    print(f"Created backup of {pam_config}")
    
    with open(pam_config, "r") as file:
        contents = file.readlines()
    if pam_line not in contents:
        contents.insert(0, pam_line)
        with open(pam_config, "w") as file:
            file.writelines(contents)
    print("PAM configured successfully.")

def configure_browsers():
    print("Configuring Firefox, Chrome, and Edge for CAC...\n")
    for profile in ["~/.mozilla/firefox/*.default-release", "~/.config/google-chrome/", "~/.config/microsoft-edge/"]:
        try:
            run_command(f"modutil -dbdir sql:{profile} -add 'CAC Module' -libfile /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")
        except Exception as e:
            print(f"Warning: Could not configure {profile}: {str(e)}")
    print("Browsers configured for CAC authentication.")

def configure_8021x():
    print("Configuring 802.1X Wireless...\n")
    
    # Get network configuration from user
    ssid = input("Enter your WiFi SSID: ")
    identity = input("Enter your identity (often your username or email): ")
    ca_cert_path = input("Enter the path to your CA certificate (or press Enter for default DoD CA): ")
    
    if not ca_cert_path:
        ca_cert_path = "/usr/share/ca-certificates/dod-ca.pem"
    
    wifi_conf = "/etc/wpa_supplicant/wpa_supplicant-wlan0.conf"
    wifi_settings = f"""
network={{
    ssid="{ssid}"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="{identity}"
    client_cert="/path/to/user_cert.pem"
    private_key="/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
    ca_cert="{ca_cert_path}"
}}
"""
    with open(wifi_conf, "w") as file:
        file.write(wifi_settings)

    run_command("systemctl enable wpa_supplicant@wlan0")
    run_command("systemctl restart wpa_supplicant@wlan0")
    print("Wireless 802.1X configured successfully.")

def print_help():
    print("""
Ubuntu ProTEC Automation Script Help

This script automates the setup of CAC (Common Access Card) authentication
for Ubuntu systems. It configures system login, browser access, and network
authentication using CAC credentials.

OPTIONS:
  -h, --help            Show this help message and exit
  --install-only        Only install prerequisites, don't configure
  --cac-setup           Configure CAC reader and certificates
  --pam-setup           Configure PAM for system login via CAC
  --browser-setup       Configure browsers for CAC authentication
  --network-setup       Configure 802.1X network authentication
  
EXAMPLES:
  sudo ./protec.py               # Run the full setup process
  sudo ./protec.py --help        # Display this help message
  sudo ./protec.py --cac-setup   # Only configure the CAC reader
  
For more information, visit the Ubuntu ProTEC documentation at:
https://canonical.com/ubuntu/pro/protec
""")

def parse_arguments():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Show help message and exit')
    parser.add_argument('--install-only', action='store_true', help='Only install prerequisites')
    parser.add_argument('--cac-setup', action='store_true', help='Configure CAC reader and certificates')
    parser.add_argument('--pam-setup', action='store_true', help='Configure PAM for system login')
    parser.add_argument('--browser-setup', action='store_true', help='Configure browsers for CAC')
    parser.add_argument('--network-setup', action='store_true', help='Configure 802.1X network')
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    if args.help:
        print_help()
        sys.exit(0)
    
    print("🚀 Starting Ubuntu ProTEC Automation Script...\n")
    check_root()
    
    # Handle specific component setup if flags are provided
    if args.install_only:
        install_prerequisites()
        sys.exit(0)
    
    if args.cac_setup:
        install_prerequisites()
        detect_cac_reader()
        prompt_user("Please insert your CAC into the detected reader.")
        detect_smart_card()
        extract_certificates()
        sys.exit(0)
    
    if args.pam_setup:
        configure_pam()
        sys.exit(0)
    
    if args.browser_setup:
        configure_browsers()
        sys.exit(0)
    
    if args.network_setup:
        configure_8021x()
        sys.exit(0)
    
    # If no specific flags, run the full workflow
    install_prerequisites()
    detect_cac_reader()
    prompt_user("Please insert your CAC into the detected reader.")
    detect_smart_card()
    extract_certificates()
    configure_pam()
    configure_browsers()
    configure_8021x()
    print("🎯 All configurations complete! Reboot recommended.")

if __name__ == "__main__":
    main()
