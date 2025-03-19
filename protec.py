#!/usr/bin/env python3
# Ubuntu ProTEC Automation Script
# Version: 2.0
# Implements best practices from official Ubuntu smart card documentation

import os
import subprocess
import time
import sys
import shutil
import getpass
import re
import logging
import json
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"protec-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('protec')

# Global configuration
CONFIG = {
    "backup_dir": "protec_backups",
    "cert_dir": "/etc/ssl/certs/cac",
    "pam_config_dir": "/etc/pam.d",
    "pam_pkcs11_dir": "/etc/pam_pkcs11",
    "nss_config_dir": "/etc/pki/nssdb",
    "pkcs11_module": "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
}

def run_command(command, check=True, silent=False, input_str=None):
    """
    Execute a shell command and return its output.
    Handles errors and provides detailed logging.
    """
    try:
        if input_str:
            result = subprocess.run(
                command, 
                shell=True, 
                check=check, 
                capture_output=True, 
                text=True,
                input=input_str
            )
        else:
            result = subprocess.run(
                command, 
                shell=True, 
                check=check, 
                capture_output=True, 
                text=True
            )
        
        if not silent:
            logger.debug(f"Command executed: {command}")
            logger.debug(f"Command output: {result.stdout.strip()}")
        
        if result.stderr and not silent:
            logger.debug(f"Command stderr: {result.stderr.strip()}")
            
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running command: {command}")
        logger.error(f"Error details: {e.stderr}")
        
        if check:
            print(f"Command failed: {command}")
            print(f"Error: {e.stderr}")
            
            if "not found" in e.stderr and check_package_in_command(command):
                missing_package = check_package_in_command(command)
                print(f"It appears {missing_package} may not be installed. Attempting to install...")
                run_command(f"apt update && apt install -y {missing_package}", check=False)
                # Try the command again
                return run_command(command, check=False)
            
            sys.exit(1)
        
        return e.stderr

def check_package_in_command(command):
    """
    Check if the command potentially contains references to a package that needs to be installed.
    Returns package name if found, None otherwise.
    """
    common_tools = {
        "opensc-tool": "opensc",
        "pkcs11-tool": "opensc",
        "p11tool": "gnutls-bin",
        "pam-auth-update": "libpam-runtime",
        "modutil": "libnss3-tools",
        "certutil": "libnss3-tools",
        "pk12util": "libnss3-tools",
        "wpa_supplicant": "wpasupplicant",
        "ssh-keygen": "openssh-client"
    }
    
    for tool, package in common_tools.items():
        if tool in command:
            return package
    return None

def check_root():
    """
    Ensure the script runs with root privileges.
    """
    if os.geteuid() != 0:
        logger.error("This script must be run as root.")
        print("This script must be run as root. Please run again with 'sudo'.")
        sys.exit(1)
    logger.info("Script running with root privileges.")

def prompt_user(message, default=None):
    """
    Prompt the user for input with optional default value.
    """
    prompt = f"{message} "
    if default:
        prompt += f"[{default}]: "
    else:
        prompt += ": "
    
    user_input = input(prompt)
    if not user_input and default:
        return default
    return user_input

def prompt_continue(message="Continue with the installation?"):
    """
    Ask user to confirm continuation.
    """
    response = prompt_user(f"{message} (y/n)", "y").lower()
    if response != 'y' and response != 'yes':
        logger.info("User chose to exit.")
        print("Exiting ProTEC installation.")
        sys.exit(0)

def create_backup(file_path, backup_dir=CONFIG["backup_dir"]):
    """
    Create a backup of a configuration file before modifying it.
    """
    if not os.path.exists(file_path):
        logger.warning(f"Cannot backup {file_path} - file does not exist.")
        return False
    
    # Create backup directory if it doesn't exist
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
        logger.info(f"Created backup directory: {backup_dir}")
    
    backup_path = os.path.join(backup_dir, f"{os.path.basename(file_path)}.{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    
    try:
        shutil.copy2(file_path, backup_path)
        logger.info(f"Created backup of {file_path} at {backup_path}")
        print(f"Backup created: {backup_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to create backup of {file_path}: {str(e)}")
        print(f"Warning: Could not create backup of {file_path}")
        return False

def restore_backup(file_path, backup_dir=CONFIG["backup_dir"]):
    """
    Restore the most recent backup of a configuration file.
    """
    if not os.path.exists(backup_dir):
        logger.warning("No backup directory found.")
        print("No backups found to restore.")
        return False
    
    # Find the most recent backup
    backup_files = [f for f in os.listdir(backup_dir) if f.startswith(os.path.basename(file_path))]
    if not backup_files:
        logger.warning(f"No backups found for {file_path}")
        print(f"No backups found for {file_path}")
        return False
    
    latest_backup = sorted(backup_files)[-1]
    backup_path = os.path.join(backup_dir, latest_backup)
    
    try:
        shutil.copy2(backup_path, file_path)
        logger.info(f"Restored {file_path} from {backup_path}")
        print(f"Restored {file_path} from backup")
        return True
    except Exception as e:
        logger.error(f"Failed to restore {file_path}: {str(e)}")
        print(f"Failed to restore from backup: {str(e)}")
        return False

def install_prerequisites():
    """
    Install required packages for CAC functionality.
    Based on Ubuntu documentation recommendations.
    """
    print("Installing required packages...")
    logger.info("Installing prerequisites")
    
    # Updated package list based on Ubuntu documentation
    packages = [
        "opensc", 
        "pcscd", 
        "libccid", 
        "libnss3-tools", 
        "network-manager", 
        "wpasupplicant", 
        "ca-certificates",
        "libpam-pkcs11",  # Added from Ubuntu docs
        "opensc-pkcs11",  # Added from Ubuntu docs
        "gnutls-bin",     # Added for p11tool
        "libpam-runtime", # Added for pam-auth-update
        "openssh-client"  # For SSH key operations
    ]
    
    try:
        run_command(f"apt update && apt install -y {' '.join(packages)}")
        print("Prerequisite installation complete.")
        logger.info("Prerequisite installation completed successfully")
        
        # Ensure services are running
        run_command("systemctl enable pcscd")
        run_command("systemctl start pcscd")
        logger.info("pcscd service started")
        
        # Create certificate directories
        os.makedirs(CONFIG["cert_dir"], exist_ok=True)
        logger.info(f"Created certificate directory: {CONFIG['cert_dir']}")
        
        return True
    except Exception as e:
        logger.error(f"Failed to install prerequisites: {str(e)}")
        print(f"Failed to install prerequisites: {str(e)}")
        return False

def detect_cac_reader():
    """
    Detect connected smart card readers.
    Returns the detected reader.
    """
    print("Detecting Smart Card Reader...")
    logger.info("Searching for smart card reader")
    
    max_attempts = 10
    attempt = 0
    
    while attempt < max_attempts:
        attempt += 1
        try:
            # Try different detection methods
            output = run_command("opensc-tool -l")
            
            if "No smart card readers found" not in output:
                print(output)  # Report detected reader
                reader_match = re.search(r'Reader\s+([^:]+):', output)
                if reader_match:
                    reader_name = reader_match.group(1).strip()
                    logger.info(f"Smart card reader detected: {reader_name}")
                    return reader_name
                else:
                    logger.info("Reader detected but couldn't extract name")
                    return "Unknown Reader"
            
            # Try alternative detection method from Ubuntu docs
            output = run_command("pcsc_scan -n", check=False)
            if "Reader" in output and "No card" in output:
                print(output)
                reader_match = re.search(r'Reader ([^:]+):', output)
                if reader_match:
                    reader_name = reader_match.group(1).strip()
                    logger.info(f"Smart card reader detected via pcsc_scan: {reader_name}")
                    return reader_name
        except Exception as e:
            logger.warning(f"Error detecting reader: {str(e)}")
        
        if attempt < max_attempts:
            print(f"Waiting for smart card reader... (Attempt {attempt}/{max_attempts})")
            time.sleep(3)
    
    print("No smart card reader detected after multiple attempts.")
    logger.error("Failed to detect smart card reader")
    prompt_continue("Continue without a detected reader?")
    return None

def detect_smart_card():
    """
    Detect inserted smart card.
    Uses multiple detection methods from Ubuntu documentation.
    """
    print("Waiting for CAC insertion...")
    logger.info("Waiting for smart card insertion")
    
    max_attempts = 10
    attempt = 0
    
    while attempt < max_attempts:
        attempt += 1
        try:
            # Try different detection methods
            output = run_command("opensc-tool -l")
            
            if "Card present" in output:
                print("Smart card detected with opensc-tool.")
                logger.info("Smart card detected with opensc-tool")
                
                # Try to get card information
                try:
                    # Method from our script
                    card_info = run_command("pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -I", check=False)
                    if "token label" in card_info.lower():
                        print(f"Card information: {card_info.splitlines()[0]}")
                        logger.info(f"Card info: {card_info.splitlines()[0]}")
                    
                    # Alternative method from Ubuntu docs
                    card_info_alt = run_command("p11tool --list-tokens", check=False)
                    if "Token" in card_info_alt:
                        print(f"Additional card information via p11tool:")
                        for line in card_info_alt.splitlines()[:5]:  # First 5 lines
                            print(f"  {line}")
                    
                except Exception as e:
                    logger.warning(f"Could not retrieve detailed card information: {str(e)}")
                
                return True
            
            # Alternative method from Ubuntu docs
            output = run_command("pcsc_scan -n", check=False)
            if "Card found" in output:
                print("Smart card detected with pcsc_scan.")
                logger.info("Smart card detected with pcsc_scan")
                return True
                
        except Exception as e:
            logger.warning(f"Error checking for card: {str(e)}")
        
        if attempt < max_attempts:
            print(f"Waiting for CAC insertion... (Attempt {attempt}/{max_attempts})")
            time.sleep(3)
    
    print("No smart card detected after multiple attempts.")
    logger.error("Failed to detect smart card")
    prompt_continue("Continue without a detected smart card?")
    return False

def extract_certificates():
    """
    Extract certificates from CAC.
    Uses both pkcs11-tool and p11tool approaches from Ubuntu documentation.
    Returns path to extracted certificate and certificate information.
    """
    print("Extracting CAC Certificate...")
    logger.info("Attempting to extract certificates")
    
    cert_info = {}
    cert_paths = []
    
    try:
        # Method 1: Use pkcs11-tool (from original script)
        try:
            # List available certificates
            cert_list = run_command("pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -O")
            print("Certificate information from pkcs11-tool:")
            print(cert_list)
            
            # Parse certificate IDs
            cert_ids = re.findall(r'ID:\s*([0-9a-f]+)', cert_list)
            
            if cert_ids:
                # If multiple certificates, let user choose
                if len(cert_ids) > 1:
                    print("\nMultiple certificates found:")
                    for i, cert_id in enumerate(cert_ids):
                        print(f"{i+1}. Certificate ID: {cert_id}")
                    
                    selection = prompt_user(f"Select certificate (1-{len(cert_ids)})", "1")
                    try:
                        cert_id = cert_ids[int(selection) - 1]
                    except (ValueError, IndexError):
                        logger.warning(f"Invalid selection: {selection}, using first certificate")
                        cert_id = cert_ids[0]
                else:
                    cert_id = cert_ids[0]
                
                print(f"Using certificate ID: {cert_id}")
                logger.info(f"Selected certificate ID: {cert_id}")
                
                # Extract the certificate
                cert_path = f"{CONFIG['cert_dir']}/user_cert_{cert_id}.der"
                pem_path = f"{CONFIG['cert_dir']}/user_cert_{cert_id}.pem"
                
                run_command(f"pkcs11-tool --module {CONFIG['pkcs11_module']} --read-object --type cert --id {cert_id} --output-file {cert_path}")
                run_command(f"openssl x509 -inform DER -in {cert_path} -out {pem_path}")
                
                print(f"Certificate extracted to '{pem_path}'.")
                logger.info(f"Certificate extracted to {pem_path}")
                
                # Get certificate information
                cert_details = run_command(f"openssl x509 -in {pem_path} -text -noout")
                subject = re.search(r'Subject: (.+)', cert_details)
                if subject:
                    cert_info['subject'] = subject.group(1).strip()
                    print(f"Certificate Subject: {cert_info['subject']}")
                
                cert_paths.append(pem_path)
            else:
                logger.warning("No certificate IDs found with pkcs11-tool")
                print("No certificates found with pkcs11-tool, trying alternative method...")
        except Exception as e:
            logger.warning(f"Error extracting certificates with pkcs11-tool: {str(e)}")
            print(f"Could not extract certificates with pkcs11-tool: {str(e)}")
        
        # Method 2: Use p11tool (from Ubuntu documentation)
        try:
            tokens = run_command("p11tool --list-tokens", check=False)
            if "Token" in tokens:
                token_urls = re.findall(r'URL: (.+)', tokens)
                
                if token_urls:
                    # For each token URL, list and extract certificates
                    for url in token_urls:
                        certs = run_command(f"p11tool --list-all-certs '{url}'", check=False)
                        if "Object" in certs:
                            cert_urls = re.findall(r'URL: (.+)', certs)
                            
                            for i, cert_url in enumerate(cert_urls):
                                cert_id = f"p11_{i}"
                                pem_path = f"{CONFIG['cert_dir']}/p11_cert_{cert_id}.pem"
                                
                                run_command(f"p11tool --export '{cert_url}' --outfile {pem_path}", check=False)
                                
                                if os.path.exists(pem_path) and os.path.getsize(pem_path) > 0:
                                    print(f"Certificate extracted to '{pem_path}' via p11tool.")
                                    logger.info(f"Certificate extracted to {pem_path} via p11tool")
                                    
                                    # Get certificate information
                                    cert_details = run_command(f"openssl x509 -in {pem_path} -text -noout", check=False)
                                    subject = re.search(r'Subject: (.+)', cert_details)
                                    if subject:
                                        if not cert_info.get('subject'):
                                            cert_info['subject'] = subject.group(1).strip()
                                            print(f"Certificate Subject: {cert_info['subject']}")
                                    
                                    cert_paths.append(pem_path)
        except Exception as e:
            logger.warning(f"Error extracting certificates with p11tool: {str(e)}")
            print(f"Could not extract certificates with p11tool: {str(e)}")
        
        # Final check
        if cert_paths:
            print(f"\nSuccessfully extracted {len(cert_paths)} certificate(s).")
            # Return the first certificate path for compatibility with rest of script
            return cert_paths[0], cert_info
        else:
            logger.warning("No certificates extracted by any method")
            print("Failed to extract any certificates.")
            prompt_continue("Continue without certificate extraction?")
            return None, {}
            
    except Exception as e:
        logger.error(f"Error during certificate extraction process: {str(e)}")
        print(f"Error during certificate extraction: {str(e)}")
        prompt_continue("Continue without certificate extraction?")
        return None, {}

def parse_certificate_subject(subject_str):
    """
    Parse a certificate subject string into components.
    """
    components = {}
    
    # Example: CN=John Doe,OU=Department,O=Organization,C=US
    parts = subject_str.split(',')
    
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            components[key.strip()] = value.strip()
    
    return components

def configure_pam_pkcs11(cert_info):
    """
    Configure pam_pkcs11 for certificate mapping.
    Based on the Ubuntu documentation approach.
    """
    print("Configuring pam_pkcs11 certificate mapping...")
    logger.info("Configuring pam_pkcs11")
    
    pam_pkcs11_conf = f"{CONFIG['pam_pkcs11_dir']}/pam_pkcs11.conf"
    
    # Backup the configuration
    if os.path.exists(pam_pkcs11_conf):
        create_backup(pam_pkcs11_conf)
    
    # Extract username for mapping
    username = getpass.getuser()
    if cert_info and 'subject' in cert_info:
        components = parse_certificate_subject(cert_info['subject'])
        if 'CN' in components:
            suggested_username = components['CN'].split()[0].lower()
            username = prompt_user(f"Enter username to map certificate to", suggested_username)
    else:
        username = prompt_user(f"Enter username to map certificate to", username)
    
    logger.info(f"Mapping certificate to username: {username}")
    
    # Configure mapper module
    mapper_module = prompt_user(
        "Select certificate mapper (cn/digest/email/krb/ldap/ms/opensc/uid)", 
        "cn"
    )
    
    # Setup mapper options based on selection
    mapper_options = ""
    if mapper_module == "cn":
        mapper_options = """
        # CN mapper options
        cert_item = cn
        ignorecase = true
        """
    elif mapper_module == "digest":
        mapper_options = "# Digest mapper has no options"
    elif mapper_module == "uid":
        mapper_options = """
        # UID mapper options
        ignorecase = true
        """
    else:
        mapper_options = f"# Using {mapper_module} mapper with default options"
    
    # Create mapping file
    mapping_dir = f"{CONFIG['pam_pkcs11_dir']}/mapper"
    os.makedirs(mapping_dir, exist_ok=True)
    
    mapping_file = f"{mapping_dir}/{mapper_module}.map"
    if os.path.exists(mapping_file):
        create_backup(mapping_file)
    
    with open(mapping_file, "w") as f:
        f.write(f"# Certificate to user mapping for ProTEC\n")
        f.write(f"# Format depends on the mapper module used\n")
        f.write(f"# For CN mapper: CN_from_cert -> username\n\n")
        
        if 'subject' in cert_info:
            components = parse_certificate_subject(cert_info['subject'])
            if 'CN' in components:
                f.write(f"{components['CN']} -> {username}\n")
            else:
                f.write(f"# No CN found in certificate, manual mapping required\n")
                f.write(f"# CERT_SUBJECT -> {username}\n")
        else:
            f.write(f"# No certificate information available, manual mapping required\n")
            f.write(f"# CERT_SUBJECT -> {username}\n")
    
    print(f"Created mapping file at {mapping_file}")
    logger.info(f"Created mapping file at {mapping_file}")
    
    # Configure pam_pkcs11.conf
    if os.path.exists(pam_pkcs11_conf):
        # Use the existing file as a template
        with open(pam_pkcs11_conf, 'r') as f:
            config_content = f.read()
        
        # Update mapper module
        config_content = re.sub(r'use_mappers = .+;', f'use_mappers = "{mapper_module}";', config_content)
        
        # Update PKCS#11 module path
        config_content = re.sub(r'module = .+;', f'module = "{CONFIG["pkcs11_module"]}";', config_content)
        
        # Write updated configuration
        with open(pam_pkcs11_conf, 'w') as f:
            f.write(config_content)
    else:
        # Create a new configuration file
        with open(pam_pkcs11_conf, 'w') as f:
            f.write(f"""
# This file was generated by ProTEC

pam_pkcs11 {{
    # Base configuration
    debug = false;
    nullok = true;
    use_first_pass = true;
    try_first_pass = false;
    use_authtok = false;
    
    # Which PKCS #11 module to use
    module = "{CONFIG["pkcs11_module"]}";
    
    # Certificate verification options
    cert_policy = ca,signature;
    
    # Map certificate to user
    use_mappers = "{mapper_module}";
    
    # Mapper configuration
    mapper {mapper_module} {{
        {mapper_options}
    }};
}};
""")
    
    print(f"Configured pam_pkcs11.conf")
    logger.info(f"Configured pam_pkcs11.conf")
    
    # Configure event daemon
    event_conf = f"{CONFIG['pam_pkcs11_dir']}/pkcs11_eventmgr.conf"
    
    with open(event_conf, 'w') as f:
        f.write(f"""
# PKCS #11 Event Manager configuration
# Generated by ProTEC

pkcs11_eventmgr {{
    debug = false;
    polling_time = 1;
    expire_time = 0;
    
    # Event daemon actions
    event_handler = "internal";
    
    # Actions to take on events
    on_card_add {{
        action = "none";
    }};
    
    on_card_remove {{
        action = "lock_screen";
    }};
}};
""")
    
    print(f"Configured pkcs11_eventmgr.conf")
    logger.info(f"Configured pkcs11_eventmgr.conf")
    
    # Create systemd service for event manager
    service_file = "/etc/systemd/system/pkcs11_eventmgr.service"
    
    with open(service_file, 'w') as f:
        f.write("""
[Unit]
Description=PKCS#11 Event Manager
After=pcscd.service
Wants=pcscd.service

[Service]
Type=simple
ExecStart=/usr/bin/pkcs11_eventmgr
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
""")
    
    # Enable and start the service
    run_command("systemctl daemon-reload")
    run_command("systemctl enable pkcs11_eventmgr.service")
    run_command("systemctl start pkcs11_eventmgr.service")
    
    print(f"Configured and started pkcs11_eventmgr service")
    logger.info(f"Configured and started pkcs11_eventmgr service")
    
    return True

def configure_pam():
    """
    Configure PAM for CAC authentication.
    Uses the Ubuntu docs approach with pam-auth-update.
    """
    print("Configuring PAM for CAC login...")
    logger.info("Configuring PAM")
    
    # Check if Ubuntu's pam-auth-update exists
    pam_auth_update_exists = run_command("which pam-auth-update || echo ''", check=False) != ''
    
    if pam_auth_update_exists:
        # Ubuntu approach - use pam-auth-update
        print("Using Ubuntu's pam-auth-update mechanism")
        logger.info("Using pam-auth-update")
        
        # Create PAM config file for smart card auth
        pam_smartcard_file = "/usr/share/pam-configs/smartcard"
        
        with open(pam_smartcard_file, "w") as f:
            f.write("""Name: Smart card authentication
Default: yes
Priority: 128
Auth-Type: Primary
Auth:
    [success=end default=ignore] pam_pkcs11.so
Auth-Initial:
    [success=end default=ignore] pam_pkcs11.so
""")
        
        # Run pam-auth-update to enable the configuration
        run_command("pam-auth-update --package")
        
        print("PAM configured using pam-auth-update")
        logger.info("PAM configured with pam-auth-update")
    else:
        # Fallback to direct configuration
        print("pam-auth-update not found, using direct configuration")
        logger.info("Using direct PAM configuration")
        
        # Common PAM files to update
        pam_files = ["common-auth", "login", "gdm-password", "lightdm"]
        
        for pam_file in pam_files:
            pam_path = f"{CONFIG['pam_config_dir']}/{pam_file}"
            if os.path.exists(pam_path):
                create_backup(pam_path)
                
                with open(pam_path, "r") as f:
                    contents = f.readlines()
                
                # Check if configuration already exists
                if not any("pam_pkcs11.so" in line for line in contents):
                    # Find the right position to insert our configuration
                    insert_pos = 0
                    for i, line in enumerate(contents):
                        if "auth" in line and not line.strip().startswith("#"):
                            insert_pos = i
                            break
                    
                    # Insert the PKCS#11 configuration
                    contents.insert(insert_pos, "auth [success=2 default=ignore] pam_pkcs11.so\n")
                    
                    with open(pam_path, "w") as f:
                        f.writelines(contents)
                    
                    print(f"Updated PAM configuration in {pam_path}")
                    logger.info(f"Updated PAM configuration in {pam_path}")
                else:
                    print(f"PAM configuration already exists in {pam_path}")
                    logger.info(f"PAM configuration already exists in {pam_path}")
    
    # Additional PAM configuration for SSH
    ssh_pam_file = f"{CONFIG['pam_config_dir']}/sshd"
    if os.path.exists(ssh_pam_file):
        create_backup(ssh_pam_file)
        
        with open(ssh_pam_file, "r") as f:
            contents = f.readlines()
        
        # Check if configuration already exists
        if not any("pam_pkcs11.so" in line for line in contents):
            # Insert the PKCS#11 configuration after the @include common-auth line
            updated = False
            for i, line in enumerate(contents):
                if "@include common-auth" in line:
                    contents.insert(i+1, "auth       sufficient   pam_pkcs11.so\n")
                    updated = True
                    break
            
            if not updated:
                # If there's no @include common-auth, add our line at the top of the auth section
                for i, line in enumerate(contents):
                    if "auth" in line and not line.strip().startswith("#"):
                        contents.insert(i, "auth       sufficient   pam_pkcs11.so\n")
                        updated = True
                        break
            
            if updated:
                with open(ssh_pam_file, "w") as f:
                    f.writelines(contents)
                
                print(f"Updated SSH PAM configuration in {ssh_pam_file}")
                logger.info(f"Updated SSH PAM configuration in {ssh_pam_
