# Ubuntu ProTEC Troubleshooting Guide

This document provides solutions for common issues that may be encountered when using Ubuntu ProTEC for CAC authentication.

## Smart Card Reader Issues

### Reader Not Detected

**Symptoms:**
- Error message: "No smart card readers found"
- Script fails at the card reader detection stage

**Solutions:**
1. Ensure the reader is properly connected to a USB port
2. Try a different USB port, preferably one directly on the computer (not through a hub)
3. Check if the pcscd service is running:
   ```bash
   sudo systemctl status pcscd
   ```
   If it's not running, start it:
   ```bash
   sudo systemctl start pcscd
   sudo systemctl enable pcscd
   ```
4. Verify the required packages are installed:
   ```bash
   sudo apt install opensc pcscd libccid
   ```
5. Run `pcsc_scan` to see if the system can detect your reader

### Reader Intermittently Disconnects

**Symptoms:**
- Reader works initially but stops responding
- Authentication failures after initial success

**Solutions:**
1. Check for power management issues by disabling USB autosuspend:
   ```bash
   echo "SUBSYSTEM==\"usb\", ATTRS{idVendor}==\"YOUR_VENDOR_ID\", ATTRS{idProduct}==\"YOUR_PRODUCT_ID\", ATTR{power/autosuspend}=\"-1\"" | sudo tee /etc/udev/rules.d/99-disable-autosuspend.rules
   ```
   Replace `YOUR_VENDOR_ID` and `YOUR_PRODUCT_ID` with the values from `lsusb` for your reader
2. Restart the pcscd service:
   ```bash
   sudo systemctl restart pcscd
   ```
3. Consider using a powered USB hub if the issue persists

## Smart Card Authentication Issues

### Card Detected But Certificate Not Extracted

**Symptoms:**
- Card reader is detected and card presence is confirmed
- Error when attempting to extract certificate

**Solutions:**
1. Make sure the card is properly inserted (chip-side up, fully seated)
2. Try cleaning the card contacts with isopropyl alcohol and a soft cloth
3. Run the pkcs11-tool command manually to see detailed errors:
   ```bash
   pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -O
   ```
4. Try the alternative p11tool method:
   ```bash
   p11tool --list-tokens
   p11tool --list-all-certs "pkcs11:..."
   ```
5. Check if your card is locked due to incorrect PIN attempts
6. For YubiKey testing, verify PIV mode is enabled:
   ```bash
   ykman info
   ```

### Authentication Failed at Login

**Symptoms:**
- CAC is detected but authentication fails at login screen
- "Authentication failed" message appears

**Solutions:**
1. Verify PAM configuration:
   ```bash
   cat /etc/pam.d/common-auth | grep pkcs11
   ```
   The line `auth [success=2 default=ignore] pam_pkcs11.so` should be present
2. Check PAM logs:
   ```bash
   grep pam_pkcs11 /var/log/auth.log
   ```
3. Verify the certificate mapping:
   ```bash
   pklogin_finder debug
   ```
4. Check the pam_pkcs11 configuration:
   ```bash
   cat /etc/pam_pkcs11/pam_pkcs11.conf
   ```
5. Verify certificate mapping files:
   ```bash
   cat /etc/pam_pkcs11/mapper/*.map
   ```
6. As a last resort, restore the backup of your PAM config if available:
   ```bash
   sudo cp /path/to/protec_backups/common-auth.TIMESTAMP /etc/pam.d/common-auth
   ```

## Browser Integration Issues

### Certificate Not Available in Browser

**Symptoms:**
- CAC working for system authentication but not showing up in browser
- "No certificates found" when accessing CAC-enabled websites

**Solutions:**
1. Verify the PKCS#11 module is loaded in your browser:
   
   **For Firefox:**
   - Open Firefox
   - Go to Preferences → Privacy & Security → Security Devices
   - Check if "CAC Module" is listed
   
   **For Chrome/Edge:**
   - Run the modutil command to check:
     ```bash
     modutil -dbdir sql:~/.config/google-chrome/ -list
     ```
2. Make sure pcscd is running while the browser is open:
   ```bash
   sudo systemctl restart pcscd
   ```
3. Try manually adding the module:
   ```bash
   modutil -dbdir sql:~/.mozilla/firefox/*.default-release -add "CAC Module" -libfile /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
   ```
4. Import your certificate into the browser's certificate store:
   ```bash
   certutil -A -d sql:~/.mozilla/firefox/*.default/ -n "CAC Certificate" -t "P,," -i /path/to/certificate.pem
   ```

### Browser Crashes When Accessing CAC Sites

**Symptoms:**
- Browser crashes immediately when attempting to access CAC-authenticated sites
- Error related to NSS or security modules

**Solutions:**
1. Reset the browser's security database:
   
   **For Firefox:**
   ```bash
   rm ~/.mozilla/firefox/*.default/cert9.db
   rm ~/.mozilla/firefox/*.default/key4.db
   ```
   Then restart Firefox and reconfigure the CAC module
   
   **For Chrome/Edge:**
   ```bash
   rm -rf ~/.pki/nssdb
   mkdir -p ~/.pki/nssdb
   modutil -dbdir sql:~/.pki/nssdb -create
   ```
2. Update to the latest browser version
3. Check for conflicting extensions that might interfere with certificate processing

## 802.1X Network Issues

### Failed to Connect to 802.1X Network

**Symptoms:**
- Network configuration completes but device won't connect
- Authentication failures reported in logs

**Solutions:**
1. Check wpa_supplicant logs:
   ```bash
   journalctl -u wpa_supplicant@wlan0 | tail -n 50
   ```
2. Verify the wpa_supplicant configuration file:
   ```bash
   cat /etc/wpa_supplicant/wpa_supplicant-wlan0.conf
   ```
3. Ensure the certificate paths are correct and readable
4. Manually restart the wpa_supplicant service:
   ```bash
   sudo systemctl restart wpa_supplicant@wlan0
   ```
5. If using NetworkManager, check connection details:
   ```bash
   nmcli connection show "CAC-8021X-SSID"
   ```
6. Verify network support for EAP-TLS (some networks only support PEAP or EAP-TTLS)

### Connection Drops Frequently

**Symptoms:**
- Successfully connects but drops connection periodically
- Requires reinsertion of CAC to reconnect

**Solutions:**
1. Check for conflicts with NetworkManager:
   ```bash
   sudo systemctl status NetworkManager
   ```
2. Consider editing the NetworkManager configuration to avoid conflicts:
   ```bash
   echo "[keyfile]
   unmanaged-devices=interface-name:wlan0" | sudo tee -a /etc/NetworkManager/NetworkManager.conf
   sudo systemctl restart NetworkManager
   ```
3. Increase debugging in wpa_supplicant:
   ```bash
   sed -i 's/ctrl_interface=.*/ctrl_interface=DIR=\/var\/run\/wpa_supplicant GROUP=netdev\nap_scan=1\nfast_reauth=1\neapol_version=2\neventhistory=1/' /etc/wpa_supplicant/wpa_supplicant-wlan0.conf
   ```

## SSH Authentication Issues

### SSH Key Not Recognized

**Symptoms:**
- SSH authentication fails with "No suitable authentication method found"
- PKCS#11 provider errors in SSH

**Solutions:**
1. Verify SSH configuration:
   ```bash
   cat ~/.ssh/config | grep PKCS11Provider
   ```
2. Extract the public key to check it's valid:
   ```bash
   ssh-keygen -D /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
   ```
3. Make sure the public key is correctly installed in `~/.ssh/authorized_keys` on the remote system
4. Enable verbose SSH logging for more details:
   ```bash
   ssh -v -I /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so user@remote-host
   ```
5. Check for correct permissions on SSH files:
   ```bash
   chmod 700 ~/.ssh
   chmod 600 ~/.ssh/config
   ```

### SSH Connection Drops After Card Removal

**Symptoms:**
- SSH session terminates when CAC is removed
- Unable to reconnect without reinserting card

**Solutions:**
1. Configure SSH to use agent forwarding to maintain connections:
   ```bash
   echo "AddKeysToAgent yes" >> ~/.ssh/config
   ```
2. Use ssh-agent to cache credentials temporarily:
   ```bash
   eval $(ssh-agent)
   ssh-add -s /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
   ```
3. For extended sessions, consider using tools like `screen` or `tmux` on the remote server

## System-Wide Issues

### Updates Break CAC Authentication

**Symptoms:**
- CAC authentication stops working after a system update
- Configuration files may have been overwritten

**Solutions:**
1. Check if PAM configurations were modified by package updates:
   ```bash
   grep -r "pam_pkcs11" /etc/pam.d/
   ```
2. Restore from backup if available:
   ```bash
   sudo cp /path/to/protec_backups/common-auth.TIMESTAMP /etc/pam.d/common-auth
   ```
3. Re-run the ProTEC script to reconfigure the system:
   ```bash
   sudo ./protec.py
   ```

### Log Collection for Troubleshooting

If you're experiencing persistent issues, collect logs to help identify the problem:

```bash
mkdir -p ~/protec-logs
sudo cp /var/log/auth.log ~/protec-logs/
sudo journalctl -u pcscd > ~/protec-logs/pcscd.log
sudo journalctl -u wpa_supplicant > ~/protec-logs/wpa_supplicant.log
grep -r "pkcs11" /var/log/* 2>/dev/null > ~/protec-logs/pkcs11-mentions.log
tar -czf protec-logs.tar.gz ~/protec-logs
```

## Testing With Yubi
