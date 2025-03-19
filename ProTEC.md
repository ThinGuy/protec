# Ubuntu ProTEC

## Ubuntu Pro-enabled Trusted Environment for CAC

**Version 1.1**

## Contents

[ProTEC Overview](#protec-overview)

[What Does ProTEC Secure?](#what-does-protec-secure)
- [Login Authentication](#1-login-authentication)
- [Network Access (802.1X)](#2-network-access-8021x)
- [Browser-Based Authentication](#3-browser-based-authentication)

[Key Features](#key-features)
- [Automated CAC Detection](#automated-cac-detection)
- [Certificate Extraction](#certificate-extraction)
- [PAM Integration](#pam-integration)
- [Browser Support](#browser-support)
- [802.1X Support for Wired & Wireless Networks](#8021x-support-for-wired--wireless-networks)
- [Flexible User Mapping](#flexible-user-mapping)
- [Configuration Backup and Restore](#configuration-backup-and-restore)
- [Comprehensive Logging](#comprehensive-logging)

[Ubuntu and Security Compliance](#ubuntu-and-security-compliance)

[Why ProTEC?](#why-protec)

[Use Cases](#use-cases)

[Getting Started](#getting-started)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Verifying Installation](#verifying-installation)

[Troubleshooting](#troubleshooting)

[Appendix I. Recommended Hardware for Testing](#appendix-i-recommended-hardware-for-testing)
- [Recommended Smart Cards for Testing](#recommended-smart-cards-for-testing)
- [Recommended Smart Card Readers](#recommended-smart-card-readers)
- [Best Overall Choice: YubiKey 5 Series](#best-overall-choice-yubikey-5-series)

[Appendix II. Using YubiKey 5 Security Keys for CAC Testing](#appendix-ii-using-yubikey-5-security-keys-for-cac-testing)
- [Step-by-Step YubiKey Setup](#step-by-step-yubikey-setup)

# ProTEC Overview {#protec-overview}

ProTEC is an automation tool designed to seamlessly integrate U.S. Department of Defense (DoD) Common Access Cards (CAC) with Ubuntu systems. Leveraging Ubuntu's security-first design and robust compliance features, ProTEC ensures reliable, secure access for CAC-enabled environments while meeting stringent government standards.

ProTEC streamlines CAC configuration for:

* System Login Authentication via PAM (Pluggable Authentication Modules)  
* Browser Integration for Firefox, Google Chrome, and Microsoft Edge  
* 802.1X Network Access Control for both wired and wireless environments

By automating these configurations through the Ubuntu Pro Client, ProTEC simplifies deployment, reduces human error, and ensures secure identity-based access across Ubuntu systems.

---

## What Does ProTEC Secure? {#what-does-protec-secure}

### 1. Login Authentication {#1-login-authentication}

* ProTECs user logins by requiring CAC credentials instead of relying on local passwords.  
* Ensures only authorized personnel can access the system.  
* Reduces risk of password compromise through CAC-based identity verification.

### 2. Network Access (802.1X) {#2-network-access-8021x}

* Secures both wired and wireless network connections by authenticating devices with CAC certificates.  
* Ensures network connections are encrypted and controlled based on verified identity.

### 3. Browser-Based Authentication {#3-browser-based-authentication}

* Configures Firefox, Chrome, and Edge to enforce CAC-based authentication for secure web portals and DoD-specific websites.  
* Reduces phishing risks by ensuring only CAC-verified identities can access sensitive sites.

---

## Key Features {#key-features}

### Automated CAC Detection {#automated-cac-detection}

Guides users through connecting a CAC reader and inserting their card. Detects and confirms card presence before proceeding.

### Certificate Extraction {#certificate-extraction}

Securely extracts CAC certificates for authentication, ensuring proper identification for system login and web access.

### PAM Integration {#pam-integration}

Automatically configures PAM to support CAC authentication for system logins, ensuring compliance with DoD security protocols.

### Browser Support {#browser-support}

Seamlessly configures Firefox, Chrome, and Edge to enable CAC-based authentication for government portals and secure websites.

### 802.1X Support for Wired & Wireless Networks {#8021x-support-for-wired--wireless-networks}

Ensures secure network access with WPA2-Enterprise/EAP-TLS for enhanced ProTECion in CAC environments.

### Flexible User Mapping {#flexible-user-mapping}

Supports mapping all CAC users to a common non-privileged local account, reducing the need for extensive local account management.

### Configuration Backup and Restore {#configuration-backup-and-restore}

Automatically creates backups of critical system configuration files before modification, allowing for safe rollback if needed.

### Comprehensive Logging {#comprehensive-logging}

Maintains detailed logs of all operations for troubleshooting and audit purposes, helping administrators diagnose issues.

## Ubuntu and Security Compliance {#ubuntu-and-security-compliance}

ProTEC builds on Ubuntu's strong security foundation, leveraging:

* **Ubuntu Security Guide (USG)**: A powerful hardening tool that aligns Ubuntu systems with DISA STIG (Security Technical Implementation Guide) standards, simplifying DoD compliance.  
* **FIPS 140-2/140-3 Cryptographic Modules**: Ensures all cryptographic operations comply with federal security requirements.  
* **Canonical's Pro-Enabled Services**: Extends Ubuntu's security with proactive patching, automated updates, and critical CVE ProTECion.

## Why ProTEC? {#why-protec}

* **Secure by Design**: Built for Ubuntu's robust security model with minimal attack surface.  
* **Effortless Automation**: Reduces configuration complexity, ensuring faster deployment and improved accuracy.  
* **Compliance Ready**: Aligns with DISA STIG requirements and DoD security protocols.  
* **Flexible and Scalable**: Designed to support environments ranging from single devices to enterprise-scale Ubuntu deployments.
* **Resilient Configuration**: Backup and restore capabilities prevent system lockouts during configuration.

### Use Cases {#use-cases}

* DoD Workstations and Field Devices  
* CAC-Enabled Air-Gapped Systems  
* Secure Ubuntu Environments in Defense and Government Organizations  
* Contractors and Vendors Working with Federal Agencies

### Getting Started {#getting-started}

#### Prerequisites {#prerequisites}

Before running ProTEC, ensure you have:

1. Ubuntu 20.04 LTS or newer
2. Ubuntu Pro subscription activated
3. Administrative (sudo) access
4. Compatible CAC reader connected
5. Valid CAC card or testing hardware (see Appendix for testing options)

#### Installation {#installation}

ProTEC is delivered as a lightweight Python utility that automates CAC setup. To deploy:

1. Clone the repository:
   ```
   git clone https://github.com/canonical/ubuntu-protec.git
   cd ubuntu-protec
   ```

2. Run the setup script with root privileges:
   ```
   sudo ./protec.py
   ```

3. Follow the interactive prompts to:
   - Connect your CAC reader
   - Insert your CAC
   - Configure authentication preferences
   - Set up 802.1X network access (if desired)

#### Verifying Installation {#verifying-installation}

After installation, the script automatically runs verification tests to ensure proper configuration. You can also manually verify:

1. **CAC Reader Detection**:
   ```
   opensc-tool -l
   ```

2. **Smart Card Status**:
   ```
   pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -T
   ```

3. **PAM Configuration**:
   ```
   grep pam_pkcs11 /etc/pam.d/common-auth
   ```

4. **Browser Configuration** (Firefox example):
   ```
   modutil -dbdir sql:~/.mozilla/firefox/*.default-release -list
   ```

### Troubleshooting {#troubleshooting}

For common issues and solutions, refer to the detailed [Troubleshooting Guide](troubleshooting.md).

Basic troubleshooting steps:

1. Check logs in `/var/log/auth.log` for PAM authentication issues
2. Verify the pcscd service is running: `systemctl status pcscd`
3. Test card detection with: `pcsc_scan`
4. For browser issues, check the PKCS#11 module configuration in your browser settings
5. For network issues, check: `journalctl -u wpa_supplicant@wlan0`

# Appendix I. Recommended Hardware for Testing {#appendix-i-recommended-hardware-for-testing}

For testing CAC functionality without an actual CAC, the following smart cards and tools are widely used for development and testing purposes for both CAC and non-CAC smartcards:

### Recommended Smart Cards for Testing {#recommended-smart-cards-for-testing}

1. #### Yubico YubiKey 5 Series {#yubico-yubikey-5-series}

   1. Supports PIV (Personal Identity Verification), which mirrors CAC functionality.  
   2. Excellent for testing PKCS\#11, certificate-based authentication, and secure key storage.  
   3. Compatible with opensc, pcscd, and pkcs11-tool.

2. #### Gemalto IDPrime Smart Cards {#gemalto-idprime-smart-cards}

   1. Widely used for PKI (Public Key Infrastructure) testing.  
   2. Offers a strong match for DoD CAC testing scenarios.

3. #### Athena IDProtect Cards {#athena-idprotect-cards}

   1. It supports PKCS\#11 and is widely supported by open-source smart card tools.

4. #### SafeNet eToken 5110 {#safenet-etoken-5110}

   1. USB-based token that behaves like a smart card with PKCS\#11 support.  
   2. Ideal for testing secure authentication methods.

5. #### Feitian ePass2003 {#feitian-epass2003}

   1. Budget-friendly option that supports PKCS\#11 and is compatible with opensc.

### Recommended Smart Card Readers {#recommended-smart-card-readers}

For best compatibility with Ubuntu and opensc, the following readers are well tested:

1. #### Identiv SCR3310v2.0

   1. It is Reliable, widely supported, and works well in CAC environments.

2. #### Omnikey 3121

   1. This is Affordable and extensively tested with CAC software.

3. #### ACR39U-H1

   1. Known for solid Linux support with pcscd.

## Best Overall Choice: YubiKey 5 Series {#best-overall-choice-yubikey-5-series}

YubiKey's PIV support makes it an ideal substitute for CAC testing and development, including:

* Certificate Management  
* PKCS\#11 Support  
* Two-factor authentication  
* SSH Key Storage

# Appendix II. Using YubiKey 5 Security Keys for CAC Testing {#appendix-ii-using-yubikey-5-security-keys-for-cac-testing}

⚠️ This will erase any existing PIV keys and certificates ⚠️

⚠️ This will erase any existing PIV keys and certificates ⚠️ 

⚠️ This will erase any existing PIV keys and certificates ⚠️ 

## Step-by-Step YubiKey Setup {#step-by-step-yubikey-setup}

### Step 1: Enable PIV Mode on Your YubiKey {#step-1-enable-piv-mode-on-your-yubikey}

PIV mode is supported by default on YubiKey 5 devices. Verify with:

```
ykman info
```

If PIV is not enabled:

```
ykman piv reset
```

### Step 2: Generate a Certificate for Testing {#step-2-generate-a-certificate-for-testing}

We'll create a self-signed certificate for testing.

```
ykman piv generate-key 9a public_key.pem
ykman piv generate-certificate --subject "CN=Test User" 9a public_key.pem
```

This certificate will act as your CAC test credential.

### Step 3: Extract and Test Certificates {#step-3-extract-and-test-certificates}

The protec.py script already handles extraction using the pkcs11-tool. Verify detection with:

```
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -O
```

If successful, your YubiKey should appear with certificate details.

### Step 4: Map the YubiKey for System Login {#step-4-map-the-yubikey-for-system-login}

Update PAM to leverage the YubiKey's PKCS\#11 driver:

```
echo "auth [success=2 default=ignore] pam_pkcs11.so" | sudo tee -a /etc/pam.d/common-auth
```

### Step 5: Configure Your Browsers {#step-5-configure-your-browsers}

For Firefox, Chrome, and Edge:

```
modutil -dbdir sql:~/.mozilla/firefox/*.default-release -add "YubiKey CAC" -libfile /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
modutil -dbdir sql:~/.config/google-chrome/ -add "YubiKey CAC" -libfile /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
modutil -dbdir sql:~/.config/microsoft-edge/ -add "YubiKey CAC" -libfile /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```

### Step 6: Test Your Setup {#step-6-test-your-setup}

* Test system login using your YubiKey as a CAC alternative.  
* Use DoD-like websites or PKI-only websites to confirm certificate authentication.

### Step 7: 802.1X Network Testing {#step-7-802-1x-network-testing}

If your network supports WPA2-Enterprise/EAP-TLS, your YubiKey can authenticate as a CAC substitute.

## Recommended Testing Resources {#recommended-testing-resources}

* Yubico PIV Tool (ykman piv) for direct management  
* opensc-tool for card reader details  
* pkcs11-tool for extracting certificates and managing keys

|  ![Canonical Logo](https://assets.ubuntu.com/v1/8dd99b80-Shield_ubuntu.svg)  |  [canonical.com](https://canonical.com)  |  [ubuntu.com](https://ubuntu.com) |
| :---: | :---: | :---: |

© 2025 Canonical Ltd. All rights reserved.
