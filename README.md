# Ubuntu ProTEC

[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-orange)](https://ubuntu.com/)
[![Security](https://img.shields.io/badge/Security-CAC%20Ready-brightgreen)](https://ubuntu.com/security)

## Ubuntu Pro-enabled Trusted Environment for CAC

ProTEC is an automation tool designed to seamlessly integrate U.S. Department of Defense (DoD) Common Access Cards (CAC) with Ubuntu systems. Leveraging Ubuntu's security-first design and robust compliance features, ProTEC ensures reliable, secure access for CAC-enabled environments while meeting stringent government standards.

![ProTEC Banner](https://assets.ubuntu.com/v1/8dd99b80-Shield_ubuntu.svg)

## Features

ProTEC streamlines CAC configuration for:

- **System Login Authentication** via PAM (Pluggable Authentication Modules)
- **Browser Integration** for Firefox, Google Chrome, and Microsoft Edge
- **802.1X Network Access Control** for both wired and wireless environments
- **SSH Authentication** with PKCS#11 support

By automating these configurations, ProTEC simplifies deployment, reduces human error, and ensures secure identity-based access across Ubuntu systems.

## Security Components

### 1. Login Authentication
- Protects user logins by requiring CAC credentials instead of relying on local passwords
- Ensures only authorized personnel can access the system
- Reduces risk of password compromise through CAC-based identity verification

### 2. Network Access (802.1X)
- Secures both wired and wireless network connections by authenticating devices with CAC certificates
- Ensures network connections are encrypted and controlled based on verified identity
- Supports both NetworkManager and wpa_supplicant configurations

### 3. Browser-Based Authentication
- Configures Firefox, Chrome, and Edge to enforce CAC-based authentication for secure web portals and DoD-specific websites
- Reduces phishing risks by ensuring only CAC-verified identities can access sensitive sites
- Sets up proper NSS database configuration for certificate integration

### 4. SSH Authentication
- Enables certificate-based SSH authentication without passwords
- Configures PKCS#11 module integration for SSH clients
- Provides guidance for authorized_keys setup on remote systems

## Prerequisites

- Ubuntu 20.04 LTS or newer
- Ubuntu Pro subscription (for full compliance features)
- Root access for installation
- CAC reader and card for authentication
- For development: YubiKey 5 Series or compatible smart card

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/ThinGuy/protec.git
   cd protec
   ```

2. Run the installation script with root privileges:
   ```bash
   sudo ./protec.py
   ```

3. Follow the interactive prompts to complete installation and configuration.

## Detailed Documentation

For comprehensive documentation, see the [ProTEC.md](ProTEC.md) file included in this repository.

## Development Testing

For testing without an actual CAC card, see [Appendix II: Using YubiKey 5 Security Keys for CAC Testing](ProTEC.md#appendix-ii-using-yubikey-5-security-keys-for-cac-testing) in the documentation.

## Troubleshooting

See the [Troubleshooting Guide](troubleshooting.md) for solutions to common issues.

## Compatibility

ProTEC has been tested with the following hardware:

| Smart Card Readers | Smart Cards/Tokens |
|-------------------|-------------------|
| Identiv SCR3310v2.0 | Yubico YubiKey 5 Series |
| Omnikey 3121 | Gemalto IDPrime Smart Cards |
| ACR39U-H1 | Athena IDProtect Cards |
|  | SafeNet eToken 5110 |
|  | Feitian ePass2003 |

For official CAC usage, please consult your organization's security guidelines.

## Security Compliance

ProTEC builds on Ubuntu's strong security foundation, leveraging:

- **Ubuntu Security Guide (USG)**: A powerful hardening tool that aligns Ubuntu systems with DISA STIG standards
- **FIPS 140-2/140-3 Cryptographic Modules**: Ensures all cryptographic operations comply with federal security requirements
- **Canonical's Pro-Enabled Services**: Extends Ubuntu's security with proactive patching, automated updates, and critical CVE protection

## Contributing

Contributions are welcome! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Support

For commercial support and questions about Ubuntu Pro, please contact [Canonical](https://ubuntu.com/contact-us).

For issues with this tool, please [file an issue](https://github.com/ThinGuy/protec/issues) on the GitHub repository.

---

© 2025 Canonical Ltd. • [canonical.com](https://canonical.com) • [ubuntu.com](https://ubuntu.com)
