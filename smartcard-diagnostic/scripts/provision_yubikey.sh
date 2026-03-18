#!/bin/bash
# YubiKey Smart Card Provisioning Tool
# Provisions YubiKey for testing various smart card personalities
#
# WARNING: This script WILL ERASE existing PIV data on your YubiKey
# Use ONLY on dedicated test YubiKeys, NOT production authentication keys

set -e

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if ykman is installed
if ! command -v ykman &> /dev/null; then
    echo -e "${RED}ERROR: ykman (YubiKey Manager) is not installed${NC}"
    echo "Install with: sudo apt install yubikey-manager"
    exit 1
fi

# Check if a YubiKey is connected
if ! ykman list 2>/dev/null | grep -q .; then
    echo -e "${RED}ERROR: No YubiKey detected${NC}"
    echo "Please insert a YubiKey and try again"
    exit 1
fi

# Display current YubiKey information
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}YubiKey Smart Card Provisioning Tool${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}Detecting YubiKey...${NC}"
echo ""

# Get YubiKey info
YUBIKEY_INFO=$(ykman info 2>&1)
echo "$YUBIKEY_INFO"
echo ""

# Extract serial number if available
SERIAL=$(echo "$YUBIKEY_INFO" | grep -i "serial" | awk '{print $NF}')

# Extract device type/form factor
DEVICE_TYPE=$(echo "$YUBIKEY_INFO" | grep -i "device type" | sed 's/.*: //')
FIRMWARE=$(echo "$YUBIKEY_INFO" | grep -i "firmware" | sed 's/.*: //')

# Get current PIV info to show what will be erased
echo -e "${YELLOW}Current PIV application status:${NC}"
PIV_INFO=$(ykman piv info 2>&1 || echo "No PIV data")
echo "$PIV_INFO"
echo ""

# Check for OATH accounts (these are 2FA codes!)
OATH_COUNT=0
if ykman oath accounts list &> /dev/null; then
    OATH_ACCOUNTS=$(ykman oath accounts list 2>/dev/null)
    OATH_COUNT=$(echo "$OATH_ACCOUNTS" | grep -c . || echo "0")
fi

# Check for FIDO2 credentials
FIDO_COUNT=0
if ykman fido credentials list --pin 000000 &> /dev/null 2>&1; then
    FIDO_COUNT=$(ykman fido credentials list --pin 000000 2>/dev/null | grep -c . || echo "0")
fi

# Check if PIV has certificates
HAS_CERTS=$(echo "$PIV_INFO" | grep -c "Slot" || echo "0")

# Build identity summary for the user
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              YubiKey Identity Summary                         ║${NC}"
echo -e "${BLUE}╠════════════════════════════════════════════════════════════════╣${NC}"
if [ -n "$SERIAL" ]; then
    echo -e "${BLUE}║  Serial Number: ${YELLOW}${SERIAL}${BLUE}$(printf '%*s' $((44 - ${#SERIAL})) '')║${NC}"
fi
if [ -n "$DEVICE_TYPE" ]; then
    echo -e "${BLUE}║  Device Type:   ${YELLOW}${DEVICE_TYPE}${BLUE}$(printf '%*s' $((44 - ${#DEVICE_TYPE})) '')║${NC}"
fi
if [ -n "$FIRMWARE" ]; then
    echo -e "${BLUE}║  Firmware:      ${YELLOW}${FIRMWARE}${BLUE}$(printf '%*s' $((44 - ${#FIRMWARE})) '')║${NC}"
fi
echo -e "${BLUE}║                                                              ║${NC}"
echo -e "${BLUE}║  PIV Certificates: ${YELLOW}${HAS_CERTS}${BLUE}$(printf '%*s' $((41 - ${#HAS_CERTS})) '')║${NC}"
echo -e "${BLUE}║  OATH Accounts:    ${YELLOW}${OATH_COUNT}${BLUE}$(printf '%*s' $((41 - ${#OATH_COUNT})) '')║${NC}"
echo -e "${BLUE}║  FIDO2 Credentials:${YELLOW}${FIDO_COUNT}${BLUE}$(printf '%*s' $((41 - ${#FIDO_COUNT})) '')║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$HAS_CERTS" -gt 0 ]; then
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    ⚠️  CRITICAL WARNING  ⚠️                     ║${NC}"
    echo -e "${RED}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║  This YubiKey contains EXISTING PIV certificates!            ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║  These certificates may be used for:                         ║${NC}"
    echo -e "${RED}║  • Work authentication (VPN, email, login)                   ║${NC}"
    echo -e "${RED}║  • Two-factor authentication (2FA)                           ║${NC}"
    echo -e "${RED}║  • Code signing                                              ║${NC}"
    echo -e "${RED}║  • SSH authentication                                        ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║  Provisioning will PERMANENTLY DELETE all PIV data!          ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Existing certificates on this YubiKey:${NC}"
    # Show certificate details with subject names for identification
    while IFS= read -r line; do
        if echo "$line" | grep -q "Slot"; then
            echo -e "  ${RED}${line}${NC}"
        elif echo "$line" | grep -q "Subject"; then
            echo -e "    ${YELLOW}${line}${NC}"
        elif echo "$line" | grep -q "Issuer"; then
            echo -e "    ${line}"
        elif echo "$line" | grep -q "Not After"; then
            echo -e "    ${line}"
        fi
    done <<< "$PIV_INFO"
    echo ""
fi

if [ "$OATH_COUNT" -gt 0 ]; then
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║              ⚠️  OATH/2FA ACCOUNTS DETECTED  ⚠️                ║${NC}"
    echo -e "${RED}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║  This YubiKey has ${OATH_COUNT} OATH account(s) (TOTP/HOTP 2FA codes).   ║${NC}"
    echo -e "${RED}║  NOTE: PIV provisioning does NOT erase OATH accounts,        ║${NC}"
    echo -e "${RED}║  but a full factory reset (option 4 in menu) WILL.           ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}OATH accounts on this YubiKey:${NC}"
    echo "$OATH_ACCOUNTS" | while IFS= read -r acct; do
        echo -e "  ${RED}• ${acct}${NC}"
    done
    echo ""
fi

# Safety confirmation
echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}This script will provision your YubiKey for TESTING ONLY${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Available smart card personalities for testing:"
echo ""
echo "  1) PIV Card (NIST SP 800-73-4 Personal Identity Verification)"
echo "  2) PIV-I Card (PIV-Interoperable for federal contractors)"
echo "  3) Generic Enterprise PKI Card"
echo "  4) DoD CAC Emulation (U.S. Department of Defense Common Access Card)"
echo ""
echo -e "${RED}WARNING: This will ERASE all existing PIV data on the YubiKey!${NC}"
if [ -n "$SERIAL" ]; then
    echo -e "${RED}Target YubiKey Serial: ${SERIAL}${NC}"
fi
echo ""
read -p "Do you want to continue? Type 'YES' in capital letters to proceed: " CONFIRM

if [ "$CONFIRM" != "YES" ]; then
    echo -e "${GREEN}Operation cancelled. Your YubiKey was not modified.${NC}"
    exit 0
fi

# Double confirmation if certificates exist
if [ "$HAS_CERTS" -gt 0 ]; then
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║              FINAL CONFIRMATION REQUIRED                      ║${NC}"
    echo -e "${RED}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║  You are about to PERMANENTLY ERASE existing certificates    ║${NC}"
    echo -e "${RED}║  from this YubiKey. This action CANNOT be undone.            ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║  If these certificates are used for work login, VPN, email   ║${NC}"
    echo -e "${RED}║  signing, or SSH access, you WILL lose that access and may   ║${NC}"
    echo -e "${RED}║  need your IT department to re-provision the key.            ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    if [ -n "$SERIAL" ]; then
        read -p "Type the YubiKey serial number (${SERIAL}) to confirm: " SERIAL_CONFIRM
        if [ "$SERIAL_CONFIRM" != "$SERIAL" ]; then
            echo -e "${GREEN}Serial number mismatch. Operation cancelled. Your YubiKey was not modified.${NC}"
            exit 0
        fi
    else
        read -p "Type 'ERASE' in capital letters to confirm: " ERASE_CONFIRM
        if [ "$ERASE_CONFIRM" != "ERASE" ]; then
            echo -e "${GREEN}Operation cancelled. Your YubiKey was not modified.${NC}"
            exit 0
        fi
    fi
fi

# Select personality
echo ""
read -p "Select smart card personality (1-4): " PERSONALITY

case $PERSONALITY in
    1)
        CARD_TYPE="Standard PIV"
        SUBJECT="CN=Test User,OU=ORGANIZATIONAL_UNIT,OU=PKI,O=ORGANIZATION_NAME,C=US"
        ;;
    2)
        CARD_TYPE="PIV-I (Interoperable)"
        SUBJECT="CN=Test Contractor,OU=Contractor,OU=PKI,O=Federal Agency,C=US"
        ;;
    3)
        CARD_TYPE="Generic Enterprise PKI"
        SUBJECT="CN=Test User,OU=Engineering,O=Example Corporation,C=US"
        ;;
    4)
        CARD_TYPE="DoD CAC Emulation"
        SUBJECT="CN=DOE.JOHN.MIDDLE.1234567890,OU=CONTRACTOR,OU=PKI,OU=DoD,O=U.S. Government,C=US"
        ;;
    *)
        echo -e "${RED}Invalid selection${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${BLUE}Provisioning YubiKey as: ${CARD_TYPE}${NC}"
echo -e "${BLUE}Certificate Subject: ${SUBJECT}${NC}"
echo ""

# Reset PIV application
echo -e "${YELLOW}Step 1/5: Resetting PIV application...${NC}"
ykman piv reset -f

# Set PIN and PUK (default for testing)
echo -e "${YELLOW}Step 2/5: Setting default PIN and PUK for testing...${NC}"
# Default PIN: 123456, Default PUK: 12345678
ykman piv access change-pin -P 123456 -n 123456
ykman piv access change-puk -p 12345678 -n 12345678
echo -e "${GREEN}  PIN set to: 123456 (for testing only!)${NC}"
echo -e "${GREEN}  PUK set to: 12345678 (for testing only!)${NC}"

# Generate key in slot 9a (PIV Authentication)
echo -e "${YELLOW}Step 3/5: Generating authentication key (RSA 2048)...${NC}"
ykman piv keys generate -a RSA2048 9a /tmp/yubikey_pubkey.pem

# Generate self-signed certificate
echo -e "${YELLOW}Step 4/5: Generating self-signed certificate...${NC}"
VALID_FROM=$(date +%Y-%m-%d)
VALID_TO=$(date -d "+3 years" +%Y-%m-%d)

ykman piv certificates generate -s "$SUBJECT" \
    --valid-from "$VALID_FROM" \
    --valid-to "$VALID_TO" \
    9a /tmp/yubikey_pubkey.pem

# Verify installation
echo -e "${YELLOW}Step 5/5: Verifying installation...${NC}"
ykman piv info

# Clean up temp file
rm -f /tmp/yubikey_pubkey.pem

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Provisioning Complete                       ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${NC}"
printf "${GREEN}║  Card Type: %-49s║${NC}\n" "$CARD_TYPE"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Testing Credentials:                                        ║${NC}"
echo -e "${GREEN}║    PIN: 123456                                               ║${NC}"
echo -e "${GREEN}║    PUK: 12345678                                             ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Certificate Subject:                                        ║${NC}"
printf "${GREEN}║    %-58s║${NC}\n" "$SUBJECT"
echo -e "${GREEN}║                                                              ║${NC}"
printf "${GREEN}║  Valid: %s to %-39s║${NC}\n" "$VALID_FROM" "$VALID_TO"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Test with: opensc-tool -l"
echo "  2. View certificate: pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -O"
echo "  3. Launch Smart Card Diagnostic app"
echo ""
echo -e "${YELLOW}REMEMBER: This is a TEST configuration with default PINs!${NC}"
echo -e "${YELLOW}Do NOT use for production authentication!${NC}"
echo ""
