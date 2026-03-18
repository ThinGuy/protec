#!/bin/bash
# YubiKey Testing Menu - Simple interface for provisioning test cards

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_menu() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          YubiKey Smart Card Testing Menu                      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  1) Provision YubiKey for Testing"
    echo "  2) View Current YubiKey Status"
    echo "  3) Test Smart Card Detection"
    echo "  4) Reset YubiKey PIV to Factory Defaults"
    echo ""
    echo "  9) Help & Documentation"
    echo "  0) Exit"
    echo ""
}

view_status() {
    echo -e "${BLUE}Current YubiKey Status:${NC}"
    echo ""
    if ! command -v ykman &> /dev/null; then
        echo -e "${RED}ykman not installed${NC}"
        echo "Install with: sudo apt install yubikey-manager"
        return
    fi

    if ! ykman list 2>/dev/null | grep -q .; then
        echo -e "${YELLOW}No YubiKey detected${NC}"
        return
    fi

    echo -e "${BLUE}Device Info:${NC}"
    ykman info
    echo ""

    echo -e "${BLUE}PIV Application:${NC}"
    ykman piv info 2>&1 || echo "PIV not available or not configured"
    echo ""

    # Show OATH account count (without listing details for safety)
    if ykman oath accounts list &> /dev/null 2>&1; then
        OATH_COUNT=$(ykman oath accounts list 2>/dev/null | grep -c . || echo "0")
        echo -e "${BLUE}OATH Accounts: ${OATH_COUNT}${NC}"
    fi
    echo ""
}

test_detection() {
    echo -e "${BLUE}Testing Smart Card Detection:${NC}"
    echo ""

    echo "1. Reader Detection:"
    if command -v opensc-tool &> /dev/null; then
        opensc-tool -l 2>&1 || echo "  No readers found"
    else
        echo -e "  ${YELLOW}opensc-tool not installed. Install with: sudo apt install opensc${NC}"
    fi
    echo ""

    echo "2. Card Objects:"
    if command -v pkcs11-tool &> /dev/null; then
        pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -O 2>&1 | head -20 || echo "  No objects found"
    else
        echo -e "  ${YELLOW}pkcs11-tool not installed. Install with: sudo apt install opensc${NC}"
    fi
    echo ""
}

reset_yubikey() {
    echo -e "${RED}════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  WARNING: This will reset the PIV application on your     ${NC}"
    echo -e "${RED}  YubiKey to factory defaults.                             ${NC}"
    echo -e "${RED}                                                           ${NC}"
    echo -e "${RED}  All PIV keys, certificates, and PIN/PUK will be erased. ${NC}"
    echo -e "${RED}  OATH (2FA) and FIDO2 credentials are NOT affected.      ${NC}"
    echo -e "${RED}════════════════════════════════════════════════════════════${NC}"
    echo ""

    if ! command -v ykman &> /dev/null; then
        echo -e "${RED}ykman not installed${NC}"
        return
    fi

    if ! ykman list 2>/dev/null | grep -q .; then
        echo -e "${YELLOW}No YubiKey detected${NC}"
        return
    fi

    # Show what's on the key
    echo -e "${YELLOW}Current YubiKey identity:${NC}"
    SERIAL=$(ykman info | grep -i "serial" | awk '{print $NF}')
    if [ -n "$SERIAL" ]; then
        echo -e "  Serial: ${SERIAL}"
    fi
    echo ""

    echo -e "${YELLOW}Current PIV status:${NC}"
    ykman piv info 2>&1 || echo "  No PIV data"
    echo ""

    read -p "Type 'RESET PIV' to confirm PIV reset: " CONFIRM

    if [ "$CONFIRM" != "RESET PIV" ]; then
        echo -e "${GREEN}Reset cancelled. Your YubiKey was not modified.${NC}"
        return
    fi

    echo ""
    echo -e "${YELLOW}Resetting PIV application...${NC}"
    ykman piv reset -f

    echo ""
    echo -e "${GREEN}PIV application reset to factory defaults.${NC}"
    echo -e "${GREEN}Default PIN: 123456 | Default PUK: 12345678${NC}"
}

show_help() {
    clear
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Smart Card Testing Help${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Purpose:"
    echo "  This tool helps you provision a YubiKey for testing smart card"
    echo "  authentication scenarios without risking production credentials."
    echo ""
    echo "Requirements:"
    echo "  - YubiKey 5 Series (or compatible with PIV support)"
    echo "  - yubikey-manager installed (ykman)"
    echo "  - opensc and pcsc-lite installed (for detection testing)"
    echo ""
    echo "Safety Features:"
    echo "  - Shows YubiKey serial number before any changes"
    echo "  - Displays all existing certificates and 2FA accounts"
    echo "  - Requires typing 'YES' in capitals to proceed"
    echo "  - Requires serial number confirmation if certs exist"
    echo "  - Only resets PIV app (OATH/FIDO2 untouched by provisioning)"
    echo ""
    echo "Available Test Personalities:"
    echo "  1. Standard PIV   - NIST SP 800-73-4 compliant card"
    echo "  2. PIV-I           - PIV-Interoperable for contractors"
    echo "  3. Enterprise PKI  - Standard corporate smart card"
    echo "  4. DoD CAC         - U.S. military Common Access Card"
    echo ""
    echo "After Provisioning:"
    echo "  - Test detection with Smart Card Diagnostic app"
    echo "  - Verify with: opensc-tool -l"
    echo "  - View cert: pkcs11-tool -O"
    echo ""
    echo "Test Credentials (all personalities):"
    echo "  - PIN: 123456"
    echo "  - PUK: 12345678"
    echo "  - 3-year self-signed certificate"
    echo ""
    echo "To Restore:"
    echo "  - Use option 4 to reset PIV to factory defaults"
    echo "  - Re-provision for your actual use case with your IT dept"
    echo ""
}

while true; do
    show_menu
    read -p "Select option: " choice

    case $choice in
        1)
            bash "$SCRIPT_DIR/provision_yubikey.sh"
            read -p "Press Enter to continue..."
            ;;
        2)
            view_status
            read -p "Press Enter to continue..."
            ;;
        3)
            test_detection
            read -p "Press Enter to continue..."
            ;;
        4)
            reset_yubikey
            read -p "Press Enter to continue..."
            ;;
        9)
            show_help
            read -p "Press Enter to continue..."
            ;;
        0)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            sleep 1
            ;;
    esac
done
