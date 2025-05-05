#!/bin/bash
# Integration script to use GPU key derivation with Plan C

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if required tools exist
if [ ! -f "./gpu_derive_key" ]; then
    echo -e "${RED}Error: gpu_derive_key not found. Please build it first.${NC}"
    exit 1
fi

# Default values
MAX_USER_ID=10000000
PLAN_C_PATH="./plan-c"

# Function to show help
show_help() {
    echo -e "${BLUE}GPU Key Derivation + Plan C Integration Script${NC}"
    echo -e "This script combines the GPU key derivation with Plan C to streamline the backup recovery process."
    echo ""
    echo -e "Usage: $0 [options]"
    echo ""
    echo -e "Options:"
    echo -e "  -p, --passphrase PASS   CrashPlan archive passphrase"
    echo -e "  -c, --cp-properties PATH  Path to cp.properties file with dataKeyChecksum"
    echo -e "  -m, --max-userid N      Maximum user ID to consider (default: 10000000)"
    echo -e "  -b, --plan-c PATH       Path to Plan C executable (default: ./plan-c)"
    echo -e "  -a, --archive PATH      CrashPlan backup archive path"
    echo -e "  -d, --dest PATH         Destination directory for restored files"
    echo -e "  -h, --help              Show this help message"
    echo ""
    echo -e "Example:"
    echo -e "  $0 --passphrase \"MyPassword\" --cp-properties /path/to/cp.properties --archive /path/to/backup --dest /path/to/restore"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -p|--passphrase)
            PASSPHRASE="$2"
            shift 2
            ;;
        -c|--cp-properties)
            CP_PROPERTIES="$2"
            shift 2
            ;;
        -m|--max-userid)
            MAX_USER_ID="$2"
            shift 2
            ;;
        -b|--plan-c)
            PLAN_C_PATH="$2"
            shift 2
            ;;
        -a|--archive)
            ARCHIVE_PATH="$2"
            shift 2
            ;;
        -d|--dest)
            DEST_PATH="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Check required parameters
if [ -z "$PASSPHRASE" ]; then
    echo -e "${RED}Error: Passphrase is required.${NC}"
    show_help
    exit 1
fi

if [ -z "$CP_PROPERTIES" ]; then
    echo -e "${RED}Error: cp.properties file path is required.${NC}"
    show_help
    exit 1
fi

if [ ! -f "$CP_PROPERTIES" ]; then
    echo -e "${RED}Error: cp.properties file not found at $CP_PROPERTIES${NC}"
    exit 1
fi

# Extract dataKeyChecksum from cp.properties
echo -e "${BLUE}Extracting dataKeyChecksum from $CP_PROPERTIES...${NC}"
DATA_KEY_CHECKSUM=$(grep -E "^dataKeyChecksum=" "$CP_PROPERTIES" | cut -d'=' -f2)

if [ -z "$DATA_KEY_CHECKSUM" ]; then
    echo -e "${RED}Error: Could not find dataKeyChecksum in cp.properties file.${NC}"
    exit 1
fi

echo -e "${GREEN}Found dataKeyChecksum: $DATA_KEY_CHECKSUM${NC}"

# Run GPU key derivation
echo -e "${BLUE}Running GPU key derivation...${NC}"
echo -e "This may take a while depending on your GPU and the range of user IDs to check."
echo -e "Searching through $MAX_USER_ID potential user IDs..."

GPU_RESULT=$(./gpu_derive_key "$PASSPHRASE" "$DATA_KEY_CHECKSUM" "$MAX_USER_ID")
DERIVED_KEY=$(echo "$GPU_RESULT" | grep "Key (hex):" | cut -d':' -f2 | tr -d ' ')

if [ -z "$DERIVED_KEY" ]; then
    echo -e "${RED}Error: Failed to derive key. Check the passphrase and try again.${NC}"
    exit 1
fi

echo -e "${GREEN}Successfully derived key: $DERIVED_KEY${NC}"

# Check if we want to continue with Plan C
if [ -z "$ARCHIVE_PATH" ] || [ -z "$DEST_PATH" ]; then
    echo -e "${YELLOW}Archive path or destination path not provided. Stopping after key derivation.${NC}"
    echo -e "You can use the derived key with Plan C manually:"
    echo -e "${BLUE}$PLAN_C_PATH --key $DERIVED_KEY --archive /path/to/archive restore --dest /path/to/destination${NC}"
    exit 0
fi

# Verify Plan C exists
if [ ! -f "$PLAN_C_PATH" ]; then
    echo -e "${RED}Error: Plan C executable not found at $PLAN_C_PATH${NC}"
    exit 1
fi

# Run Plan C with the derived key
echo -e "${BLUE}Running Plan C with the derived key...${NC}"
echo -e "Archive: $ARCHIVE_PATH"
echo -e "Destination: $DEST_PATH"

# Create destination directory if it doesn't exist
mkdir -p "$DEST_PATH"

# Execute Plan C
echo -e "${YELLOW}Executing: $PLAN_C_PATH --key $DERIVED_KEY --archive $ARCHIVE_PATH restore --dest $DEST_PATH${NC}"
"$PLAN_C_PATH" --key "$DERIVED_KEY" --archive "$ARCHIVE_PATH" restore --dest "$DEST_PATH"

PLAN_C_EXIT_CODE=$?

if [ $PLAN_C_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}Plan C completed successfully. Files restored to $DEST_PATH${NC}"
else
    echo -e "${RED}Plan C encountered an error (exit code: $PLAN_C_EXIT_CODE). Please check the output above.${NC}"
fi

echo -e "${BLUE}Process complete.${NC}"