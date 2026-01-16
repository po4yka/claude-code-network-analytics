#!/bin/bash
# Hook: Validate network scanning targets
# Warns when scanning external (non-private) IP addresses

# Extract target from command arguments
TARGET="$1"

# Check if target looks like an IP
if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    # Extract first octet
    FIRST_OCTET=$(echo "$TARGET" | cut -d. -f1)
    SECOND_OCTET=$(echo "$TARGET" | cut -d. -f2)

    # Check for private IP ranges (RFC 1918)
    IS_PRIVATE=false

    # 10.0.0.0/8
    if [[ "$FIRST_OCTET" == "10" ]]; then
        IS_PRIVATE=true
    fi

    # 172.16.0.0/12
    if [[ "$FIRST_OCTET" == "172" ]] && [[ "$SECOND_OCTET" -ge 16 ]] && [[ "$SECOND_OCTET" -le 31 ]]; then
        IS_PRIVATE=true
    fi

    # 192.168.0.0/16
    if [[ "$FIRST_OCTET" == "192" ]] && [[ "$SECOND_OCTET" == "168" ]]; then
        IS_PRIVATE=true
    fi

    # 127.0.0.0/8 (localhost)
    if [[ "$FIRST_OCTET" == "127" ]]; then
        IS_PRIVATE=true
    fi

    # Warn if external IP
    if [[ "$IS_PRIVATE" == "false" ]]; then
        echo "⚠️  WARNING: Target appears to be an external IP address ($TARGET)"
        echo "   Ensure you have authorization to scan this target."
        echo "   Unauthorized scanning may be illegal in your jurisdiction."
        echo ""
        read -p "Continue with scan? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
fi

exit 0
