#!/usr/bin/env bats

setup() {
    export HARDEN_DIR="${BATS_TEST_DIRNAME}/../../../Linux/harden"
    export HARDEN_SCRIPT="${HARDEN_DIR}/harden.sh"
    chmod +x "$HARDEN_SCRIPT"

    # We are running with sudo if we are not root
}

@test "Permissions: /etc/passwd has correct permissions" {
    # Ensure starting condition is known, we can touch it just in case
    sudo touch /etc/passwd

    # Run harden.sh skipping everything but 'perms' in TUI
    cd "$HARDEN_DIR"
    run sudo expect -c "
        spawn ./harden.sh -c
        expect \"harden> \"
        send \"perms\\r\"
        expect \"Configured permissions\"
        expect \"harden> \"
        send \"quit\\r\"
        expect eof
    "
    [ "$status" -eq 0 ]

    # Check permissions of /etc/passwd
    run sudo stat -c "%a %U %G" /etc/passwd
    [ "$status" -eq 0 ]

    # It should be 644 root root
    [ "$output" = "644 root root" ]
}

@test "Permissions: /etc/shadow has correct permissions" {
    # Create or touch shadow file
    sudo touch /etc/shadow

    # Run harden.sh skipping everything but 'perms' in TUI
    cd "$HARDEN_DIR"
    run sudo expect -c "
        spawn ./harden.sh -c
        expect \"harden> \"
        send \"perms\\r\"
        expect \"Configured permissions\"
        expect \"harden> \"
        send \"quit\\r\"
        expect eof
    "
    [ "$status" -eq 0 ]

    # Check permissions of /etc/shadow depending on distro.
    run sudo stat -c "%a %U %G" /etc/shadow
    [ "$status" -eq 0 ]

    # Ubuntu/Debian: 640 root shadow
    # RHEL: 0 root root
    if [ "$output" = "640 root shadow" ] || [ "$output" = "0 root root" ] || [ "$output" = "400 root root" ] || [ "$output" = "600 root root" ]; then
        true
    else
        # Fail
        echo "Unexpected permissions for /etc/shadow: $output"
        false
    fi
}
