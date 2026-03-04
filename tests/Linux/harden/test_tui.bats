#!/usr/bin/env bats

setup() {
    export HARDEN_DIR="${BATS_TEST_DIRNAME}/../../../Linux/harden"
    export HARDEN_SCRIPT="${HARDEN_DIR}/harden.sh"
    chmod +x "$HARDEN_SCRIPT"
}

@test "TUI: Can exit via 'quit' command" {
    cd "$HARDEN_DIR"
    run expect -c "
        spawn ./harden.sh -c
        expect \"harden> \"
        send \"quit\\r\"
        expect eof
    "
    [ "$status" -eq 0 ]
}

@test "TUI: Handles invalid option gracefully" {
    cd "$HARDEN_DIR"
    run expect -c "
        spawn ./harden.sh -c
        expect \"harden> \"
        send \"invalid_option_123\\r\"
        expect \"Unrecognized option: invalid_option_123\"
        expect \"harden> \"
        send \"quit\\r\"
        expect eof
    "
    [ "$status" -eq 0 ]
}
