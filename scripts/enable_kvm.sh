#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

# Hardware acceleration for the Android emulator on GitHub's Linux runners.
echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' |
    sudo tee /etc/udev/rules.d/99-kvm4all.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --name-match=kvm
