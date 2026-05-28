#!/bin/bash

# Update HOME_NET to include Docker networks
sed -i "s/HOME_NET: .*/HOME_NET: \"[192.168.0.0\/16,10.0.0.0\/8,172.16.0.0\/12]\"/" /etc/suricata/suricata.yaml

# Enable X-Forwarded-For parsing and set mode to overwrite
# This replaces the proxy's IP with the real client IP in alerts
sed -i -e '/http:/,/^$/ s/xff: .*/xff:\n          enabled: yes\n          mode: overwrite\n          header: X-Forwarded-For/' /etc/suricata/suricata.yaml

# Add custom rules path to rule-files
sed -i '/rule-files:/a \  - /etc/suricata/rules/custom/local.rules' /etc/suricata/suricata.yaml

# Enable drop action (IPS mode features in IDS mode, even if passive, it generates drop alerts)
sed -i 's/drop:\n  alerts: .*/drop:\n  alerts: yes/' /etc/suricata/suricata.yaml || true
