#!/bin/sh -x

export DEBIAN_FRONTEND="noninteractive"

# Disable periodic activities of apt
systemctl stop apt-daily.timer
systemctl disable apt-daily.timer
systemctl mask apt-daily.service
systemctl daemon-reload

cat > /etc/apt/apt.conf.d/10disable-periodic <<EOF
APT::Periodic::Enable "0";
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF

# Disable release-upgrades
sed -i.bak 's/^Prompt=.*$/Prompt=never/' /etc/update-manager/release-upgrades

# Update the package list
apt-get -y update

# Upgrade all installed packages incl. kernel and kernel headers
apt-get -y dist-upgrade -o Dpkg::Options::="--force-confnew"
