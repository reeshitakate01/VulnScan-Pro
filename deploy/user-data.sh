#!/bin/bash
# EC2 user-data bootstrap for Amazon Linux 2023.
# Paste this into "Advanced details > User data" when launching the instance,
# or run it manually after SSH. Installs Docker + the compose plugin.
set -euxo pipefail

dnf update -y
dnf install -y docker git
systemctl enable --now docker
usermod -aG docker ec2-user

# Install the Docker Compose v2 plugin.
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

echo "Docker $(docker --version) and compose $(docker compose version) installed."
echo "Log out and back in (or run 'newgrp docker') so 'docker' works without sudo."
