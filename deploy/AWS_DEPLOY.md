# Deploying VulnScan Pro on AWS (EC2, locked-down demo)

This deploys a **safe, public demo**: the scanner runs with a bundled
deliberately-vulnerable lab, and scanning is **locked to that lab only**
(`SCAN_ALLOWLIST`). The lab is internal — never exposed to the internet — so
nobody can point your server at third-party sites. That keeps you within
**AWS's Acceptable Use Policy** (no unauthorised scanning of others).

> Architecture: `[ public :80 ] → scanner container → (internal) → vulnlab container`

---

## 0. Cost & safety

- A **t3.micro** is covered by the AWS **free tier** for 12 months (750 hrs/mo).
  Outside free tier it's ~\$8–9/mo. **Stop or terminate the instance when you're
  done** to avoid charges.
- Keep `SCAN_ALLOWLIST` set (the compose file does this). Do **not** expose the
  lab's port 5001 to the internet.

---

## 1. Launch the EC2 instance

1. EC2 → **Launch instance**.
2. **AMI:** Amazon Linux 2023. **Type:** `t3.micro` (free tier).
3. **Key pair:** create/download one (you'll SSH with it).
4. **Network / Security group** — add inbound rules:
   | Type | Port | Source |
   |------|------|--------|
   | SSH  | 22   | **My IP** |
   | HTTP | 80   | Anywhere (0.0.0.0/0) |
   *(Do NOT open 5001.)*
5. *(Optional)* **Advanced details → User data:** paste the contents of
   [`deploy/user-data.sh`](user-data.sh) to auto-install Docker on boot.
6. Launch, then note the instance's **Public IPv4 address**.

## 2. Connect

```bash
ssh -i /path/to/your-key.pem ec2-user@<PUBLIC_IP>
```

## 3. Install Docker (skip if you used the user-data script)

```bash
sudo dnf update -y
sudo dnf install -y docker git
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user
# compose v2 plugin
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
newgrp docker   # or log out and back in
```

## 4. Get the code

The repo is public, so just clone it — no credentials needed:

```bash
git clone https://github.com/reeshitakate01/VulnScan-Pro.git
cd VulnScan-Pro
```

*(If you later make the repo private, clone it with a fine-grained, read-only
GitHub token instead: `git clone https://<YOUR_TOKEN>@github.com/reeshitakate01/VulnScan-Pro.git`.)*

## 5. Set the secret

```bash
cp deploy/.env.aws.example .env
# put a strong random key in .env:
sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$(openssl rand -hex 32)/" .env
```

## 6. Build & run

```bash
docker compose -f deploy/docker-compose.aws.yml up -d --build
```

First build takes a few minutes. Check it's up:

```bash
docker compose -f deploy/docker-compose.aws.yml ps
docker compose -f deploy/docker-compose.aws.yml logs -f scanner   # Ctrl+C to stop tailing
```

## 7. Use it

Open **http://<PUBLIC_IP>** in a browser:
1. **Register** an account (first visit).
2. The scan box is **pre-filled** with the allowed lab target — just click
   **Initiate Scan**.
3. Watch the live log, then explore the results, exports and history.

Trying to scan anything other than the lab returns a clear
*"locked-down demo"* message — by design.

## 8. Everyday commands

```bash
# update to the latest code
git pull && docker compose -f deploy/docker-compose.aws.yml up -d --build
# stop (keeps data volumes)
docker compose -f deploy/docker-compose.aws.yml down
# view logs
docker compose -f deploy/docker-compose.aws.yml logs --tail=100 scanner
```

---

## Optional: HTTPS with a domain (recommended if you'll share the link widely)

Login over plain HTTP sends the password in cleartext. If you have a domain,
point an `A` record at the EC2 IP, open **port 443** in the security group, and
add a Caddy reverse proxy (automatic Let's Encrypt). Create `deploy/Caddyfile`:

```
your-domain.com {
    reverse_proxy scanner:5000
}
```

…and add this service to the compose file, then change the scanner's `ports`
to only expose internally (`expose: ["5000"]` instead of `ports: ["80:5000"]`):

```yaml
  caddy:
    image: caddy:2
    ports: ["80:80", "443:443"]
    volumes:
      - ./deploy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
    depends_on: [scanner]
    restart: unless-stopped
# and add  caddy-data:  under the top-level `volumes:` key
```

---

## Security checklist
- [ ] `SCAN_ALLOWLIST` is set (compose does this) — scanning is lab-only
- [ ] Port 5001 is **not** in the security group (lab stays internal)
- [ ] `SECRET_KEY` is a strong random value in `.env` (never committed)
- [ ] SSH (22) restricted to **your IP**
- [ ] Instance **stopped/terminated** when not demoing

## Teardown
`docker compose -f deploy/docker-compose.aws.yml down -v` to remove containers +
data, then **terminate the EC2 instance** in the console to stop all charges.
