# WKS Portal

WKS Portal contains the components needed to set up WKD/WKS for PGP keys:

- **WKD** — Web Key Directory: serves published public keys over HTTPS
- **WKS** — Web Key Service / Web Key Server: handles email-based key submission
- **Portal** — an internal web application for publishing new keys after OIDC-authenticated, mailbox-confirmed validation

The portal is intended to run internally, for example:

```text
https://wks-portal.internal.domain.cc
```

## Repository layout

```
etc/
  nginx/nginx.conf                    — nginx config (WKD public vhost + portal vhost)
  oauth2-proxy/wks-portal.cfg         — oauth2-proxy OIDC config
  postfix/main.cf                     — Postfix config (relay + WKS pipe transport)
  postfix/master.cf.addon             — Postfix master.cf additions for WKS pipe
  postfix/relay_recipients            — allowed relay recipients
  postfix/transport                   — transport map routing key-submission to gpg-wks-server
  systemd/system/wks-portal.service  — systemd unit for the portal (gunicorn)
  systemd/system/oauth2-proxy.service — systemd unit for oauth2-proxy
opt/
  wks-portal/app.py                   — Flask application (Python 3.6+, Flask 0.12+)
usr/
  local/sbin/wks-receive              — shell script: feeds incoming WKS emails to gpg-wks-server
var/
  lib/gnupg/wks/domain.cc/policy     — WKS policy file (one per domain)
  lib/gnupg/wks/domain.cc/submission-address — WKS submission address (one per domain)
  spool/cron/webkey                   — crontab for the webkey user
```

## Overview

The portal is designed for environments where users authenticate through an OIDC-protected reverse proxy before submitting or publishing PGP keys.

The expected deployment model is:

- The portal runs as the `webkey` user
- `webkey` owns the WKS/GnuPG working directory
- `nginx` serves the WKD/WKS files under `/.well-known/openpgpkey/` (public vhost)
- `nginx` proxies the internal portal through `oauth2-proxy` (internal vhost)
- `oauth2-proxy` authenticates users via OIDC and sets the `X-User` header
- Pending key submissions are stored in a local SQLite database

## Request flow

### Web portal (HTTP-based submission)

1. User navigates to the internal portal (authentication enforced by oauth2-proxy via nginx)
2. User uploads an ASCII-armored public key (`.asc`, max 512 KB)
3. Portal parses UIDs and fingerprint using `gpg --import-options show-only` in a temporary homedir (no persistent keyring write)
4. If the key has multiple UIDs matching allowed domains, the user selects one; otherwise the single address is used automatically
5. A one-time confirmation link (valid for `WKS_PORTAL_TOKEN_TTL_MIN` minutes, default 60) is sent to the target email address
6. The key owner clicks the link in their mailbox
7. Portal calls `gpg-wks-server --install-key` to publish the key into the WKD tree
8. The key is immediately available via WKD at `https://openpgpkey.domain.cc/.well-known/openpgpkey/<domain>/hu/<hash>`

### WKS email-based submission

1. MUA sends a key submission email to `key-submission@domain.cc`
2. Postfix routes it via the `wks` transport to `/usr/local/sbin/wks-receive`
3. `wks-receive` calls `gpg-wks-server --receive --send` which handles the WKS challenge/response protocol and publishes the key

### Automatic cleanup

Expired and used pending requests are cleaned up on every incoming request. The cron job removes any WKS requests that the server has not yet confirmed.

## Prerequisites

The examples below assume a RHEL-compatible system using `yum`.

## Installation

### Create the `webkey` user

```bash
useradd -r -m -d /var/lib/gnupg/wks webkey
```

### Install required packages

```bash
yum install -y \
  gnupg2 \
  gnupg2-smime \
  sqlite \
  sqlite3 \
  python3-flask \
  python3-flask-script \
  python3-flask-restful \
  python3-flask-login \
  python3-flask-healthz \
  python3-aniso8601 \
  python3-werkzeug \
  python3-itsdangerous \
  python3-gunicorn \
  python3-click \
  nginx \
  nginx-all-modules \
  nginx-filesystem \
  nginx-mod-stream \
  nginx-mod-mail \
  nginx-mod-http-xslt-filter \
  nginx-mod-http-perl \
  nginx-mod-http-image-filter \
  mpdecimal \
  libwebp \
  gd \
  swaks \
  mailx \
  perl-NTLM \
  perl-GSSAPI \
  perl-Authen-SASL \
  perl-Authen-DigestMD5 \
  perl-Net-DNS \
  perl-Digest-HMAC
```

Note: depending on distribution and repository, the SQLite command-line package may be named either `sqlite`, `sqlite3`, or be provided by another SQLite package. The `sqlite3` command must be available on the system.

### Install application files

```bash
install -d -o webkey -g webkey -m 750 /opt/wks-portal
install -o webkey -g webkey -m 640 opt/wks-portal/app.py /opt/wks-portal/app.py

install -o root -g root -m 755 usr/local/sbin/wks-receive /usr/local/sbin/wks-receive
```

## SELinux

Allow nginx to connect to the local `oauth2-proxy` and portal upstream:

```bash
setsebool -P httpd_can_network_connect 1
```

## GnuPG / WKS directory

The `webkey` user's home directory must point to the WKS working tree.

### Initialize the WKS directory

```bash
mkdir -p /var/lib/gnupg/wks
chown webkey:nginx /var/lib/gnupg/wks
chmod 751 /var/lib/gnupg/wks
```

The directory must be accessible to nginx for serving WKD material while keeping the GnuPG tree restricted.

### Per-domain setup

For each domain, create a `policy` file and a `submission-address` file:

```bash
mkdir -p /var/lib/gnupg/wks/domain.cc
echo "key-submission@domain.cc" > /var/lib/gnupg/wks/domain.cc/submission-address
touch /var/lib/gnupg/wks/domain.cc/policy
chown -R webkey:webkey /var/lib/gnupg/wks/domain.cc
chmod 640 /var/lib/gnupg/wks/domain.cc/submission-address
chmod 640 /var/lib/gnupg/wks/domain.cc/policy
```

An empty `policy` file indicates that the WKS server accepts key submissions. Add `mailbox-only` if only exact mailbox matches should be accepted.

## Database setup

Create the portal database directory:

```bash
mkdir -p /var/lib/wks-portal
```

Create the SQLite database:

```bash
sqlite3 /var/lib/wks-portal/portal.sqlite <<'EOF'
CREATE TABLE IF NOT EXISTS pending (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  requested_by TEXT,
  selected_email TEXT,
  fpr TEXT NOT NULL,
  emails_json TEXT NOT NULL,
  asc_path TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
EOF
```

The application also creates the table automatically on first start via `init_db()`.

## Pending key directory

Create a directory for pending key submissions:

```bash
mkdir -p /var/lib/wks-portal/pending
chown -R webkey:webkey /var/lib/wks-portal
chmod 750 /var/lib/wks-portal
chmod 640 /var/lib/wks-portal/portal.sqlite
chmod 750 /var/lib/wks-portal/pending
```

## Postfix configuration

Postfix is used both for sending confirmation emails and for receiving WKS key submissions via the `key-submission@` address.

### main.cf

Copy `etc/postfix/main.cf` to `/etc/postfix/main.cf`, adjusting `myhostname`, `relayhost`, `relay_domains`, `mynetworks`, and SASL credentials for your environment.

### WKS pipe transport

Append `etc/postfix/master.cf.addon` to `/etc/postfix/master.cf`:

```bash
cat etc/postfix/master.cf.addon >> /etc/postfix/master.cf
```

This adds a `wks` transport that pipes incoming key submissions to `wks-receive` running as `webkey`.

### Relay recipients and transport map

```bash
install -m 644 etc/postfix/relay_recipients /etc/postfix/relay_recipients
install -m 644 etc/postfix/transport /etc/postfix/transport

postmap /etc/postfix/relay_recipients
postmap /etc/postfix/transport
```

`relay_recipients` allowlists `key-submission@domain.cc`. `transport` routes it to the `wks:` transport.

### Reload Postfix

```bash
systemctl reload postfix
```

## nginx configuration

Copy `etc/nginx/nginx.conf` to `/etc/nginx/nginx.conf`.

The configuration defines two virtual hosts:

| Hostname | Purpose |
|---|---|
| `openpgpkey.domain.cc` | Public WKD endpoint — serves `/.well-known/openpgpkey/` files, CORS enabled, no authentication |
| `wks-portal.internal.domain.cc` | Internal portal — restricted to `10.0.0.0/8`, requires oauth2-proxy authentication |

Adjust `server_name`, SSL certificate paths, and the network allowlist (`allow`) to match your environment.

```bash
nginx -t && systemctl reload nginx
```

## oauth2-proxy configuration

oauth2-proxy provides OIDC authentication in front of the portal. The example config in `etc/oauth2-proxy/wks-portal.cfg` is configured for ADFS as the OIDC provider.

1. Download `oauth2-proxy` and install it to `/opt/oauth2-proxy/oauth2-proxy`
2. Copy and edit the config file:

```bash
install -d /etc/oauth2-proxy
install -m 600 etc/oauth2-proxy/wks-portal.cfg /etc/oauth2-proxy/wks-portal.cfg
```

3. Set `client_id`, `client_secret`, `cookie_secret`, and `oidc_issuer_url` for your IdP

The proxy listens on `127.0.0.1:4180` and passes the authenticated user's UPN via `X-Auth-Request-Email`, which nginx forwards to the portal as `X-User`.

## Systemd services

Install and enable both units:

```bash
install -m 644 etc/systemd/system/wks-portal.service /etc/systemd/system/
install -m 644 etc/systemd/system/oauth2-proxy.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now oauth2-proxy
systemctl enable --now wks-portal
```

Edit `wks-portal.service` to set the `Environment=` lines appropriate for your deployment before enabling.

## Cron jobs

The `webkey` user requires one cron job:

```bash
crontab -u webkey <<'EOF'
#
# minute hour day-of-month month day-of-week
# 0-59   0-23 1-31         1-12  0-7
#
# Remove unconfirmed WKS requests after their expiry time.
25 0 * * * /usr/bin/gpg-wks-server --cron >/dev/null 2>&1

# Clean up old submitted, but not confirmed, PGP keys in /var/lib/wks-portal/pending.
17 3 * * * /usr/bin/find /var/lib/wks-portal/pending -type f -name '*.asc' -mtime +2 -size -1M -delete
EOF
```

## Environment variables

Set these in `wks-portal.service` (or equivalent):

| Variable | Required | Description |
|---|---|---|
| `WKS_PORTAL_BASEURL` | Yes | Base URL of the portal (used in confirmation email links) |
| `WKS_PORTAL_FROM` | Yes | Sender address for confirmation emails |
| `WKS_PORTAL_TOKEN_TTL_MIN` | No | Confirmation link lifetime in minutes (default: `60`) |
| `WKS_PORTAL_DB` | Yes | Path to the SQLite database file |
| `WKS_PORTAL_PENDING_DIR` | Yes | Directory for storing pending `.asc` files |
| `WKS_PORTAL_ALLOWED_DOMAINS` | Yes | Comma-separated list of allowed email domains |
| `WKS_PORTAL_REQUIRE_SSO` | No | Set to `1` to reject requests without the `X-User` header (default: `0`) |
| `WKS_PORTAL_SMTP_HOST` | No | SMTP relay host (default: `127.0.0.1`) |
| `WKS_PORTAL_SMTP_PORT` | No | SMTP relay port (default: `25`) |
| `GPG` | No | Path to `gpg` binary (default: `/usr/bin/gpg`) |
| `GPG_WKS_SERVER` | No | Path to `gpg-wks-server` binary (default: `/usr/bin/gpg-wks-server`) |

Example (also in `wks-portal.service`):

```bash
WKS_PORTAL_BASEURL=https://wks-portal.internal.domain.cc
WKS_PORTAL_FROM="PGP Key Publisher <no-reply@domain.cc>"
WKS_PORTAL_TOKEN_TTL_MIN=60
WKS_PORTAL_DB=/var/lib/wks-portal/portal.sqlite
WKS_PORTAL_PENDING_DIR=/var/lib/wks-portal/pending
WKS_PORTAL_ALLOWED_DOMAINS=domain.cc,domain2.cc
WKS_PORTAL_REQUIRE_SSO=1
WKS_PORTAL_SMTP_HOST=127.0.0.1
WKS_PORTAL_SMTP_PORT=25
```

## Application endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Redirects to `/request` |
| `GET` | `/request` | Upload form |
| `POST` | `/request` | Upload key or select target email |
| `GET` | `/confirm?token=<id>` | Confirm and publish key (called from email link) |
| `POST` | `/admin/remove` | Remove a published key (`email=<addr>`); protect with nginx allowlist |

## Runtime assumptions

The portal assumes:

- `gpg-wks-server` is available at `/usr/bin/gpg-wks-server`
- The portal runs as user `webkey`
- The `webkey` user's home directory is `/var/lib/gnupg/wks`
- nginx serves `/.well-known/openpgpkey/` from the WKS publication tree
- Authentication is handled before traffic reaches the portal
- The portal receives the authenticated user's identity through the `X-User` header set by nginx/oauth2-proxy

## Security notes

- The internal portal is network-restricted to `10.0.0.0/8` in the example nginx config; adjust to match your internal network
- Key files are parsed using a temporary, isolated GPG homedir that is cleaned up immediately; keys are never imported into a persistent keyring during the upload phase
- Confirmation tokens are single-use and time-limited
- Do not expose the portal directly to untrusted clients; authentication relies on forwarded headers from the reverse proxy

## Copyright

Copyright (C) 2026 XPD AB

## License

SPDX-License-Identifier: AGPL-3.0-or-later

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
