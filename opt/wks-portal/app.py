#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# wks-portal - Web Key Service portal
#
# Copyright (C) 2026 XPD AB
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# When       Who                What
# 2026-03-10 fredrik@xpd.se     created.

# wks-portal (legacy-safe)
# - Python 3.6.8 compatible
# - Flask 0.12.x compatible (NO @app.get / @app.post)
# - No new pip deps required (uses stdlib + optional requests if present)
#
# Assumptions:
# - Portal runs as user "webkey"
# - webkey HOME points to /var/lib/gnupg/wks
# - gpg-wks-server is available at /usr/bin/gpg-wks-server
# - WKD/WKS is configured and nginx serves /.well-known/openpgpkey/ from your wks tree
#
# Environment:
#   WKS_PORTAL_BASEURL=https://wks-portal.internal.domain.cc
#   WKS_PORTAL_FROM=PGP Key Publisher <no-reply@internal.domain.cc>
#   WKS_PORTAL_TOKEN_TTL_MIN=60
#   WKS_PORTAL_DB=/var/lib/wks-portal/portal.sqlite
#   WKS_PORTAL_PENDING_DIR=/var/lib/wks-portal/pending
#   WKS_PORTAL_ALLOWED_DOMAINS=domain.cc,domain2.cc
#   WKS_PORTAL_REQUIRE_SSO=1   (optional)
#   WKS_PORTAL_SMTP_HOST=127.0.0.1
#   WKS_PORTAL_SMTP_PORT=25
#
# Optional headers (from nginx/oauth2-proxy):
#   X-User: <upn>

from __future__ import print_function

import os
import re
import json
import time
import uuid
import sqlite3
import tempfile
import subprocess
import smtplib

try:
    from urllib.parse import urlparse
except ImportError:  # pragma: no cover
    from urlparse import urlparse  # py2 fallback, not used

from email.mime.text import MIMEText
from email.utils import formatdate

from flask import Flask, request, render_template_string

APP = Flask(__name__)
APP.config["MAX_CONTENT_LENGTH"] = 512 * 1024  # 512 KB upload limit

GPG = os.environ.get("GPG", "/usr/bin/gpg")
GPG_WKS_SERVER = os.environ.get("GPG_WKS_SERVER", "/usr/bin/gpg-wks-server")

BASEURL = os.environ.get("WKS_PORTAL_BASEURL", "https://wks.example.tld").rstrip("/")
MAIL_FROM = os.environ.get("WKS_PORTAL_FROM", "PGP Key Publisher <no-reply@example.tld>")

TOKEN_TTL_MIN = int(os.environ.get("WKS_PORTAL_TOKEN_TTL_MIN", "60"))
TOKEN_TTL_SEC = TOKEN_TTL_MIN * 60

DB_PATH = os.environ.get("WKS_PORTAL_DB", "/var/lib/wks-portal/portal.sqlite")
PENDING_DIR = os.environ.get("WKS_PORTAL_PENDING_DIR", "/var/lib/wks-portal/pending")

ALLOWED_DOMAINS = [d.strip().lower() for d in os.environ.get("WKS_PORTAL_ALLOWED_DOMAINS", "").split(",") if d.strip()]
REQUIRE_SSO = os.environ.get("WKS_PORTAL_REQUIRE_SSO", "0") in ("1", "true", "yes", "on")

SMTP_HOST = os.environ.get("WKS_PORTAL_SMTP_HOST", "127.0.0.1")
SMTP_PORT = int(os.environ.get("WKS_PORTAL_SMTP_PORT", "25"))

EMAIL_RE = re.compile(r"<([^<>@\s]+@[^<>@\s]+)>")
EMAIL_RE2 = re.compile(r"\b([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)

# --- HTML templates (single-file, legacy Flask) --------------------------------

PAGE_REQUEST = u"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>WKD Publish Portal</title></head>
<body>
  <h2>Publish your OpenPGP public key (WKD)</h2>
  <p>Internal portal. Requires mailbox confirmation before publishing.</p>

  {% if err %}<p style="color:red"><b>Error:</b> {{ err }}</p>{% endif %}
  {% if msg %}<p style="color:green"><b>{{ msg }}</b></p>{% endif %}

  {% if emails %}
    <h3>Select address</h3>
    <form method="post" action="{{ url_for('request_publish') }}">
      <p>
        <select name="email" required>
          {% for e in emails %}
            <option value="{{ e }}">{{ e }}</option>
          {% endfor %}
        </select>
      </p>
      <input type="hidden" name="pending_id" value="{{ pending_id }}">
      <button type="submit">Send confirmation email</button>
    </form>
  {% else %}
    <h3>Upload public key</h3>
    <form method="post" enctype="multipart/form-data" action="{{ url_for('request_publish') }}">
      <p>
        <input type="file" name="pubkey" accept=".asc,.pgp,.txt" required>
      </p>
      <button type="submit">Continue</button>
    </form>
  {% endif %}

  <hr>
  <p style="font-size: 90%; opacity: .8;">
    Tip: export your public key as ASCII-armored (.asc).
    {% if who %}<br><b>{{ who }}</b> (Authenticated user){% endif %}
  </p>
</body>
</html>
"""

PAGE_CONFIRM = u"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>Confirmation</title></head>
<body>
  <h2>Confirmation</h2>

  {% if ok %}
    <p style="color:green"><b>Published</b></p>
    <p>Address: <b>{{ email }}</b></p>
    <p>Fingerprint: <code>{{ fpr }}</code></p>
    <p>You can now retrieve it via WKD.</p>
  {% else %}
    <p style="color:red"><b>Failed</b></p>
    <pre style="white-space: pre-wrap">{{ err }}</pre>
  {% endif %}
</body>
</html>
"""

# --- helpers -------------------------------------------------------------------

def ensure_dirs():
    if not os.path.isdir(PENDING_DIR):
        os.makedirs(PENDING_DIR, 0o750)

def db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    ensure_dirs()
    conn = db()
    cur = conn.cursor()
    cur.execute("""
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
        )
    """)
    conn.commit()
    conn.close()

def now_ts():
    return int(time.time())

def get_requested_by():
    return request.headers.get("X-User", "").strip()

def enforce_sso_if_needed():
    if not REQUIRE_SSO:
        return None
    who = get_requested_by()
    if not who:
        return "SSO required (missing X-User header)."
    return None

def allowed_email(addr):
    addr = (addr or "").strip().lower()
    if not addr or "@" not in addr:
        return False
    dom = addr.split("@", 1)[1]
    if ALLOWED_DOMAINS and dom not in ALLOWED_DOMAINS:
        return False
    return True

def run_cmd(cmd, input_bytes=None, timeout=20):
    # Python 3.6-safe subprocess with timeout
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = p.communicate(input=input_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            p.kill()
        except Exception:
            pass
        return 124, "", "timeout"
    out_s = out.decode("utf-8", "replace") if out else ""
    err_s = err.decode("utf-8", "replace") if err else ""
    return p.returncode, out_s, err_s

def parse_uids_and_fpr(asc_bytes):
    """
    Extract emails from UID lines and primary fingerprint without importing into persistent homedir.
    Uses gpg --import-options show-only, but gpg still wants a writable homedir -> tempdir.
    """
    td = tempfile.mkdtemp(prefix="wks-portal-gnupg-")
    try:
        cmd = [
            GPG, "--batch", "--no-tty",
            "--homedir", td,
            "--with-colons",
            "--import-options", "show-only",
            "--import", "-"
        ]
        rc, out, err = run_cmd(cmd, input_bytes=asc_bytes, timeout=15)
        if rc != 0:
            raise ValueError("Invalid OpenPGP public key: " + (err.strip() or out.strip() or "gpg failed"))

        fpr = None
        emails = []

        for line in out.splitlines():
            if line.startswith("fpr:") and fpr is None:
                parts = line.split(":")
                if len(parts) > 9 and parts[9]:
                    fpr = parts[9].strip()

            if line.startswith("uid:"):
                parts = line.split(":")
                if len(parts) > 9:
                    uid = parts[9]
                    m = EMAIL_RE.search(uid)
                    if m:
                        emails.append(m.group(1).strip().lower())
                    else:
                        m2 = EMAIL_RE2.search(uid or "")
                        if m2:
                            emails.append(m2.group(1).strip().lower())

        # unique preserving order
        seen = set()
        uniq = []
        for e in emails:
            if e not in seen:
                uniq.append(e)
                seen.add(e)

        if not fpr:
            raise ValueError("Could not extract fingerprint from key.")
        if not uniq:
            raise ValueError("No email address found in key UIDs.")

        return uniq, fpr
    finally:
        # best-effort cleanup
        try:
            for root, dirs, files in os.walk(td, topdown=False):
                for fn in files:
                    try:
                        os.unlink(os.path.join(root, fn))
                    except Exception:
                        pass
                for dn in dirs:
                    try:
                        os.rmdir(os.path.join(root, dn))
                    except Exception:
                        pass
            os.rmdir(td)
        except Exception:
            pass

def store_pending(asc_bytes, emails, fpr, requested_by):
    pid = uuid.uuid4().hex
    asc_path = os.path.join(PENDING_DIR, pid + ".asc")
    with open(asc_path, "wb") as f:
        f.write(asc_bytes)
    try:
        os.chmod(asc_path, 0o640)
    except Exception:
        pass

    ts = now_ts()
    exp = ts + TOKEN_TTL_SEC

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO pending (id, created_at, expires_at, requested_by, selected_email, fpr, emails_json, asc_path, used) "
        "VALUES (?,?,?,?,?,?,?,?,0)",
        (pid, ts, exp, requested_by, None, fpr, json.dumps(emails), asc_path)
    )
    conn.commit()
    conn.close()
    return pid

def load_pending(pid):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM pending WHERE id=?", (pid,))
    row = cur.fetchone()
    conn.close()
    return row

def mark_used(pid, selected_email):
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE pending SET used=1, selected_email=? WHERE id=?", (selected_email, pid))
    conn.commit()
    conn.close()

def send_mail(to_addr, subject, body):
    msg = MIMEText(body, _charset="utf-8")
    msg["From"] = MAIL_FROM
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)

    s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
    try:
        s.sendmail(MAIL_FROM, [to_addr], msg.as_string())
    finally:
        try:
            s.quit()
        except Exception:
            pass

def send_confirmation_email(to_addr, token, fpr, requested_by):
    confirm_url = BASEURL + "/confirm?token=" + token
    subject = "Confirm publishing your OpenPGP public key (WKD)"
    body = (
        "Hello!\n\n"
        "A request was made to publish an OpenPGP public key for:\n"
        "  {addr}\n\n"
        "Fingerprint:\n"
        "  {fpr}\n\n"
        "Requested by (SSO):\n"
        "  {who}\n\n"
        "To approve this publication, click:\n"
        "{url}\n\n"
        "This link expires in {ttl} minutes.\n\n"
        "If you did not request this, ignore this email.\n"
    ).format(addr=to_addr, fpr=fpr, who=(requested_by or "-"), url=confirm_url, ttl=TOKEN_TTL_MIN)
    send_mail(to_addr, subject, body)

def wks_install_key(key_path, email_addr):
    # -C points to top directory (webkey home). Keep it explicit.
    cmd = [GPG_WKS_SERVER, "-C", "/var/lib/gnupg/wks", "--install-key", key_path, email_addr]
    rc, out, err = run_cmd(cmd, timeout=30)
    return rc, (out + "\n" + err).strip()

def wks_remove_key(email_addr):
    cmd = [GPG_WKS_SERVER, "-C", "/var/lib/gnupg/wks", "--remove-key", email_addr]
    rc, out, err = run_cmd(cmd, timeout=30)
    return rc, (out + "\n" + err).strip()

# --- routes --------------------------------------------------------------------

@APP.before_first_request
def _init_once():
    init_db()

@APP.before_request
def _housekeeping():
    cleanup_pending_db()
    cleanup_pending_files()

@APP.route("/", methods=["GET"])
def index():
    # redirect to /request without external redirect to keep it simple
    return request_publish()

@APP.route("/request", methods=["GET", "POST"])
def request_publish():
    # Optional SSO gate
    sso_err = enforce_sso_if_needed()
    if sso_err:
        return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err=sso_err, msg=None), 403

    requested_by = get_requested_by()

    if request.method == "GET":
        return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err=None, msg=None, who=requested_by)

    # Step 2: user selected email for an existing pending id
    pending_id = (request.form.get("pending_id") or "").strip()
    sel_email = (request.form.get("email") or "").strip().lower()

    if pending_id and sel_email:
        row = load_pending(pending_id)
        if not row:
            return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err="Unknown or expired request.", msg=None, who=requested_by), 400
        if int(row["used"]) != 0:
            return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err="This request has already been used.", msg=None, who=requested_by), 400
        if now_ts() > int(row["expires_at"]):
            return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err="This request has expired.", msg=None, who=requested_by), 400

        try:
            emails = json.loads(row["emails_json"])
        except Exception:
            emails = []

        if sel_email not in [e.lower() for e in emails]:
            return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err="Selected email is not present in key UID list.", msg=None, who=requested_by), 400
        if not allowed_email(sel_email):
            return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err="Email domain is not allowed.", msg=None, who=requested_by), 400

        # Send confirmation mail
        try:
            # bind token -> target email
            set_selected_email(pending_id, sel_email)
            send_confirmation_email(sel_email, pending_id, row["fpr"], requested_by)
        except Exception as e:
            return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err="Failed to send confirmation email: %s" % (str(e),), msg=None, who=requested_by), 500

        return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err=None, msg="Confirmation email sent to %s." % sel_email, who=requested_by)

    # Step 1: file upload
    f = request.files.get("pubkey")
    if not f or not getattr(f, "filename", ""):
        return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err="No file selected.", msg=None, who=requested_by), 400

    asc_bytes = f.read()
    if not asc_bytes:
        return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err="Empty file.", msg=None, who=requested_by), 400

    try:
        emails, fpr = parse_uids_and_fpr(asc_bytes)
    except Exception as e:
        return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err=str(e), msg=None, who=requested_by), 400

    # Filter to allowed domains (if configured)
    if ALLOWED_DOMAINS:
        emails_f = [e for e in emails if allowed_email(e)]
    else:
        emails_f = emails

    if not emails_f:
        return render_template_string(
            PAGE_REQUEST, emails=None, pending_id=None,
            err="No UID emails matched allowed domains: %s" % ", ".join(ALLOWED_DOMAINS),
            msg=None,
            who=requested_by
        ), 400

    pid = store_pending(asc_bytes, emails_f, fpr, requested_by)

    # If only one possible address: send immediately, skip step2 UI
    if len(emails_f) == 1:
        sel = emails_f[0]
        try:
            set_selected_email(pid, sel)
            send_confirmation_email(sel, pid, fpr, requested_by)
        except Exception as e:
            return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err="Failed to send confirmation email: %s" % (str(e),), msg=None, who=requested_by), 500
        return render_template_string(PAGE_REQUEST, emails=None, pending_id=None, err=None, msg="Confirmation email sent to %s." % sel, who=requested_by)

    # Otherwise show chooser (step2)
    return render_template_string(PAGE_REQUEST, emails=emails_f, pending_id=pid, err=None, msg=None, who=requested_by)

@APP.route("/confirm", methods=["GET"])
def confirm_publish():
    token = (request.args.get("token") or "").strip()
    if not token:
        return render_template_string(PAGE_CONFIRM, ok=False, err="Missing token."), 400

    row = load_pending(token)
    if not row:
        return render_template_string(PAGE_CONFIRM, ok=False, err="Unknown token."), 400
    if int(row["used"]) != 0:
        return render_template_string(PAGE_CONFIRM, ok=False, err="This token has already been used."), 400
    if now_ts() > int(row["expires_at"]):
        return render_template_string(PAGE_CONFIRM, ok=False, err="This token has expired."), 400

    # Determine which email to publish for:
    # - In this model, the token corresponds to the request, and the target email was the recipient.
    # - We don't store target email in DB at send-time to keep it simple; infer from the recipient clicking it
    #   is not possible in HTTP. So we require that the request sent confirmation already selected one email.
    #
    # To make this deterministic: we store selected_email when mail is sent.
    #
    # Backward compat: if selected_email is NULL, we cannot know which was targeted -> fail.
    selected_email = row["selected_email"]
    if not selected_email:
        # If you want, you can store selected_email at send-time in request_publish() before sending.
        # For now, fail safe.
        return render_template_string(PAGE_CONFIRM, ok=False, err="Token has no bound target email (server-side state missing)."), 500

    asc_path = row["asc_path"]
    fpr = row["fpr"]

    if not os.path.exists(asc_path):
        return render_template_string(PAGE_CONFIRM, ok=False, err="Pending key file not found on server."), 500

    rc, out = wks_install_key(asc_path, selected_email)
    if rc != 0:
        return render_template_string(PAGE_CONFIRM, ok=False, err="Publish failed: " + out), 500

    mark_used(token, selected_email)
    return render_template_string(PAGE_CONFIRM, ok=True, email=selected_email, fpr=fpr), 200

# Optional admin endpoint (legacy-safe)
@APP.route("/admin/remove", methods=["POST"])
def admin_remove():
    # Very minimal; protect with nginx allowlist or oauth2-proxy group policy.
    email_addr = (request.form.get("email") or "").strip().lower()
    if not allowed_email(email_addr):
        return "invalid email", 400
    rc, out = wks_remove_key(email_addr)
    if rc != 0:
        return out, 500
    return out or "ok", 200


def set_selected_email(pid, email_addr):
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE pending SET selected_email=? WHERE id=?", (email_addr, pid))
    conn.commit()
    conn.close()


def cleanup_pending_db():
    ts = now_ts()
    conn = db()
    cur = conn.cursor()

    # ta bort utgångna eller redan använda requests äldre än 24h
    cur.execute("DELETE FROM pending WHERE expires_at < ?", (ts,))
    cur.execute("DELETE FROM pending WHERE used = 1 AND created_at < ?", (ts - 86400,))

    conn.commit()
    conn.close()


def cleanup_pending_files():
    # ta bort orphaned .asc-filer äldre än 24h
    cutoff = now_ts() - 86400

    try:
        names_in_db = set()
        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT asc_path FROM pending")
        for row in cur.fetchall():
            if row[0]:
                names_in_db.add(os.path.abspath(row[0]))
        conn.close()

        for fn in os.listdir(PENDING_DIR):
            path = os.path.abspath(os.path.join(PENDING_DIR, fn))
            try:
                st = os.stat(path)
            except OSError:
                continue

            if not os.path.isfile(path):
                continue

            if path not in names_in_db and int(st.st_mtime) < cutoff:
                try:
                    os.unlink(path)
                except OSError:
                    pass
    except Exception:
        pass


# --- main ----------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    # Dev only. In prod use gunicorn.
    APP.run(host="127.0.0.1", port=9010, debug=False)
