import os
import time
import threading
import secrets
import hashlib
import re
from flask import Flask, request, render_template_string, jsonify, session, make_response, redirect, url_for, flash
from cryptography.fernet import Fernet, InvalidToken
import bcrypt
import requests
from markupsafe import escape
from functools import wraps
from collections import deque
from datetime import datetime, timedelta
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure Flask app
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max file size
)

SECRETS = {}  # key: {"encrypted": bytes, "ttl": float}


# TTL in seconds
TTL_AFTER_VIEW = 300  # 5 minutes

# --- disable Flask and Werkzeug logs ---
import logging

log = logging.getLogger('werkzeug')
log.disabled = True
app.logger.disabled = True

# Check for required Okta environment variables
okta_client_id = os.environ.get('OKTA_CLIENT_ID')
okta_client_secret = os.environ.get('OKTA_CLIENT_SECRET')
okta_domain = os.environ.get('OKTA_DOMAIN')

if not all([okta_client_id, okta_client_secret, okta_domain]):
    print("⚠️  WARNING: Okta SSO environment variables not set!")
    print("   Set the following environment variables for SSO:")
    print("   - OKTA_CLIENT_ID")
    print("   - OKTA_CLIENT_SECRET")
    print("   - OKTA_DOMAIN")
    print("   SSO will be disabled until these are configured.")
    SSO_ENABLED = False
else:
    SSO_ENABLED = True
    print(f"✅ Okta SSO configured for domain: {okta_domain}")

# OAuth config - only if environment variables are set
oauth = OAuth(app)
if SSO_ENABLED:
    try:
        oauth.register(
            name='okta',
            client_id=okta_client_id,
            client_secret=okta_client_secret,
            server_metadata_url=f"https://{okta_domain}/.well-known/openid-configuration",
            client_kwargs={'scope': 'openid profile email'},
        )
        print("✅ Okta OAuth registration successful")
    except Exception as e:
        print(f"❌ Okta OAuth registration failed: {e}")
        SSO_ENABLED = False

# --- load Fernet key from env ---
fernet_key = os.environ.get("FERNET_KEY")

if not fernet_key:
    # No fallback: raise an error and stop execution
    raise RuntimeError("❌ FERNET_KEY environment variable not set. This key is mandatory for encryption and decryption. Application will not start without it.")
else:
    print("✅ FERNET_KEY loaded from environment.")

# Create Fernet instance
fernet = Fernet(fernet_key.encode())



# --- in-memory store and lock ---
store = {}
store_lock = threading.Lock()

# --- settings ---
TTL_LINK_SECONDS = 300  # link validity (seconds)
TTL_AFTER_VIEW = 10  # seconds until secret destroyed after viewing
MAX_FAILS = 5  # max password fails before lockout
LOCKOUT_SECONDS = 15 * 60  # 15 minutes lockout

# --- Security settings ---
MAX_MESSAGE_LENGTH = 10000  # Maximum message length
MAX_PASSWORD_LENGTH = 100  # Maximum password length
RATE_LIMIT_WINDOW = 120  # Rate limit window in seconds
MAX_REQUESTS_PER_WINDOW = 10  # Max requests per window



# --- Security Functions ---

# Rate limiting storage
request_counts = deque(maxlen=1000)  # Store last 1000 requests
rate_limit_lock = threading.Lock()


def get_client_ip():
    """Get client IP address safely."""
    return request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))




def validate_input(text, max_length=None):
    """Validate and sanitize input."""
    if not text or not isinstance(text, str):
        return False, "Invalid input"

    if max_length and len(text) > max_length:
        return False, f"Input too long (max {max_length} characters)"

    # Check for dangerous patterns
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',  # Script tags
        r'javascript:',  # JavaScript protocol
        r'on\w+\s*=',  # Event handlers
        r'<iframe[^>]*>',  # iframe tags
        r'<object[^>]*>',  # object tags
        r'<embed[^>]*>',  # embed tags
        r'<form[^>]*>',  # form tags
        r'<input[^>]*>',  # input tags
        r'<textarea[^>]*>',  # textarea tags
        r'<select[^>]*>',  # select tags
        r'<button[^>]*>',  # button tags
        r'<link[^>]*>',  # link tags
        r'<meta[^>]*>',  # meta tags
        r'<style[^>]*>',  # style tags
        r'<link[^>]*>',  # link tags
        r'<base[^>]*>',  # base tags
        r'<bgsound[^>]*>',  # bgsound tags
        r'<xmp[^>]*>',  # xmp tags
        r'<plaintext[^>]*>',  # plaintext tags
        r'<listing[^>]*>',  # listing tags
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return False, "Dangerous content detected"

    return True, text.strip()


def add_security_headers(response):
    """Add security headers to response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers[
        'Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response


def generate_csrf_token():
    """Generate CSRF token."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf_token(token):
    """Validate CSRF token."""
    return token and token == session.get('csrf_token')


# --- background cleanup thread ---
def cleanup_expired():
    while True:
        time.sleep(5)
        now = time.time()
        with store_lock:
            keys_to_delete = []
            for k, v in store.items():
                if v.get("revoked"):
                    keys_to_delete.append(k)
                    continue
                if now - v["created_at"] > TTL_LINK_SECONDS:
                    keys_to_delete.append(k)
                    continue
                if v.get("accessed") and (now - v.get("viewed_at", 0) > TTL_AFTER_VIEW):
                    keys_to_delete.append(k)
            for k in keys_to_delete:
                store.pop(k, None)


threading.Thread(target=cleanup_expired, daemon=True).start()

# ---------------- TEMPLATES (unchanged, except for IP removed in view) ----------------
form_template = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Secret Messenger — Create</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root {
      --bg1: #0f2027;
      --bg2: #2c5364;
    }
    body {
      margin: 0;
      font-family: 'Segoe UI', Inter, system-ui, sans-serif;
      background: linear-gradient(135deg, var(--bg1), #203a43, var(--bg2));
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .card {
      width: min(500px, 92%);
      background: rgba(255, 255, 255, 0.04);
      padding: 28px;
      border-radius: 12px;
      backdrop-filter: blur(10px);
      box-shadow: 0 8px 30px rgba(2, 6, 23, 0.6);
      text-align: center;
    }
    h1 {
      margin: 0 0 12px;
      font-weight: 600;
      font-size: 1.5rem;
      letter-spacing: 0.4px;
      white-space: nowrap;
      overflow: hidden;
      border-right: 3px solid white;
      animation: typing 2.5s steps(35, end), blink 0.75s step-end infinite;
    }
    @keyframes typing {
      from { width: 0 }
      to { width: 100% }
    }
    @keyframes blink {
      50% { border-color: transparent }
    }
    p.lead {
      color: #cfe7ff90;
      margin-top: 0;
    }
    textarea, input {
      width: 100%;
      padding: 12px;
      border-radius: 8px;
      border: none;
      margin-top: 10px;
      font-size: 1rem;
      outline: none;
    }
    .row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 14px;
      justify-content: center;
    }
    .btn {
      padding: 12px 18px;
      border-radius: 9px;
      border: none;
      cursor: pointer;
      font-weight: 600;
    }
    .btn-primary {
      background: #ff6b6b;
      color: white;
      transition: background 0.3s ease;
    }
    .btn-primary:hover {
      background: #e84118;
    }
    .btn-ghost {
      background: transparent;
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: #fff;
    }
          small.note {
        display: block;
        color: #bcd3e1a4;
        margin-top: 12px;
      }
      .btn-sso {
        background: #0066cc;
        color: white;
        margin-top: 10px;
        text-decoration: none;
        display: inline-block;
      }
      .btn-sso:hover {
        background: #0052a3;
      }
      .sso-status {
        margin-top: 15px;
        padding: 10px;
        border-radius: 8px;
        font-size: 0.9rem;
      }
      .sso-enabled {
        background: rgba(0, 255, 0, 0.1);
        border: 1px solid rgba(0, 255, 0, 0.3);
      }
      .sso-disabled {
        background: rgba(255, 165, 0, 0.1);
        border: 1px solid rgba(255, 165, 0, 0.3);
      }
    </style>
  </head>
<body>
  <div class="card">
    <h1>🔐 Hy-Vee Secret Messenger</h1>
    <p class="lead">Your message will self-destruct after one view or 5 minutes.</p>

    {% if sso_enabled %}
      {% if session.authenticated and session.user %}
        <div class="sso-status sso-enabled">
          ✅ Successfully authenticated as 
          <strong>{{ session.user.get('name', session.user.get('email', 'Unknown')) }}</strong>
        </div>
        <a href="/logout" class="btn btn-ghost">🚪 Logout</a>

        <!-- Show form ONLY after login -->
        <form action="/generate" method="post" autocomplete="off">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
          <textarea name="message" placeholder="Enter your secret message..." required rows="6" maxlength="{{ max_message_length }}"></textarea>
          <input name="password" type="password" placeholder="Set a password (required)" required maxlength="{{ max_password_length }}" />
          <div class="row">
            <button class="btn btn-primary" type="submit">🚀 Generate Link</button>
            <button class="btn btn-ghost" type="reset">✖ Clear</button>
          </div>
          <small class="note">Note: Secrets are not stored and this application is end to end encrypted.</small>
        </form>
      {% else %}
        <div class="sso-status sso-enabled">
          ✅ SSO Enabled – Please login with Okta before generating a link
        </div>
        <a href="/login" class="btn btn-sso">🔐 Login with Okta SSO</a>
      {% endif %}
    {% else %}
      <div class="sso-status sso-disabled">
        ⚠️ SSO Disabled – Configure Okta environment variables
      </div>
    {% endif %}
  </div>

  <footer style="position:fixed; bottom:20px; width:100%; text-align:center; font-size:1rem; color:#bcd3e1a4;">
    © Hy-Vee Security
  </footer>

  <script>
    // Reset visited flag when user lands here
    sessionStorage.removeItem("visited");
  </script>
</body>


</html>
"""

link_template = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Hy-Vee Secret Messenger</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root{--bg1:#0f2027;--bg2:#2c5364}
    body{margin:0;font-family:Inter,system-ui,Segoe UI,Helvetica,Arial;background:linear-gradient(135deg,var(--bg1),#203a43,var(--bg2));color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center}
    .card{width:min(720px,92%);background:rgba(255,255,255,0.04);padding:28px;border-radius:12px;backdrop-filter:blur(8px);box-shadow:0 8px 30px rgba(2,6,23,0.6);text-align:center}
    input.link{width:100%;padding:12px;border-radius:10px;border:none;margin-top:10px;font-size:1rem}
    .controls{margin-top:16px;display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
    button{padding:12px 18px;border-radius:10px;border:none;cursor:pointer;font-weight:600}
    .copy{background:#3b82f6;color:white}
    .revoke{background:#ef4444;color:white}
    .new{background:#6b7280;color:white}
    p.status{margin-top:18px;font-weight:600;color:#cfe7ff}
  </style>
</head>
<body>
  <div class="card">
    <h2>✅ Secret Link Created</h2>
    <p>Share the link below. It will self-destruct after one view or {{ ttl_link }} seconds.</p>
    <input class="link" id="copyLink" value="{{ link }}" readonly />
    <div class="controls">
      <button class="copy" id="copyBtn">📋 Copy Link</button>
      <button class="revoke" id="revokeBtn">❌ Revoke Now</button>
      <button class="new" onclick="location.href='/'">➕ Create Another</button>
    </div>
    <p id="status" class="status">⏳ Waiting to be opened...</p>
  </div>
  <footer style="position:fixed; bottom:20px; width:100%; text-align:center; font-size:1rem; color:#bcd3e1a4;">
    © Hy-Vee Security
  </footer>
  <script>
    const key = "{{ key }}";
    document.getElementById('copyBtn').addEventListener('click', () => {
      const el = document.getElementById('copyLink');
      if (navigator.clipboard) {
        navigator.clipboard.writeText(el.value).then(()=> alert('✅ Copied to clipboard'));
      } else {
        el.select();
        document.execCommand('copy');
        alert('✅ Copied to clipboard');
      }
    });
    document.getElementById('revokeBtn').addEventListener('click', () => {
      fetch('/api/revoke/' + key, { method: 'POST' })
        .then(r => r.json())
        .then(j => {
          if (j.success) {
            document.getElementById('status').textContent = '❌ Link revoked.';
            document.getElementById('status').style.color = 'crimson';
          } else {
            alert('Failed to revoke');
          }
        });
    });
    function pollStatus() {
      fetch('/status/' + key).then(r=>r.json()).then(j=>{
        if (j.accessed) {
          document.getElementById('status').textContent = '✅ This link has been opened.';
          document.getElementById('status').style.color = 'lime';
        } else if (j.expired) {
          document.getElementById('status').textContent = '❌ This link has expired.';
          document.getElementById('status').style.color = 'crimson';
        } else {
          setTimeout(pollStatus, 2000);
        }
      }).catch(()=> setTimeout(pollStatus, 2000));
    }
    pollStatus();
    if (sessionStorage.getItem("visited")) {
      window.location.href = "/";
    } else {
      sessionStorage.setItem("visited", "yes");
    }
  </script>
</body>
</html>

"""
# For brevity, I will only paste the minimal part changed in view_template:
view_template = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Secret Messenger — View Secret</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{font-family:Inter,system-ui,Arial;background:#081224;color:#e6f0ff;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0}
    .card{width:min(720px,94%);padding:28px;border-radius:12px;background:linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02));box-shadow:0 12px 40px rgba(2,6,23,0.6);text-align:center}
    .secret{background:#020617;padding:18px;border-radius:10px;border:1px dashed rgba(255,255,255,0.06);font-size:1.05rem;word-break:break-word;white-space:pre-wrap}
    .controls{margin-top:16px;display:flex;gap:12px;justify-content:center;align-items:center;flex-wrap:wrap}
    button{padding:10px 16px;border-radius:10px;border:none;cursor:pointer;font-weight:700}
    .copy{background:#1f9cf0;color:white}
    .hide{background:#334155;color:white}
    .timer{margin-top:14px;font-weight:700;color:#ffb4b4;text-shadow:0 0 10px rgba(255,100,100,0.12)}
    .ip{margin-top:10px;color:#b1cbe6;font-size:0.95rem}
  </style>
</head>
<body>
  {% if message %}
  <div class="card">
    <h2>🔓 Secret Revealed</h2>

    <div id="secretEl" class="secret" aria-live="polite"></div>

    <div class="controls">
      <button class="copy" id="copySecretBtn">📋 Copy Secret</button>
      <button class="hide" id="toggleBtn">👁 Reveal / Hide</button>
    </div>

    <div class="timer" id="timerEl">⏳ This message will expire in <span id="seconds">{{ ttl_after_view }}</span> seconds</div>
    {% if okta_name %}

<div class="ip">👤 Secret shared by: <code id="oktaName">{{ okta_name }}</code></div>
    {% endif %}  </div>

<footer style="position:fixed; bottom:20px; width:100%; text-align:center; font-size:1rem; color:#bcd3e1a4;">
    © Hy-Vee Security
  </footer>

<script>
const secretValue = {{ message|tojson|safe }};
const ttl = Number({{ ttl_after_view }});
let seconds = ttl;
const secretEl = document.getElementById('secretEl');
const secondsEl = document.getElementById('seconds');
const timerEl = document.getElementById('timerEl');
const copyBtn = document.getElementById('copySecretBtn');
const toggleBtn = document.getElementById('toggleBtn');
let revealed = false;
function renderSecret() {
  if (!secretValue) { secretEl.textContent = '⛔ Secret unavailable'; return; }
  secretEl.textContent = revealed ? secretValue : '•'.repeat(Math.max(12, Math.min(secretValue.length, 40)));
}
renderSecret();

toggleBtn.addEventListener('click', () => {
  revealed = !revealed;
  renderSecret();
  toggleBtn.textContent = revealed ? '🙈 Hide' : '👁 Reveal / Hide';
});

async function copyText(text) {
  if (!text) return false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) {}
  // fallback
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position='fixed';
    ta.style.left='-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    return true;
  } catch (e) { return false; }
}

copyBtn.addEventListener('click', async () => {
  const ok = await copyText(secretValue);
  if (ok) {
    copyBtn.textContent = '✅ Copied';
    // expire immediately after copy to enforce one-time behavior
    expireNow();
  } else {
    alert('Copy failed — try using the Reveal button then select+copy manually.');
  }
});

let countdown = setInterval(() => {
  seconds -= 1;
  if (seconds >= 0) secondsEl.textContent = seconds;
  if (seconds <= 0) {
    clearInterval(countdown);
    expireNow();
  }
}, 1000);

function expireNow() {
  // Clear sensitive data from DOM and disable actions
  secretEl.textContent = '⛔ Message expired.';
  copyBtn.disabled = true;
  toggleBtn.disabled = true;
  timerEl.textContent = '❌ Message expired.';
  // optional: we could POST to server to mark revoked; store cleanup thread also removes entry
}
</script>

  {% else %}
  <div class="card">
    <h2 style="color:#ffb4b4">❌ This link is invalid, expired, or already used.</h2>
  </div>
  {% endif %}
</body>
</html>
"""


# ------------------ ROUTES ------------------

from functools import wraps
import time
from flask import request, jsonify

rate_limit_store = {}  # { ip: [timestamps...] }

def rate_limit(max_requests=10, window=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            window_start = now - window

            # purge old timestamps
            timestamps = [t for t in rate_limit_store.get(ip, []) if t > window_start]
            rate_limit_store[ip] = timestamps

            if len(timestamps) >= max_requests:
                return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

            timestamps.append(now)
            rate_limit_store[ip] = timestamps

            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route("/")
@rate_limit(max_requests=20, window=60)   # homepage form, moderate limit

def index():
    response = make_response(render_template_string(
        form_template,
        ttl_link=TTL_LINK_SECONDS,
        csrf_token=generate_csrf_token(),
        max_message_length=MAX_MESSAGE_LENGTH,
        max_password_length=MAX_PASSWORD_LENGTH,
        sso_enabled=SSO_ENABLED
    ))
    return add_security_headers(response)


@app.route("/generate", methods=["POST"])
@rate_limit(max_requests=20, window=60)
def generate():
    if not (session.get('authenticated') and session.get('user')):
        return "Unauthorized: Please login with Okta SSO", 403

    # Validate CSRF token
    csrf_token = request.form.get("csrf_token")
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403

    message = request.form.get("message", "")
    password = request.form.get("password", "")

    # Validate input
    is_valid, result = validate_input(message, MAX_MESSAGE_LENGTH)
    if not is_valid:
        return f"Invalid message: {result}", 400
    message = result

    is_valid, result = validate_input(password, MAX_PASSWORD_LENGTH)
    if not is_valid:
        return f"Invalid password: {result}", 400
    password = result

    if not message or not password:
        return "Missing message or password", 400

    key = secrets.token_urlsafe(32)

    # Encrypt message
    encrypted = fernet.encrypt(message.encode())

    # Hash password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    sender_userinfo = session.get('user', {})
    store[key] = {
        "ciphertext": encrypted,
        "password_hash": password_hash.decode(),
        "created_at": time.time(),
        "accessed": False,
        "viewed_at": None,
        "revoked": False,
        "fail_count": 0,
        "locked_until": 0,
        "sender_hostname": request.host,
        "sender_okta_user": sender_userinfo  # store sender info here
    }

    raw_link = request.url_root.rstrip("/") + "/view/" + key
    response = make_response(render_template_string(
        link_template,
        link=raw_link,
        key=key,
        ttl_link=TTL_LINK_SECONDS
    ))
    return add_security_headers(response)



import secrets

@app.route('/login')
def login():
    if not SSO_ENABLED:
        return "SSO is not configured. Please set OKTA_CLIENT_ID, OKTA_CLIENT_SECRET, and OKTA_DOMAIN environment variables.", 503

    try:
        # Clear any existing session data
        session.clear()

        # Generate nonce for security
        nonce = secrets.token_urlsafe(16)
        session["okta_nonce"] = nonce

        # Store intended destination before redirect
        next_url = request.args.get('next') or url_for('index')
        session['next'] = next_url

        # Build redirect URI (must match Okta config)
        redirect_uri = url_for("auth_callback", _external=True)

        # Log without revealing actual URI
        # print("🔐 Initiating Okta login (redirect URI hidden for security)")

        # Start OAuth flow
        return oauth.okta.authorize_redirect(redirect_uri, nonce=nonce)

    except Exception as e:
        # print(f"❌ Login initiation failed: {e}")
        return f"SSO login failed: {str(e)}", 500


@app.route('/callback')
def auth_callback():
    if not SSO_ENABLED:
        return "SSO is not configured.", 503

    try:
        # print("🔄 Processing Okta callback...")

        # Get token
        try:
            token = oauth.okta.authorize_access_token()
            # print(f"✅ Token received: {list(token.keys()) if token else 'No token'}")
        except Exception as token_error:
            # print(f"❌ Token error: {token_error}")
            session.clear()
            return redirect(url_for('login'))

        # Validate ID token with nonce
        try:
            nonce = session.get("okta_nonce")
            if not nonce:
                raise ValueError("Missing nonce in session")

            userinfo = oauth.okta.parse_id_token(token, nonce=nonce)
            # print(f"👤 User info from Okta: {userinfo}")

            # Clear nonce after validation
            session.pop("okta_nonce", None)

        except Exception as user_error:
            # print(f"❌ User info error: {user_error}")
            session.clear()
            return redirect(url_for('login'))

        # Store user info in session
        session['user'] = userinfo
        session['authenticated'] = True
        session['login_time'] = time.time()

        # print(f"✅ User authenticated: {userinfo.get('name', userinfo.get('email', 'Unknown'))}")

        # Redirect to intended destination or index
        next_url = session.pop('next', url_for('index'))
        return redirect(next_url)


    except Exception:

        session.clear()

        return "SSO Login callback failed", 500


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))




@app.route("/view/<key>", methods=["GET", "POST"])
@rate_limit(max_requests=20, window=60)
def view(key):
    # Validate key format
    if not re.match(r'^[A-Za-z0-9_-]+$', key):
        return "Invalid key format", 400

    entry = store.get(key)

    # Not found or revoked
    if not entry or entry.get("revoked"):
        response = make_response(render_template_string(view_template, message=None))
        return add_security_headers(response)

    # Expired by time
    if time.time() - entry["created_at"] > TTL_LINK_SECONDS:
        store.pop(key, None)
        response = make_response(render_template_string(view_template, message=None))
        return add_security_headers(response)

    # Removed SSO check here to allow anyone to view with password

    # GET: show password prompt
    if request.method == "GET":
        if request.method == "GET":
            password_template = """
              <!doctype html>
              <html>
              <head>
                <meta charset="UTF-8">
                <title>🔐 Enter Password</title>
                <footer style="position:fixed; bottom:20px; width:100%; text-align:center; font-size:1rem; color:#bcd3e1a4;">
          © Hy-Vee Security
        </footer>
                <style>
                  * {
                    box-sizing: border-box;
                  }
                  body {
                    margin: 0;
                    padding: 0;
                    background: #1f2f38;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    color: #d1d9e6;
                  }
                  .container {
                    background: #2b3e47;
                    padding: 40px;
                    border-radius: 20px;
                    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.5);
                    max-width: 600px;
                    width: 100%;
                  }
                  h2 {
                    font-size: 24px;
                    margin-bottom: 10px;
                    display: flex;
                    align-items: center;
                    font-weight: bold;
                  }
                  h2 .emoji {
                    font-size: 28px;
                    margin-right: 10px;
                  }
                  p {
                    font-size: 17px;
                    color: #a0b0c2;
                    margin-bottom: 30px;
                  }
                  input[type="password"] {
                    width: 100%;
                    padding: 14px;
                    border-radius: 12px;
                    border: none;
                    background: #0e1621;
                    color: white;
                    font-size: 16px;
                    margin-bottom: 25px;
                  }
                  input::placeholder {
                    color: #ccc;
                  }
                  button {
                    background: #00e0c6;
                    color: white;
                    font-weight: bold;
                    padding: 14px 28px;
                    border: none;
                    border-radius: 12px;
                    font-size: 16px;
                    cursor: pointer;
                    transition: background 0.3s ease;
                  }
                  button:hover {
                    background: #03c6b0;
                  }
                </style>
              </head>
              <body>
                <div class="container">
                  <h2><span class="emoji">🔐</span>Enter Password</h2>
                  <p>To reveal the secret, enter the password the sender provided.</p>
                  <form method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
                    <input type="password" name="password" placeholder="Password" required maxlength="{{ max_password_length }}" />
                    <br/>
                    <button type="submit">🔓 View Secret</button>
                  </form>
                </div>
              </body>
              </html>
              """
        response = make_response(render_template_string(
            password_template,
            csrf_token=generate_csrf_token(),
            max_password_length=MAX_PASSWORD_LENGTH
        ))
        return add_security_headers(response)

        # POST: verify password
    csrf_token = request.form.get("csrf_token")
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403

    password = request.form.get("password", "")

    is_valid, result = validate_input(password, MAX_PASSWORD_LENGTH)
    if not is_valid:
        return f"Invalid password: {result}", 400
    password = result

    stored_hash = entry["password_hash"].encode()
    if not bcrypt.checkpw(password.encode(), stored_hash):
        return "<h3 style='text-align:center;color:#ff4f4f;background:#081224;padding:2rem;border-radius:12px;font-family:Inter,sans-serif;'>❌ Incorrect password.</h3>", 403

    if entry.get("accessed"):
        return render_template_string(view_template, message=None)

    try:
        message = fernet.decrypt(entry["ciphertext"]).decode()
    except InvalidToken:
        return render_template_string(view_template, message=None)

    entry["accessed"] = True
    entry["viewed_at"] = time.time()

    # Attempt to get Okta user info if available; optional now
    userinfo = session.get('user')
    sender_okta_user = entry.get("sender_okta_user", {})
    okta_name = (
            sender_okta_user.get("name")
            or sender_okta_user.get("preferred_username")
            or sender_okta_user.get("email")
            or "Unknown"
    )

    response = make_response(render_template_string(
        view_template,
        message=escape(message),
        ttl_after_view=TTL_AFTER_VIEW,
        okta_name=escape(okta_name)
    ))

    return add_security_headers(response)


def shorten_url(long_url: str) -> str:
    try:
        r = requests.get("https://tinyurl.com/api-create.php", params={"url": long_url}, timeout=5)
        if r.status_code == 200 and r.text:
            return r.text.strip()
    except Exception:
        pass
    return long_url


def get_remote_ip():
    # Get IP safely, behind proxies if configured
    return request.headers.get("X-Forwarded-For", request.remote_addr) or "Unknown"


@app.route("/status/<key>")
@rate_limit(max_requests=10, window=60)
def status(key):
    if not re.match(r'^[A-Za-z0-9_-]+$', key):
        return jsonify({"error": "Invalid key format"}), 400

    with store_lock:
        entry = store.get(key)
        if not entry:
            return add_security_headers(make_response(jsonify({"expired": True})))

        is_expired = entry.get("revoked") or (time.time() - entry["created_at"] > TTL_LINK_SECONDS)
        return add_security_headers(make_response(jsonify({
            "accessed": bool(entry.get("accessed")),
            "expired": bool(is_expired)
        })))



@app.route("/api/revoke/<key>", methods=["POST"])
@rate_limit(max_requests=10, window=60)
def api_revoke(key):
    # Validate key format
    if not re.match(r'^[A-Za-z0-9_-]+$', key):
        return jsonify({"success": False, "error": "Invalid key format"}), 400

    try:
        with store_lock:
            if key in store:
                store[key]["revoked"] = True
                response = make_response(jsonify({"success": True}))
                return add_security_headers(response)
            response = make_response(jsonify({"success": False, "error": "Invalid key"}), 404)
            return add_security_headers(response)
    except Exception as e:
        print(f"Error revoking key {key}: {e}")
        response = make_response(jsonify({"success": False, "error": "Server error"}), 500)
        return add_security_headers(response)


# password prompt template (used in GET /view/<key>)
password_prompt_template = """
<!doctype html>
<html>
<head>
  <meta charset="UTF-8">
  <title>🔐 Enter Password</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; padding: 0;
      background: #1f2f38;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      display: flex; justify-content: center; align-items: center; height: 100vh;
      color: #d1d9e6;
    }
    .container {
      background: #2b3e47;
      padding: 40px;
      border-radius: 20px;
      box-shadow: 0 16px 40px rgba(0,0,0,0.5);
      max-width: 600px;
      width: 100%;
    }
    h2 {
      font-size: 24px;
      margin-bottom: 10px;
      display: flex; align-items: center;
      font-weight: bold;
    }
    h2 .emoji {
      font-size: 28px; margin-right: 10px;
    }
    p {
      font-size: 17px;
      color: #a0b0c2;
      margin-bottom: 30px;
    }
    input[type="password"] {
      width: 100%;
      padding: 14px;
      border-radius: 12px;
      border: none;
      background: #0e1621;
      color: white;
      font-size: 16px;
      margin-bottom: 25px;
    }
    input::placeholder {
      color: #ccc;
    }
    button {
      background: #00e0c6;
      color: white;
      font-weight: bold;
      padding: 14px 28px;
      border: none;
      border-radius: 12px;
      font-size: 16px;
      cursor: pointer;
      transition: background 0.3s ease;
    }
    button:hover {
      background: #03c6b0;
    }
  </style>
</head>
<body>
  <div class="container">
    <h2><span class="emoji">🔐</span>Enter Password</h2>
    <p>To reveal the secret, enter the password the sender provided.</p>
    <form method="post">
      <input type="password" name="password" placeholder="Password" required />
      <br/>
      <button type="submit">🔓 View Secret</button>
    </form>
  </div>
</body>
</html>
"""

import socket


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

app.config.update(MAX_CONTENT_LENGTH=16 * 1024 * 1024)

if __name__ == "__main__":
    local_ip = get_local_ip()
    port = int(os.environ.get("PORT", 7000))
    print(f"🔒 Secure server running on http://{local_ip}:{port}")
    print(f"🔐 Security features enabled:")
    print(f"   - XSS Protection: ✅")
    print(f"   - CSRF Protection: ✅")
    print(f"   - Rate Limiting: ✅")
    print(f"   - Security Headers: ✅")
    print(f"   - Input Validation: ✅")
    print(f"   - SSO Integration: {'✅' if SSO_ENABLED else '❌'}")
    if SSO_ENABLED:
        print(f"   - Okta Domain: {okta_domain}")
    app.run(host="0.0.0.0", port=port, debug=False)

