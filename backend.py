import hashlib
import hmac
import json
import os
import secrets
import smtplib
import string
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool

app = Flask(__name__)
CORS(app, supports_credentials=True, allow_headers=["Content-Type", "Authorization"])

# ===== CONFIGURATION (use environment variables!) =====
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY')
ADMIN_RESET_KEY = os.getenv('ADMIN_RESET_KEY', 'your-secret-reset-key')
ADMIN_REVOKE_KEY = os.getenv('ADMIN_REVOKE_KEY', 'your-secret-revoke-key')
DATABASE_URL = os.getenv('DATABASE_URL')

# ===== DATABASE CONNECTION POOL =====
db_pool = None

def init_db_pool():
    global db_pool
    if DATABASE_URL:
        db_pool = SimpleConnectionPool(1, 20, DATABASE_URL, cursor_factory=RealDictCursor)
    else:
        # Fallback for local development (use a local PostgreSQL or SQLite)
        # For simplicity, we'll raise an error
        raise Exception("DATABASE_URL environment variable not set")

def get_db_connection():
    return db_pool.getconn()

def put_db_connection(conn):
    db_pool.putconn(conn)

def init_db():
    """Create the licenses table if it doesn't exist"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    email TEXT PRIMARY KEY,
                    license_key TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    status TEXT DEFAULT 'active',
                    devices JSONB DEFAULT '[]',
                    used_by_username TEXT,
                    activation_count INTEGER DEFAULT 0,
                    max_activations INTEGER DEFAULT 2,
                    recovery_pin_hash TEXT,
                    security_answer_hash TEXT
                )
            """)
            conn.commit()
    finally:
        put_db_connection(conn)

# ===== HELPER FUNCTIONS =====
def generate_license_key():
    parts = []
    for _ in range(3):
        part = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        parts.append(part)
    return f"CTJP-{parts[0]}-{parts[1]}-{parts[2]}"

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def send_email(to_email, license_key, subject=None):
    if not SMTP_USER or not SMTP_PASSWORD:
        print("SMTP credentials not set. Cannot send email.")
        return False
    if subject is None:
        subject = "Crypto Trading Journal Pro License"
    body = f"""Welcome to Crypto Trading Journal Pro 🚀

Your license key:
{license_key}

Enter it in the app to unlock all Pro features.

If you have any questions, reply to this email."""
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def get_license_by_key(key):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key = %s", (key,))
            return cur.fetchone()
    finally:
        put_db_connection(conn)

def update_license(license_key, updates):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            set_clause = ", ".join([f"{k} = %s" for k in updates.keys()])
            values = list(updates.values()) + [license_key]
            cur.execute(f"UPDATE licenses SET {set_clause} WHERE license_key = %s", values)
            conn.commit()
    finally:
        put_db_connection(conn)

# ===================== LICENSE ACTIVATION =====================
@app.route('/activate-license', methods=['POST'])
def activate_license():
    data = request.get_json()
    key = data.get('license_key')
    username = data.get('username')
    pin = data.get('recovery_pin')
    answer = data.get('security_answer')
    device_id = data.get('device_id')

    if not all([key, username, pin, answer, device_id]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    license_entry = get_license_by_key(key)
    if not license_entry:
        return jsonify({'success': False, 'error': 'Invalid license key'}), 200

    if license_entry['status'] == 'revoked':
        return jsonify({'success': False, 'error': 'License has been revoked.'}), 200

    if license_entry['used_by_username'] == username:
        return jsonify({'success': True}), 200

    if license_entry['used_by_username'] is not None:
        return jsonify({'success': False, 'error': 'License already used by another user. Use recovery instead.'}), 200

    activation_count = license_entry['activation_count'] or 0
    max_activations = license_entry['max_activations'] or 2
    if activation_count >= max_activations:
        return jsonify({'success': False, 'error': 'Activation limit reached. Cannot activate new license.'}), 200

    updates = {
        'used_by_username': username,
        'activation_count': activation_count + 1,
        'recovery_pin_hash': hash_data(pin),
        'security_answer_hash': hash_data(answer),
        'devices': json.dumps([device_id]),
        'status': 'active'
    }
    update_license(key, updates)

    return jsonify({'success': True}), 200

# ===================== LICENSE RECOVERY =====================
@app.route('/recover-license', methods=['POST'])
def recover_license():
    data = request.get_json()
    key = data.get('license_key')
    username = data.get('username')
    pin = data.get('recovery_pin')
    answer = data.get('security_answer')
    device_id = data.get('device_id')

    if not all([key, username, pin, answer, device_id]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    license_entry = get_license_by_key(key)
    if not license_entry:
        return jsonify({'success': False, 'error': 'Invalid license key'}), 200

    if license_entry['status'] == 'revoked':
        return jsonify({'success': False, 'error': 'License has been revoked.'}), 200

    if (hash_data(pin) != license_entry.get('recovery_pin_hash') or
        hash_data(answer) != license_entry.get('security_answer_hash')):
        return jsonify({'success': False, 'error': 'Invalid recovery credentials'}), 200

    activation_count = license_entry['activation_count'] or 0
    max_activations = license_entry['max_activations'] or 2
    if activation_count + 1 > max_activations:
        return jsonify({'success': False, 'error': 'Activation limit reached. License cannot be transferred again.'}), 200

    updates = {
        'used_by_username': username,
        'activation_count': activation_count + 1,
        'devices': json.dumps([device_id]),
        'status': 'active'
    }
    update_license(key, updates)

    return jsonify({'success': True}), 200

# ===================== LICENSE VERIFICATION =====================
@app.route('/verify-license', methods=['POST'])
def verify_license():
    data = request.get_json()
    key = data.get('license_key')
    device_id = data.get('device_id')
    username = data.get('username')

    if not key:
        return jsonify({'valid': False, 'error': 'Missing license key'}), 400

    license_entry = get_license_by_key(key)
    if not license_entry:
        return jsonify({'valid': False, 'error': 'Invalid license key'}), 200

    if license_entry['status'] == 'revoked':
        return jsonify({'valid': False, 'error': 'License revoked'}), 200

    bound_username = license_entry.get('used_by_username')
    if bound_username and bound_username != username:
        has_recovery = bool(license_entry.get('recovery_pin_hash') and license_entry.get('security_answer_hash'))
        return jsonify({
            'valid': False,
            'error': 'Already used by another user',
            'recoverable': has_recovery
        }), 200

    if not bound_username and username:
        update_license(key, {'used_by_username': username})

    devices = json.loads(license_entry.get('devices', '[]'))
    if device_id not in devices:
        if len(devices) >= 1:
            return jsonify({'valid': False, 'error': 'Device limit reached'}), 200
        devices.append(device_id)
        update_license(key, {'devices': json.dumps(devices)})

    return jsonify({'valid': True}), 200

# ===================== LICENSE STATUS =====================
@app.route('/license-status', methods=['POST'])
def license_status():
    data = request.get_json()
    key = data.get('license_key')
    username = data.get('username')

    license_entry = get_license_by_key(key)
    if not license_entry:
        return jsonify({'status': 'invalid', 'valid': False}), 200

    status = license_entry.get('status', 'invalid')
    bound_username = license_entry.get('used_by_username')

    if status == 'revoked':
        return jsonify({'status': 'revoked', 'valid': False}), 200

    if bound_username and username and bound_username != username:
        return jsonify({
            'status': 'used_by_other',
            'valid': False,
            'recoverable': bool(license_entry.get('recovery_pin_hash'))
        }), 200

    if not bound_username:
        return jsonify({'status': 'free', 'valid': False}), 200

    return jsonify({'status': 'active', 'valid': True}), 200

# ===================== ADMIN REVOKE =====================
@app.route('/revoke-license', methods=['POST'])
def revoke_license():
    data = request.get_json()
    admin_key = data.get('admin_key')
    license_key = data.get('license_key')

    if admin_key != ADMIN_REVOKE_KEY:
        return jsonify({'error': 'Unauthorized'}), 401

    license_entry = get_license_by_key(license_key)
    if not license_entry:
        return jsonify({'error': 'License not found'}), 404

    update_license(license_key, {'status': 'revoked'})
    return jsonify({'status': 'success', 'message': 'License revoked'}), 200

# ===================== PAYSTACK WEBHOOK =====================
def verify_paystack_signature():
    signature = request.headers.get('x-paystack-signature')
    if not signature or not PAYSTACK_SECRET_KEY:
        return False
    payload = request.get_data()
    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode(),
        payload,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(signature, computed)

@app.route('/paystack-webhook', methods=['POST'])
def paystack_webhook():
    if not verify_paystack_signature():
        return jsonify({'error': 'Invalid signature'}), 400

    event = request.get_json()
    if event.get('event') == 'charge.success':
        data = event.get('data')
        email = data.get('customer', {}).get('email')
        if email:
            conn = get_db_connection()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT license_key FROM licenses WHERE email = %s", (email,))
                    existing = cur.fetchone()
                    if existing:
                        license_key = existing['license_key']
                        send_email(email, license_key)
                        return jsonify({'status': 'already_licensed', 'key': license_key}), 200
                    else:
                        license_key = generate_license_key()
                        cur.execute("""
                            INSERT INTO licenses (email, license_key, created_at, status, devices, used_by_username, activation_count, max_activations, recovery_pin_hash, security_answer_hash)
                            VALUES (%s, %s, %s, 'active', '[]', NULL, 0, 2, NULL, NULL)
                        """, (email, license_key, datetime.now()))
                        conn.commit()
                        send_email(email, license_key)
                        return jsonify({'status': 'success', 'key': license_key}), 200
            finally:
                put_db_connection(conn)
    return jsonify({'status': 'ignored'}), 200

# ===================== ADMIN RESET DEVICE =====================
@app.route('/reset-device', methods=['POST'])
def reset_device():
    data = request.get_json()
    admin_key = data.get('admin_key')
    license_key = data.get('license_key')

    if admin_key != ADMIN_RESET_KEY:
        return jsonify({'error': 'Unauthorized'}), 401
    if not license_key:
        return jsonify({'error': 'Missing license key'}), 400

    license_entry = get_license_by_key(license_key)
    if not license_entry:
        return jsonify({'error': 'License key not found'}), 404

    update_license(license_key, {'devices': '[]'})
    return jsonify({'status': 'success', 'message': 'Device list cleared'}), 200

@app.route('/admin/create-test-license', methods=['POST'])
def create_test_license():
    data = request.get_json()
    admin_key = data.get('admin_key')
    if admin_key != ADMIN_RESET_KEY:
        return jsonify({'error': 'Unauthorized'}), 401
    email = data.get('email', 'test@example.com')
    license_key = data.get('license_key', 'CTJP-TEST-1234')
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO licenses (email, license_key, created_at, status, devices, used_by_username, activation_count, max_activations, recovery_pin_hash, security_answer_hash)
                VALUES (%s, %s, NOW(), 'active', '[]', NULL, 0, 2, NULL, NULL)
                ON CONFLICT (license_key) DO NOTHING
            """, (email, license_key))
            conn.commit()
            return jsonify({'success': True, 'license_key': license_key})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        put_db_connection(conn)
        
@app.route('/admin/list-licenses', methods=['GET'])
def list_licenses():
    auth = request.headers.get('Authorization')
    if auth != f"Bearer {ADMIN_RESET_KEY}":
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT email, license_key, used_by_username, 
                       devices::text, activation_count, status, created_at 
                FROM licenses
            """)
            rows = cur.fetchall()
            licenses = []
            for row in rows:
                licenses.append({
                    'email': row.get('email') or '',
                    'license_key': row.get('license_key') or '',
                    'used_by_username': row.get('used_by_username') or '',
                    'devices': row.get('devices') or '[]',
                    'activation_count': row.get('activation_count') or 0,
                    'status': row.get('status') or 'unknown',
                    'created_at': row.get('created_at').isoformat() if row.get('created_at') else None
                })
            return jsonify({'licenses': licenses})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'type': type(e).__name__}), 500
    finally:
        put_db_connection(conn)

@app.route('/admin/test-db', methods=['GET', 'OPTIONS'])
def test_db():
    if request.method == 'OPTIONS':
        return '', 200
    auth = request.headers.get('Authorization')
    if not auth or auth != f"Bearer {ADMIN_RESET_KEY}":
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM licenses")
            # Since cursor uses RealDictCursor, fetchone() returns a dict
            row = cur.fetchone()
            # The count is under key 'count' (PostgreSQL returns column name as 'count')
            # Alternatively, use cur.fetchone()[0] if we force tuple, but let's use dict
            count = row['count'] if row else 0
            return jsonify({'status': 'ok', 'license_count': count})
    except Exception as e:
        print(f"Error in test-db: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        put_db_connection(conn)
# ===================== STARTUP =====================
# Initialize database pool when module loads (for gunicorn)
import os
if os.getenv('DATABASE_URL'):
    init_db_pool()
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
