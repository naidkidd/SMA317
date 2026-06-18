import os
import re
import time
import html
import secrets
import logging
import hashlib
import hmac
import json
import random
import string
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from models import db, User, BuktiPendaftaran, DokumenTambahan, Pengumuman, DaftarKelulusanSementara, NotifikasiSiswa
from flask_session import Session
from urllib.parse import quote
from flask_mail import Mail, Message

load_dotenv()

BACKGROUND_IMAGE_URL = "/static/images/latar_belakang.jpg"
app = Flask(__name__)

@app.context_processor
def inject_background_image():
    return dict(background_image_url=BACKGROUND_IMAGE_URL)

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("FLASK_SECRET_KEY tidak diset di environment variables")

app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY')
if not app.config['WTF_CSRF_SECRET_KEY']:
    raise RuntimeError("WTF_CSRF_SECRET_KEY tidak diset di environment variables")

app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 7200
app.config['WTF_CSRF_SSL_STRICT'] = False
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

csrf = CSRFProtect(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError("DATABASE_URL tidak diset di environment variables")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
}

app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'fush1gurammm@gmail.com')

mail = Mail(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=7200,
    SESSION_TYPE='filesystem',
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_KEY_PREFIX='ppdb_session_',
)

SESSION_FILE_DIR = '/var/www/html/SMA-317/flask_session'
if not os.path.exists(SESSION_FILE_DIR):
    try:
        os.makedirs(SESSION_FILE_DIR, mode=0o700)
    except Exception as e:
        SESSION_FILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_session')
        if not os.path.exists(SESSION_FILE_DIR):
            os.makedirs(SESSION_FILE_DIR, mode=0o700)

app.config['SESSION_FILE_DIR'] = SESSION_FILE_DIR
Session(app)

db.init_app(app)

ADMIN_SECRET_PATH = os.environ.get('ADMIN_SECRET_PATH', '5UPI2A412!')
ADMIN_SECRET_KEY = os.environ.get('ADMIN_SECRET_KEY', 'Awikwok412')
ADMIN_ALLOWED_IPS = [ip.strip() for ip in os.environ.get('ADMIN_ALLOWED_IPS', '').split(',') if ip.strip()]

ADMIN_SECRET_PATH_ENCODED = quote(ADMIN_SECRET_PATH, safe='')

otp_storage = {}

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    try:
        msg = Message(
            subject='🔐 Admin Login OTP - PPDB SMA Negeri 317',
            recipients=[email],
            html=f"""
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
                <div style="background: white; padding: 30px; border-radius: 10px; border: 2px solid #A0D787;">
                    <h2 style="color: #A0D787; text-align: center;">🔐 Admin Login OTP</h2>
                    <p style="color: #333; font-size: 16px;">Halo Admin,</p>
                    <p style="color: #333; font-size: 16px;">Anda sedang melakukan login ke panel admin PPDB SMA Negeri 317.</p>
                    <p style="color: #333; font-size: 16px;">Gunakan kode OTP berikut untuk verifikasi:</p>
                    <div style="text-align: center; padding: 20px; margin: 20px 0; background: #f8f9fa; border-radius: 8px;">
                        <h1 style="font-size: 48px; letter-spacing: 10px; color: #A0D787; font-weight: 700; margin: 0;">
                            {otp}
                        </h1>
                    </div>
                    <p style="color: #666; font-size: 14px;">Kode OTP ini berlaku selama <strong>2 menit</strong>.</p>
                    <p style="color: #666; font-size: 14px;">Jika Anda tidak melakukan permintaan login, abaikan email ini.</p>
                    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                    <p style="color: #999; font-size: 12px; text-align: center;">
                        PPDB SMA Negeri 317<br>
                        Sistem Administrasi
                    </p>
                </div>
            </body>
            </html>
            """
        )
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Email sending error: {e}")
        return False

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

security_handler = RotatingFileHandler('security.log', maxBytes=10000, backupCount=5)
security_handler.setLevel(logging.WARNING)
security_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
security_handler.setFormatter(security_formatter)
security_logger = logging.getLogger('security')
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.WARNING)

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

class RateLimiter:
    def __init__(self):
        self.attempts = {}
        self.lockouts = {}
        self.lockout_time = 300
        self.max_attempts = 5
        self.window_time = 300

    def is_rate_limited(self, ip_address):
        current_time = time.time()
        if ip_address in self.lockouts:
            if current_time < self.lockouts[ip_address]:
                return True
            else:
                del self.lockouts[ip_address]
                if ip_address in self.attempts:
                    del self.attempts[ip_address]
                return False
        if ip_address in self.attempts:
            self.attempts[ip_address] = [
                t for t in self.attempts[ip_address]
                if current_time - t < self.window_time
            ]
            if len(self.attempts[ip_address]) >= self.max_attempts:
                self.lockouts[ip_address] = current_time + self.lockout_time
                return True
        return False

    def add_attempt(self, ip_address):
        current_time = time.time()
        if ip_address not in self.attempts:
            self.attempts[ip_address] = []
        if not self.is_rate_limited(ip_address):
            self.attempts[ip_address].append(current_time)
            if len(self.attempts[ip_address]) >= self.max_attempts:
                self.lockouts[ip_address] = current_time + self.lockout_time

    def reset_attempts(self, ip_address):
        if ip_address in self.attempts:
            del self.attempts[ip_address]
        if ip_address in self.lockouts:
            del self.lockouts[ip_address]

    def get_remaining_time(self, ip_address):
        if ip_address in self.lockouts:
            return max(0, self.lockouts[ip_address] - time.time())
        return 0

rate_limiter = RateLimiter()

def get_real_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

def is_admin_ip_allowed():
    if not ADMIN_ALLOWED_IPS:
        return True
    return get_real_ip() in ADMIN_ALLOWED_IPS

def sanitize_input(input_string):
    if input_string is None:
        return ""
    return html.escape(input_string.strip())

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_security_event(event_type, ip_address, username, details=""):
    security_logger.warning(f"{event_type} - IP: {ip_address}, User: {username}, Details: {details}")

def get_popup_message(jenis_notifikasi, user):
    messages = {
        'pendaftaran_selesai': (
            '✅ Terima kasih! Pendaftaran Anda telah berhasil diselesaikan.<br>'
            'Data Anda sudah dikunci dan tidak dapat diubah lagi.<br>'
            'Silakan menunggu pengumuman hasil seleksi.'
        ),
        'lulus': (
            f'🎉 <strong>SELAMAT {user.nama}!</strong><br>'
            f'Anda dinyatakan <strong>LULUS</strong> seleksi PPDB SMA Negeri 317.<br>'
            f'Silakan melakukan daftar ulang sesuai jadwal yang telah ditentukan.'
        ),
        'tidak_lulus': (
            f'😔 <strong>Mohon maaf {user.nama}</strong><br>'
            f'Anda dinyatakan <strong>TIDAK LULUS</strong> seleksi PPDB SMA Negeri 317.<br>'
            f'Tetap semangat dan terus berjuang untuk masa depan yang lebih baik.'
        )
    }
    return messages.get(jenis_notifikasi, "")

@app.context_processor
def inject_csrf():
    return dict(generate_csrf=generate_csrf, csrf_token=generate_csrf)

def csrf_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return f(*args, **kwargs)
        if request.endpoint in ['siswa_login_auth', 'register', 'admin_otp_login', 'admin_verify_otp', 'admin_resend_otp']:
            return f(*args, **kwargs)
        try:
            csrf.protect()
            return f(*args, **kwargs)
        except CSRFError as e:
            app.logger.warning(f"CSRF Error: {e}")
            flash('Token keamanan tidak valid. Silakan refresh halaman.', 'error')
            return redirect(request.referrer or url_for('home'))
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in') or session.get('role') != 'admin':
            app.logger.warning(f"Unauthorized admin access attempt from IP: {get_real_ip()}")
            return "Not Found", 404
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Silakan login terlebih dahulu.', 'error')
            return redirect(url_for('siswa_login_page'))
        return f(*args, **kwargs)
    return decorated

def siswa_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'siswa':
            flash('Akses ditolak. Hanya untuk siswa.', 'error')
            return redirect(url_for('siswa_login_page'))
        return f(*args, **kwargs)
    return decorated

def can_edit_data(user):
    return user.status not in ['selesai', 'lulus', 'tidak_lulus']

# ========== ADMIN OTP LOGIN ROUTES ==========
@app.route('/admin-login-page')
def admin_login_page():
    return render_template('admin_login_otp.html')

@app.route('/admin/login', methods=['POST'])
def admin_otp_login():
    data = request.get_json()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email dan password harus diisi!'})
    
    user = User.query.filter_by(email=email, role='admin').first()
    
    if not user or not user.check_password(password):
        log_security_event("ADMIN_LOGIN_FAILED", get_real_ip(), email, "Invalid credentials")
        return jsonify({'success': False, 'message': 'Email atau password salah!'})
    
    otp = generate_otp()
    expires = time.time() + 120
    otp_storage[email] = {'otp': otp, 'expires': expires}
    
    if send_otp_email(email, otp):
        log_security_event("ADMIN_OTP_SENT", get_real_ip(), email, "OTP sent successfully")
        return jsonify({'success': True, 'message': 'OTP telah dikirim ke email Anda!'})
    else:
        log_security_event("ADMIN_OTP_SEND_FAILED", get_real_ip(), email, "Failed to send OTP")
        return jsonify({'success': False, 'message': 'Gagal mengirim OTP. Periksa konfigurasi email.'})

@app.route('/admin/verify-otp', methods=['POST'])
def admin_verify_otp():
    data = request.get_json()
    email = data.get('email', '').strip()
    otp = data.get('otp', '').strip()
    
    if not email or not otp:
        return jsonify({'success': False, 'message': 'Email dan OTP harus diisi!'})
    
    stored = otp_storage.get(email)
    
    if not stored:
        return jsonify({'success': False, 'message': 'OTP tidak ditemukan. Kirim ulang OTP.'})
    
    if time.time() > stored['expires']:
        del otp_storage[email]
        return jsonify({'success': False, 'message': 'OTP sudah kadaluarsa. Kirim ulang OTP.'})
    
    if stored['otp'] != otp:
        log_security_event("ADMIN_OTP_INVALID", get_real_ip(), email, "Invalid OTP")
        return jsonify({'success': False, 'message': 'OTP tidak valid!'})
    
    user = User.query.filter_by(email=email, role='admin').first()
    
    if not user:
        return jsonify({'success': False, 'message': 'User tidak ditemukan!'})
    
    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role
    session['nama'] = user.nama
    session['admin_logged_in'] = True
    session.permanent = True
    
    del otp_storage[email]
    
    log_security_event("ADMIN_LOGIN_SUCCESS", get_real_ip(), user.username, "OTP verified")
    return jsonify({'success': True, 'redirect': url_for('admin_dashboard')})

@app.route('/admin/resend-otp', methods=['POST'])
def admin_resend_otp():
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({'success': False, 'message': 'Email harus diisi!'})
    
    otp = generate_otp()
    expires = time.time() + 120
    otp_storage[email] = {'otp': otp, 'expires': expires}
    
    if send_otp_email(email, otp):
        log_security_event("ADMIN_OTP_RESEND", get_real_ip(), email, "OTP resent")
        return jsonify({'success': True, 'message': 'OTP baru telah dikirim!'})
    else:
        return jsonify({'success': False, 'message': 'Gagal mengirim OTP.'})

# ========== SISWA LOGIN ROUTES ==========
@app.route('/siswa-portal', methods=['GET'])
def siswa_login_page():
    return render_template('siswa_login.html')

@app.route('/siswa-portal/auth', methods=['POST'])
def siswa_login_auth():
    ip_address = get_real_ip()
    
    if rate_limiter.is_rate_limited(ip_address):
        remaining = rate_limiter.get_remaining_time(ip_address)
        flash(f'Too many attempts. Try again in {int(remaining)} seconds.', 'error')
        return render_template('siswa_login.html')
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        flash('Username dan password harus diisi!', 'error')
        return render_template('siswa_login.html')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.role == 'siswa' and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['nama'] = user.nama
        session['show_popup'] = False
        session['popup_message'] = ""
        session['popup_type'] = ""
        session.permanent = True
        
        notifikasi = NotifikasiSiswa.query.filter_by(
            user_id=user.id,
            sudah_dibaca=False
        ).filter(
            NotifikasiSiswa.jenis_notifikasi.in_(['lulus', 'tidak_lulus'])
        ).order_by(NotifikasiSiswa.tanggal_dibuat.desc()).first()
        
        if notifikasi:
            session['show_popup'] = True
            session['popup_message'] = get_popup_message(notifikasi.jenis_notifikasi, user)
            session['popup_type'] = notifikasi.jenis_notifikasi
            notifikasi.sudah_dibaca = True
            notifikasi.tanggal_dibaca = datetime.utcnow()
            db.session.commit()
        
        rate_limiter.reset_attempts(ip_address)
        log_security_event("SISWA_LOGIN_SUCCESS", ip_address, username, "")
        return redirect(url_for('dashboard_siswa'))
    else:
        rate_limiter.add_attempt(ip_address)
        log_security_event("SISWA_LOGIN_FAILED", ip_address, username, "")
        flash('Username atau password salah!', 'error')
        return render_template('siswa_login.html')

@app.route('/siswa-logout')
def siswa_logout():
    session.clear()
    flash('Anda telah logout.', 'success')
    return redirect(url_for('siswa_login_page'))

# ========== PUBLIC ROUTES ==========
@app.route('/')
def home():
    pengumuman_terbaru = Pengumuman.query.order_by(Pengumuman.tanggal.desc()).first()
    siswa_lulus = User.query.filter_by(role='siswa', status='lulus').count()
    total_siswa = User.query.filter_by(role='siswa').count()
    return render_template('index.html',
                         pengumuman=pengumuman_terbaru,
                         siswa_lulus=siswa_lulus,
                         total_siswa=total_siswa)

@app.route('/pengumuman_public')
def pengumuman_public():
    pengumuman = Pengumuman.query.order_by(Pengumuman.tanggal.desc()).all()
    current_year = 2024
    next_year = 2025
    total_siswa = User.query.filter_by(role='siswa').count()
    siswa_lulus = User.query.filter_by(role='siswa', status='lulus').count()
    siswa_daftar = User.query.filter_by(role='siswa', status='menunggu').count()
    return render_template('pengumuman_public.html',
                         pengumuman=pengumuman,
                         current_year=current_year,
                         next_year=next_year,
                         total_siswa=total_siswa,
                         siswa_lulus=siswa_lulus,
                         siswa_daftar=siswa_daftar)

# ========== REGISTRATION ==========
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    nama = request.form.get('nama', '').strip()
    ip_address = get_real_ip()
    
    if not nama or not re.match(r'^[a-zA-Z\s]+$', nama) or len(nama) < 3 or len(nama) > 100:
        flash('Nama lengkap harus berupa huruf dan spasi (3-100 karakter)!', 'error')
        return redirect(url_for('register'))
    
    if not username or not re.match(r'^[0-9]+$', username) or len(username) < 8 or len(username) > 20:
        flash('NIS harus berupa angka (8-20 digit)!', 'error')
        return redirect(url_for('register'))
    
    if not password or not re.match(r'^[a-zA-Z0-9]+$', password) or len(password) < 6 or len(password) > 50:
        flash('Password harus huruf/angka (6-50 karakter)!', 'error')
        return redirect(url_for('register'))
    
    if User.query.filter_by(username=username).first():
        flash('NIS sudah terdaftar!', 'error')
        return redirect(url_for('register'))
    
    new_user = User(username=username, role='siswa', status='belum_lengkap')
    new_user.set_password(password)
    new_user.nama = nama
    
    try:
        db.session.add(new_user)
        db.session.commit()
        flash('Registrasi berhasil! Silakan login.', 'success')
        log_security_event("REGISTRATION_SUCCESS", ip_address, username, "New user registered")
        return redirect(url_for('siswa_login_page'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Registration error: {e}')
        flash('Terjadi kesalahan saat registrasi.', 'error')
        return redirect(url_for('register'))

# ========== DASHBOARD SISWA ==========
@app.route('/dashboard_siswa')
@login_required
@siswa_required
def dashboard_siswa():
    user = User.query.get(session['user_id'])
    bukti = BuktiPendaftaran.query.filter_by(user_id=session['user_id']).first()
    pengumuman = Pengumuman.query.order_by(Pengumuman.tanggal.desc()).first()
    dokumen_count = DokumenTambahan.query.filter_by(user_id=session['user_id']).count()
    return render_template('dashboard_siswa.html', user=user, bukti=bukti, pengumuman=pengumuman, dokumen_count=dokumen_count)

@app.route('/lengkapi_data_siswa', methods=['GET', 'POST'])
@login_required
@siswa_required
@csrf_protected
def lengkapi_data_siswa():
    user = User.query.get(session['user_id'])
    
    if user.status == 'selesai':
        flash('Pendaftaran sudah diselesaikan. Data tidak dapat diubah.', 'error')
        return redirect(url_for('dashboard_siswa'))
    
    if request.method == 'GET':
        return render_template('lengkapi_data_siswa.html', user=user)
    
    tempat_lahir = request.form.get('tempat_lahir', '').strip()
    if not tempat_lahir or not re.match(r'^[a-zA-Z\s]+$', tempat_lahir):
        flash('Tempat Lahir harus berupa huruf dan spasi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    no_hp = request.form.get('no_hp', '').strip()
    if not no_hp or not re.match(r'^[0-9]+$', no_hp) or len(no_hp) < 10 or len(no_hp) > 15:
        flash('No. HP harus angka (10-15 digit)!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    asal_sekolah = request.form.get('asal_sekolah', '').strip()
    if not asal_sekolah or not re.match(r'^[a-zA-Z0-9\s]+$', asal_sekolah):
        flash('Asal Sekolah harus berupa huruf, angka dan spasi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    nama_ayah = request.form.get('nama_ayah', '').strip()
    if not nama_ayah or not re.match(r'^[a-zA-Z\s]+$', nama_ayah):
        flash('Nama Ayah harus berupa huruf dan spasi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    pekerjaan_ayah = request.form.get('pekerjaan_ayah', '').strip()
    if not pekerjaan_ayah or not re.match(r'^[a-zA-Z\s]+$', pekerjaan_ayah):
        flash('Pekerjaan Ayah harus berupa huruf dan spasi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    nama_ibu = request.form.get('nama_ibu', '').strip()
    if not nama_ibu or not re.match(r'^[a-zA-Z\s]+$', nama_ibu):
        flash('Nama Ibu harus berupa huruf dan spasi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    pekerjaan_ibu = request.form.get('pekerjaan_ibu', '').strip()
    if not pekerjaan_ibu or not re.match(r'^[a-zA-Z\s]+$', pekerjaan_ibu):
        flash('Pekerjaan Ibu harus berupa huruf dan spasi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    alamat = request.form.get('alamat', '').strip()
    if not alamat or not re.match(r'^[a-zA-Z0-9\s,\.\-]+$', alamat):
        flash('Alamat hanya boleh berisi huruf, angka, spasi, koma, dan titik!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    user.tempat_lahir = tempat_lahir
    user.jenis_kelamin = request.form.get('jenis_kelamin', '')
    user.agama = request.form.get('agama', '')
    user.alamat = alamat
    user.no_hp = no_hp
    user.asal_sekolah = asal_sekolah
    user.nama_ayah = nama_ayah
    user.pekerjaan_ayah = pekerjaan_ayah
    user.nama_ibu = nama_ibu
    user.pekerjaan_ibu = pekerjaan_ibu
    
    try:
        if request.form.get('tanggal_lahir'):
            user.tanggal_lahir = datetime.strptime(request.form['tanggal_lahir'], '%Y-%m-%d')
        if user.status == 'belum_lengkap':
            user.status = 'menunggu'
        db.session.commit()
        flash('Data berhasil disimpan!', 'success')
        return redirect(url_for('dashboard_siswa'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error saving data: {e}')
        flash('Terjadi kesalahan saat menyimpan data.', 'error')
        return redirect(url_for('lengkapi_data_siswa'))

@app.route('/upload_bukti', methods=['GET', 'POST'])
@login_required
@siswa_required
@csrf_protected
def upload_bukti():
    user = User.query.get(session['user_id'])
    
    if not can_edit_data(user):
        flash('Pendaftaran sudah diselesaikan. Dokumen tidak dapat diubah.', 'error')
        return redirect(url_for('dashboard_siswa'))
    
    if request.method == 'GET':
        return render_template('upload_bukti.html', user=user)
    
    if 'file' not in request.files:
        flash('Tidak ada file yang dipilih', 'error')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('Tidak ada file yang dipilih', 'error')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        existing = BuktiPendaftaran.query.filter_by(user_id=session['user_id']).first()
        if existing:
            existing.filename = filename
            existing.filepath = filepath
            existing.tanggal_upload = datetime.utcnow()
            existing.status = 'menunggu'
        else:
            new_bukti = BuktiPendaftaran(
                user_id=session['user_id'],
                filename=filename,
                filepath=filepath,
                status='menunggu'
            )
            db.session.add(new_bukti)
        
        try:
            db.session.commit()
            flash('Bukti pendaftaran berhasil diupload!', 'success')
            return redirect(url_for('dashboard_siswa'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error uploading file: {e}')
            flash('Terjadi kesalahan saat upload file.', 'error')
            return redirect(request.url)
    else:
        flash('Format file tidak didukung!', 'error')
        return redirect(request.url)

@app.route('/upload_dokumen', methods=['GET', 'POST'])
@login_required
@siswa_required
@csrf_protected
def upload_dokumen():
    user = User.query.get(session['user_id'])
    
    if not can_edit_data(user):
        flash('Pendaftaran sudah diselesaikan. Dokumen tidak dapat diubah.', 'error')
        return redirect(url_for('dashboard_siswa'))
    
    if request.method == 'GET':
        dokumen = DokumenTambahan.query.filter_by(user_id=session['user_id']).all()
        dokumen_dict = {doc.jenis_dokumen: doc for doc in dokumen}
        return render_template('upload_dokumen.html', user=user, dokumen=dokumen_dict)
    
    if 'file' not in request.files:
        flash('Tidak ada file yang dipilih', 'error')
        return redirect(request.url)
    
    file = request.files['file']
    jenis_dokumen = request.form.get('jenis_dokumen')
    
    if file.filename == '':
        flash('Tidak ada file yang dipilih', 'error')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        existing = DokumenTambahan.query.filter_by(
            user_id=session['user_id'],
            jenis_dokumen=jenis_dokumen
        ).first()
        
        if existing:
            existing.filename = filename
            existing.filepath = filepath
            existing.tanggal_upload = datetime.utcnow()
            existing.status = 'menunggu'
        else:
            new_doc = DokumenTambahan(
                user_id=session['user_id'],
                jenis_dokumen=jenis_dokumen,
                filename=filename,
                filepath=filepath,
                status='menunggu'
            )
            db.session.add(new_doc)
        
        try:
            db.session.commit()
            flash(f'Dokumen {jenis_dokumen} berhasil diupload!', 'success')
            return redirect(url_for('upload_dokumen'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error uploading document: {e}')
            flash('Terjadi kesalahan saat upload dokumen.', 'error')
            return redirect(request.url)
    else:
        flash('Format file tidak didukung!', 'error')
        return redirect(request.url)

@app.route('/selesaikan_pendaftaran', methods=['POST'])
@login_required
@siswa_required
@csrf_protected
def selesaikan_pendaftaran():
    user = User.query.get(session['user_id'])
    
    if not can_edit_data(user):
        flash('Pendaftaran sudah diselesaikan.', 'error')
        return redirect(url_for('dashboard_siswa'))
    
    required_fields = [user.tempat_lahir, user.tanggal_lahir, user.jenis_kelamin, user.agama,
                       user.alamat, user.no_hp, user.asal_sekolah,
                       user.nama_ayah, user.pekerjaan_ayah, user.nama_ibu, user.pekerjaan_ibu]
    
    if not all(required_fields):
        flash('Data pribadi belum lengkap!', 'error')
        return redirect(url_for('dashboard_siswa'))
    
    bukti = BuktiPendaftaran.query.filter_by(user_id=session['user_id']).first()
    if not bukti:
        flash('Bukti pendaftaran belum diupload!', 'error')
        return redirect(url_for('dashboard_siswa'))
    
    dokumen_count = DokumenTambahan.query.filter_by(user_id=session['user_id']).count()
    if dokumen_count < 3:
        flash(f'Minimal upload 3 dokumen tambahan! (Saat ini: {dokumen_count})', 'error')
        return redirect(url_for('dashboard_siswa'))
    
    user.status = 'selesai'
    
    try:
        db.session.commit()
        flash('✅ Pendaftaran berhasil diselesaikan!', 'success')
        log_security_event("PENDAFTARAN_SELESAI", get_real_ip(), user.username, "")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error finalizing registration: {e}')
        flash('Terjadi kesalahan.', 'error')
    
    return redirect(url_for('dashboard_siswa'))

@app.route('/tutup_popup', methods=['POST'])
@login_required
@csrf_protected
def tutup_popup():
    session['show_popup'] = False
    return jsonify({'success': True})

# ========== ADMIN DASHBOARD ==========
@app.route('/dashboard-admin')
@admin_required
def admin_dashboard():
    semua_siswa = User.query.filter_by(role='siswa').all()
    siswa_data = []
    
    for siswa in semua_siswa:
        bukti = BuktiPendaftaran.query.filter_by(user_id=siswa.id).first()
        dokumen = DokumenTambahan.query.filter_by(user_id=siswa.id).all()
        dokumen_dict = {doc.jenis_dokumen: doc for doc in dokumen}
        siswa_data.append({'user': siswa, 'bukti': bukti, 'dokumen': dokumen_dict})
    
    total_siswa = len(semua_siswa)
    siswa_lulus = User.query.filter_by(role='siswa', status='lulus').count()
    siswa_menunggu = User.query.filter_by(role='siswa', status='menunggu').count()
    siswa_belum_lengkap = User.query.filter_by(role='siswa', status='belum_lengkap').count()
    total_lulus = DaftarKelulusanSementara.query.count()
    
    return render_template('dashboard_admin.html',
                         siswa_data=siswa_data,
                         total_siswa=total_siswa,
                         siswa_lulus=siswa_lulus,
                         siswa_menunggu=siswa_menunggu,
                         siswa_belum_lengkap=siswa_belum_lengkap,
                         total_lulus=total_lulus)

@app.route('/dashboard-admin/detail_siswa/<int:user_id>')
@admin_required
def detail_siswa(user_id):
    siswa = User.query.get(user_id)
    if not siswa or siswa.role != 'siswa':
        flash('Data siswa tidak ditemukan', 'error')
        return redirect(url_for('admin_dashboard'))
    
    bukti = BuktiPendaftaran.query.filter_by(user_id=user_id).first()
    dokumen = DokumenTambahan.query.filter_by(user_id=user_id).all()
    dokumen_dict = {doc.jenis_dokumen: doc for doc in dokumen}
    
    return render_template('detail_siswa.html', siswa=siswa, bukti=bukti, dokumen=dokumen_dict)

@app.route('/dashboard-admin/update_status/<int:user_id>', methods=['POST'])
@admin_required
@csrf_protected
def update_status(user_id):
    status = request.form.get('status')
    user = User.query.get(user_id)
    
    if user and user.role == 'siswa':
        status_sebelumnya = user.status
        user.status = status
        
        try:
            db.session.commit()
            
            if status == 'lulus' and status_sebelumnya != 'lulus':
                notifikasi = NotifikasiSiswa(
                    user_id=user_id,
                    jenis_notifikasi='lulus',
                    sudah_dibaca=False
                )
                db.session.add(notifikasi)
                
                existing = DaftarKelulusanSementara.query.filter_by(user_id=user_id).first()
                if not existing:
                    kelulusan_baru = DaftarKelulusanSementara(
                        user_id=user_id,
                        status_pengumuman='belum_diumumkan'
                    )
                    db.session.add(kelulusan_baru)
                db.session.commit()
                flash(f'✅ {user.nama} dinyatakan LULUS!', 'success')
                
            elif status == 'tidak_lulus' and status_sebelumnya != 'tidak_lulus':
                notifikasi = NotifikasiSiswa(
                    user_id=user_id,
                    jenis_notifikasi='tidak_lulus',
                    sudah_dibaca=False
                )
                db.session.add(notifikasi)
                
                kelulusan = DaftarKelulusanSementara.query.filter_by(user_id=user_id).first()
                if kelulusan:
                    db.session.delete(kelulusan)
                db.session.commit()
                flash(f'⚠️ {user.nama} dinyatakan TIDAK LULUS.', 'warning')
            else:
                flash(f'Status berhasil diupdate ke {status}!', 'success')
                
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error updating status: {e}')
            flash('Terjadi kesalahan.', 'error')
    
    return redirect(url_for('detail_siswa', user_id=user_id))

@app.route('/dashboard-admin/update_dokumen_status/<int:dokumen_id>', methods=['POST'])
@admin_required
@csrf_protected
def update_dokumen_status(dokumen_id):
    status = request.form.get('status')
    dokumen = DokumenTambahan.query.get(dokumen_id)
    
    if dokumen:
        user_id = dokumen.user_id
        dokumen.status = status
        try:
            db.session.commit()
            flash('Status dokumen berhasil diupdate!', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error updating document status: {e}')
            flash('Terjadi kesalahan.', 'error')
        return redirect(url_for('detail_siswa', user_id=user_id))
    
    flash('Dokumen tidak ditemukan!', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/dashboard-admin/download_file/<int:file_id>/<string:file_type>')
@admin_required
def download_file(file_id, file_type):
    if file_type == 'bukti':
        file_data = BuktiPendaftaran.query.get(file_id)
    elif file_type == 'dokumen':
        file_data = DokumenTambahan.query.get(file_id)
    else:
        flash('Tipe file tidak valid!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if file_data and os.path.exists(file_data.filepath):
        return send_file(file_data.filepath, as_attachment=True)
    else:
        flash('File tidak ditemukan!', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/dashboard-admin/buat_pengumuman', methods=['POST'])
@admin_required
@csrf_protected
def buat_pengumuman():
    judul = sanitize_input(request.form.get('judul', ''))
    isi = sanitize_input(request.form.get('isi', ''))
    
    if not judul or not isi:
        flash('Judul dan isi tidak boleh kosong!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    new_pengumuman = Pengumuman(judul=judul, isi=isi)
    db.session.add(new_pengumuman)
    
    try:
        db.session.commit()
        flash('Pengumuman berhasil dibuat!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error creating announcement: {e}')
        flash('Terjadi kesalahan.', 'error')
    
    return redirect(url_for('admin_dashboard'))

# ========== ROUTE KELULUSAN ==========
@app.route('/dashboard-admin/daftar_kelulusan_sementara')
@admin_required
def daftar_kelulusan():
    daftar_kelulusan = DaftarKelulusanSementara.query.all()
    total_lulus = len(daftar_kelulusan)
    total_siswa = User.query.filter_by(role='siswa').count()
    
    return render_template('daftar_kelulusan_sementara.html',
                         siswa_data=daftar_kelulusan,
                         total_siswa_lulus=total_lulus,
                         total_semua_siswa=total_siswa)

@app.route('/dashboard-admin/publish_pengumuman_kelulusan', methods=['POST'])
@admin_required
@csrf_protected
def publikasi_kelulusan():
    judul = sanitize_input(request.form.get('judul', 'Pengumuman Kelulusan PPDB SMA Negeri 317'))
    tambahan_teks = sanitize_input(request.form.get('tambahan_teks', ''))
    daftar_kelulusan = DaftarKelulusanSementara.query.all()
    
    if not daftar_kelulusan:
        flash('Tidak ada siswa dalam daftar kelulusan!', 'error')
        return redirect(url_for('daftar_kelulusan'))
    
    isi_pengumuman = f"{tambahan_teks}\n\n" if tambahan_teks else ""
    isi_pengumuman += "DAFTAR SISWA YANG LULUS SELEKSI PPDB SMA NEGERI 317:\n\n"
    daftar_terurut = sorted(daftar_kelulusan, key=lambda x: x.user.nama)
    
    for i, kelulusan in enumerate(daftar_terurut, 1):
        isi_pengumuman += f"{i}. {kelulusan.user.nama} - NIS: {kelulusan.user.username}\n"
    
    isi_pengumuman += f"\nTotal: {len(daftar_kelulusan)} siswa\n"
    isi_pengumuman += "\nSelamat kepada seluruh siswa yang lulus!"
    isi_pengumuman += "\n\nBagi siswa yang lulus, silakan melakukan daftar ulang sesuai jadwal."
    
    new_pengumuman = Pengumuman(judul=judul, isi=isi_pengumuman)
    
    try:
        db.session.add(new_pengumuman)
        db.session.commit()
        flash(f'Pengumuman kelulusan berhasil dipublish! {len(daftar_kelulusan)} siswa diumumkan.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error publishing announcement: {e}')
        flash('Terjadi kesalahan.', 'error')
    
    return redirect(url_for('daftar_kelulusan'))

@app.route('/dashboard-admin/hapus_dari_daftar_kelulusan/<int:kelulusan_id>')
@admin_required
def hapus_dari_daftar_kelulusan(kelulusan_id):
    kelulusan = DaftarKelulusanSementara.query.get(kelulusan_id)
    if kelulusan:
        nama_siswa = kelulusan.user.nama
        db.session.delete(kelulusan)
        try:
            db.session.commit()
            flash(f'{nama_siswa} berhasil dihapus dari daftar kelulusan!', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error removing from graduation list: {e}')
            flash('Terjadi kesalahan.', 'error')
    return redirect(url_for('daftar_kelulusan'))

# ========== HIDDEN ADMIN LOGIN ROUTE ==========
@app.route(f'/{ADMIN_SECRET_PATH_ENCODED}/login', methods=['GET', 'POST'])
def hidden_admin_login():
    if request.method == 'GET':
        return "Not Found", 404
    
    secret_header = request.headers.get('X-Admin-Secret')
    if secret_header != ADMIN_SECRET_KEY:
        log_security_event("ILLEGAL_ADMIN_ACCESS", get_real_ip(), "unknown", "Invalid header")
        return "Not Found", 404
    
    if not is_admin_ip_allowed():
        log_security_event("ADMIN_IP_REJECTED", get_real_ip(), "unknown", "IP not whitelisted")
        return "Not Found", 404
    
    ip_address = get_real_ip()
    if rate_limiter.is_rate_limited(ip_address):
        return "Too Many Attempts", 429
    
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        rate_limiter.add_attempt(ip_address)
        return "Not Found", 404
    
    user = User.query.filter_by(username=username, role='admin').first()
    
    if user and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['nama'] = user.nama
        session['admin_logged_in'] = True
        session.permanent = True
        
        rate_limiter.reset_attempts(ip_address)
        log_security_event("HIDDEN_ADMIN_LOGIN_SUCCESS", ip_address, username, "")
        return redirect(url_for('admin_dashboard'))
    else:
        rate_limiter.add_attempt(ip_address)
        log_security_event("HIDDEN_ADMIN_LOGIN_FAILED", ip_address, username, "")
        return "Not Found", 404

# ========== LOGOUT ==========
@app.route('/logout')
def logout():
    if session.get('admin_logged_in'):
        log_security_event("ADMIN_LOGOUT", get_real_ip(), session.get('username', 'unknown'), "")
    session.clear()
    flash('Anda telah logout.', 'success')
    return redirect(url_for('home'))

# ========== COMPATIBILITY REDIRECTS ==========
@app.route('/login')
def login_redirect():
    return redirect(url_for('siswa_login_page'))

@app.route('/pilihan_login')
def pilihan_login_redirect():
    return redirect(url_for('home'))

@app.route('/pengumuman')
def pengumuman_redirect():
    return redirect(url_for('pengumuman_public'))

@app.route('/admin-logout')
def admin_logout_redirect():
    return redirect(url_for('logout'))

# ========== INITIALIZATION ==========
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    with app.app_context():
        db.create_all()
    
    print("=" * 60)
    print("🚀 SERVER STARTED SUCCESSFULLY!")
    print("=" * 60)
    print(f"👨‍🎓 Siswa Login    : /siswa-portal")
    print(f"🔐 Admin Login    : /admin-login-page")
    print(f"📋 Admin Dashboard: /dashboard-admin")
    print(f"📧 OTP akan dikirim ke: fush1gurammm@gmail.com")
    print("=" * 60)
    
    app.run(debug=False, host='0.0.0.0', port=5000)
