import os
import re
import time
import html
import secrets
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from models import db, User, BuktiPendaftaran, DokumenTambahan, Pengumuman, DaftarKelulusanSementara, NotifikasiSiswa, encrypt_data, decrypt_data

# Load environment variables
load_dotenv()

# Konfigurasi background
BACKGROUND_IMAGE_URL = "/static/images/latar_belakang.jpg"

app = Flask(__name__)

@app.context_processor
def inject_background_image():
    return dict(background_image_url=BACKGROUND_IMAGE_URL)

# ========== KONFIGURASI KEAMANAN DARI ENVIRONMENT ==========
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("Environment FLASK_SECRET_KEY tidak diset. Generate dengan: python -c 'import secrets; print(secrets.token_urlsafe(32))'")

app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY')
if not app.config['WTF_CSRF_SECRET_KEY']:
    raise RuntimeError("Environment WTF_CSRF_SECRET_KEY tidak diset")

# Path rahasia untuk admin (default jika tidak diset, tapi sebaiknya selalu diset)
ADMIN_BASE_PATH = os.environ.get('ADMIN_SECRET_PATH', '/secure-admin')

# CSRF Configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 7200  # 2 jam
app.config['WTF_CSRF_SSL_STRICT'] = False
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

csrf = CSRFProtect(app)

# ========== KONFIGURASI DATABASE ==========
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError("Environment DATABASE_URL tidak diset")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'connect_args': {
        'ssl': {
            'ca': '/home/pbl-webserver1/ca.pem',
            'check_hostname': False
        }
    }
}

app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,   # Set ke True jika pakai HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=7200
)

db.init_app(app)

# ========== LOGGING ==========
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

security_handler = RotatingFileHandler('security.log', maxBytes=10000, backupCount=3)
security_handler.setLevel(logging.WARNING)
security_logger = logging.getLogger('security')
security_logger.addHandler(security_handler)

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

# ========== RATE LIMITER ==========
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
            remaining = max(0, self.lockouts[ip_address] - time.time())
            return remaining
        return 0

rate_limiter = RateLimiter()

# ========== UTILITY FUNCTIONS ==========
def validate_input(input_string, max_length=100):
    if input_string is None:
        return False
    if len(input_string.strip()) == 0:
        return False
    if len(input_string) > max_length:
        return False
    if not re.match(r'^[a-zA-Z0-9_@.\-\s\p{L}]*$', input_string):
        return False
    return True

def sanitize_input(input_string):
    if input_string:
        return html.escape(input_string.strip())
    return ""

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_security_event(event_type, ip_address, username, details=""):
    security_logger.warning(f"{event_type} - IP: {ip_address}, User: {username}, Details: {details}")

def get_popup_message(jenis_notifikasi, user):
    messages = {
        'pendaftaran_selesai': (
            'Terima kasih. Data pendaftaran Anda telah berhasil disimpan.<br>'
            'Selanjutnya, silakan menunggu pengumuman hasil seleksi sesuai jadwal yang telah ditentukan.<br>'
            'Informasi lebih lanjut akan diumumkan melalui website resmi.'
        ),
        'lulus': (
            f'Selamat {user.nama_decrypted}! Anda dinyatakan <strong>LULUS</strong> seleksi.<br>'
            'Silakan melakukan daftar ulang sesuai jadwal dan ketentuan yang telah ditetapkan.'
        ),
        'tidak_lulus': (
            f'Mohon maaf {user.nama_decrypted}, Anda dinyatakan <strong>TIDAK LULUS</strong> seleksi.<br>'
            'Tetap semangat dan teruslah berjuang untuk pendidikan yang lebih baik.'
        )
    }
    return messages.get(jenis_notifikasi, "")

# ========== CONTEXT PROCESSOR CSRF ==========
@app.context_processor
def inject_csrf():
    return dict(
        generate_csrf=generate_csrf,
        csrf_token=generate_csrf
    )

# ========== CSRF DECORATOR ==========
def csrf_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return f(*args, **kwargs)
        if request.endpoint in ['login', 'admin_login', 'register']:
            app.logger.debug(f"CSRF EXEMPT for {request.endpoint}")
            return f(*args, **kwargs)
        try:
            csrf.protect()
            return f(*args, **kwargs)
        except CSRFError as e:
            app.logger.error(f"CSRF Error in {request.endpoint}: {str(e)}")
            flash('Token keamanan tidak valid. Silakan refresh halaman.', 'error')
            return redirect(request.referrer or url_for('home'))
    return decorated_function

# ========== AUTHENTICATION DECORATORS ==========
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Akses ditolak. Hanya admin yang dapat mengakses halaman ini.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu.', 'error')
            return redirect(url_for('pilihan_login'))
        return f(*args, **kwargs)
    return decorated_function

def siswa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'siswa':
            flash('Akses ditolak. Hanya siswa yang dapat mengakses halaman ini.', 'error')
            return redirect(url_for('pilihan_login'))
        return f(*args, **kwargs)
    return decorated_function

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

@app.route('/pilihan_login')
def pilihan_login():
    return render_template('pilihan_login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        role = request.args.get('role', 'siswa')
        return render_template('login.html', role=role)

    username = request.form['username']
    password = request.form['password']
    role = request.form.get('role', 'siswa')
    ip_address = request.remote_addr

    if role == 'siswa':
        if rate_limiter.is_rate_limited(ip_address):
            remaining_time = rate_limiter.get_remaining_time(ip_address)
            minutes = int(remaining_time / 60)
            seconds = int(remaining_time % 60)
            if minutes > 0:
                flash(f'Terlalu banyak percobaan login. Coba lagi dalam {minutes} menit {seconds} detik.', 'error')
            else:
                flash(f'Terlalu banyak percobaan login. Coba lagi dalam {seconds} detik.', 'error')
            return render_template('login.html', role=role)

    if not username or not password:
        flash('Username dan password harus diisi!', 'error')
        if role == 'siswa':
            rate_limiter.add_attempt(ip_address)
        return render_template('login.html', role=role)

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password) and user.role == role:
        if role == 'siswa':
            rate_limiter.reset_attempts(ip_address)

        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['nama'] = user.nama_decrypted
        session['show_popup'] = False
        session['popup_message'] = ""
        session['popup_type'] = ""

        notifikasi = NotifikasiSiswa.query.filter_by(
            user_id=user.id, sudah_dibaca=False
        ).order_by(NotifikasiSiswa.tanggal_dibuat.desc()).first()
        if notifikasi:
            session['show_popup'] = True
            session['popup_message'] = get_popup_message(notifikasi.jenis_notifikasi, user)
            session['popup_type'] = notifikasi.jenis_notifikasi
            notifikasi.sudah_dibaca = True
            notifikasi.tanggal_dibaca = datetime.utcnow()
            db.session.commit()

        log_security_event("LOGIN_SUCCESS", ip_address, username, f"Role: {role}")
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard_siswa'))
    else:
        if role == 'siswa':
            rate_limiter.add_attempt(ip_address)
        log_security_event("LOGIN_FAILED", ip_address, username, f"Role: {role}")
        flash('Username, password, atau role salah!', 'error')
        return render_template('login.html', role=role)

# ADMIN LOGIN dengan path rahasia
@app.route(f'{ADMIN_BASE_PATH}/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')

    username = request.form['username']
    password = request.form['password']
    ip_address = request.remote_addr

    if not username or not password:
        flash('Username dan password harus diisi!', 'error')
        return render_template('admin_login.html')

    user = User.query.filter_by(username=username, role='admin').first()
    if user and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['nama'] = user.nama_decrypted
        log_security_event("ADMIN_LOGIN_SUCCESS", ip_address, username, "Admin login")
        return redirect(url_for('admin_dashboard'))
    else:
        log_security_event("ADMIN_LOGIN_FAILED", ip_address, username, "Admin login gagal")
        flash('Username atau password admin salah!', 'error')
        return render_template('admin_login.html')

@app.route('/register', methods=['GET', 'POST'])
@csrf_protected
def register():
    if request.method == 'GET':
        role = request.args.get('role', 'siswa')
        return render_template('register.html', role=role)

    username = sanitize_input(request.form['username'])
    password = request.form['password']
    role = request.form.get('role', 'siswa')
    nama = sanitize_input(request.form['nama'])
    ip_address = request.remote_addr

    if not username or not nama:
        flash('Username dan nama harus diisi!', 'error')
        return redirect(url_for('register'))
    if len(username) > 50 or len(nama) > 100:
        flash('Username atau nama terlalu panjang!', 'error')
        return redirect(url_for('register'))
    if len(password) < 6:
        flash('Password harus minimal 6 karakter!', 'error')
        return redirect(url_for('register'))
    if role != 'siswa':
        flash('Registrasi admin tidak tersedia.', 'error')
        return redirect(url_for('home'))

    if User.query.filter_by(username=username).first():
        flash('Username sudah terdaftar!', 'error')
        return redirect(url_for('register'))

    status_awal = 'belum_lengkap'
    new_user = User(username=username, role=role, status=status_awal)
    new_user.set_password(password)
    new_user.set_encrypted_data(nama=nama)

    try:
        db.session.add(new_user)
        db.session.commit()
        flash('Registrasi berhasil! Silakan login.', 'success')
        log_security_event("REGISTRATION_SUCCESS", ip_address, username, "New user")
        return redirect(url_for('login', role='siswa'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Registration error: {e}')
        flash('Terjadi kesalahan saat registrasi.', 'error')
        return redirect(url_for('register'))

# ========== ROUTE SISWA ==========
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

    user.set_encrypted_data(
        tempat_lahir=request.form['tempat_lahir'],
        jenis_kelamin=request.form['jenis_kelamin'],
        agama=request.form['agama'],
        alamat=request.form['alamat'],
        no_hp=request.form['no_hp'],
        asal_sekolah=request.form['asal_sekolah'],
        nama_ayah=request.form['nama_ayah'],
        pekerjaan_ayah=request.form['pekerjaan_ayah'],
        nama_ibu=request.form['nama_ibu'],
        pekerjaan_ibu=request.form['pekerjaan_ibu']
    )
    try:
        user.tanggal_lahir = datetime.strptime(request.form['tanggal_lahir'], '%Y-%m-%d')
    except ValueError:
        flash('Format tanggal tidak valid!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    if not all([request.form['tempat_lahir'], request.form['jenis_kelamin'], request.form['agama'],
                request.form['alamat'], request.form['no_hp'], request.form['asal_sekolah']]):
        flash('Semua field wajib diisi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    if user.status == 'belum_lengkap':
        user.status = 'menunggu'
    try:
        db.session.commit()
        flash('Data berhasil disimpan!', 'success')
        return redirect(url_for('dashboard_siswa'))
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat menyimpan data.', 'error')
        return redirect(url_for('lengkapi_data_siswa'))

@app.route('/upload_bukti', methods=['GET', 'POST'])
@login_required
@siswa_required
@csrf_protected
def upload_bukti():
    user = User.query.get(session['user_id'])
    if user.status == 'selesai':
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
        existing_bukti = BuktiPendaftaran.query.filter_by(user_id=session['user_id']).first()
        if existing_bukti:
            existing_bukti.filename = filename
            existing_bukti.filepath = filepath
            existing_bukti.tanggal_upload = datetime.utcnow()
            existing_bukti.status = 'menunggu'
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
    if user.status == 'selesai':
        flash('Pendaftaran sudah diselesaikan. Dokumen tidak dapat diubah.', 'error')
        return redirect(url_for('dashboard_siswa'))
    if request.method == 'GET':
        dokumen = DokumenTambahan.query.filter_by(user_id=session['user_id']).all()
        dokumen_dict = {}
        for doc in dokumen:
            dokumen_dict[doc.jenis_dokumen] = doc
        return render_template('upload_dokumen.html', user=user, dokumen=dokumen_dict)

    if 'file' not in request.files:
        flash('Tidak ada file yang dipilih', 'error')
        return redirect(request.url)
    file = request.files['file']
    jenis_dokumen = request.form['jenis_dokumen']
    if file.filename == '':
        flash('Tidak ada file yang dipilih', 'error')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        existing_doc = DokumenTambahan.query.filter_by(
            user_id=session['user_id'],
            jenis_dokumen=jenis_dokumen
        ).first()
        if existing_doc:
            existing_doc.filename = filename
            existing_doc.filepath = filepath
            existing_doc.tanggal_upload = datetime.utcnow()
            existing_doc.status = 'menunggu'
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
    if not all([
        user.tempat_lahir, user.tanggal_lahir, user.jenis_kelamin, user.agama,
        user.alamat, user.no_hp, user.asal_sekolah,
        user.nama_ayah, user.pekerjaan_ayah, user.nama_ibu, user.pekerjaan_ibu
    ]):
        flash('Data pribadi belum lengkap!', 'error')
        return redirect(url_for('dashboard_siswa'))
    bukti = BuktiPendaftaran.query.filter_by(user_id=session['user_id']).first()
    if not bukti:
        flash('Bukti pendaftaran belum diupload!', 'error')
        return redirect(url_for('dashboard_siswa'))
    dokumen_count = DokumenTambahan.query.filter_by(user_id=session['user_id']).count()
    if dokumen_count < 3:
        flash('Minimal harus upload 3 dokumen tambahan!', 'error')
        return redirect(url_for('dashboard_siswa'))
    user.status = 'selesai'
    notifikasi = NotifikasiSiswa(
        user_id=user.id,
        jenis_notifikasi='pendaftaran_selesai',
        sudah_dibaca=False
    )
    db.session.add(notifikasi)
    try:
        db.session.commit()
        flash('Pendaftaran berhasil diselesaikan! Data Anda telah dikunci.', 'success')
        log_security_event("PENDAFTARAN_SELESAI", request.remote_addr, user.username, "Pendaftaran diselesaikan")
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat menyelesaikan pendaftaran.', 'error')
        app.logger.error(f"Finalisasi error: {str(e)}")
    return redirect(url_for('dashboard_siswa'))

@app.route('/tutup_popup', methods=['POST'])
@login_required
@csrf_protected
def tutup_popup():
    session['show_popup'] = False
    return jsonify({'success': True})

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

# ========== ADMIN ROUTES (dengan path rahasia) ==========
@app.route(f'{ADMIN_BASE_PATH}')
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

@app.route(f'{ADMIN_BASE_PATH}/detail_siswa/<int:user_id>')
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

@app.route(f'{ADMIN_BASE_PATH}/update_status/<int:user_id>', methods=['POST'])
@admin_required
@csrf_protected
def update_status(user_id):
    status = request.form['status']
    user = User.query.get(user_id)
    if user and user.role == 'siswa':
        status_sebelumnya = user.status
        user.status = status
        try:
            db.session.commit()
            if status == 'lulus' and status_sebelumnya != 'lulus':
                existing_notif = NotifikasiSiswa.query.filter_by(
                    user_id=user_id, jenis_notifikasi='lulus'
                ).first()
                if not existing_notif:
                    notifikasi = NotifikasiSiswa(
                        user_id=user_id, jenis_notifikasi='lulus', sudah_dibaca=False
                    )
                    db.session.add(notifikasi)
                existing = DaftarKelulusanSementara.query.filter_by(user_id=user_id).first()
                if not existing:
                    kelulusan_baru = DaftarKelulusanSementara(user_id=user_id, status_pengumuman='belum_diumumkan')
                    db.session.add(kelulusan_baru)
                db.session.commit()
                flash(f'{user.nama_decrypted} berhasil diupdate ke LULUS!', 'success')
            elif status == 'tidak_lulus' and status_sebelumnya != 'tidak_lulus':
                notifikasi = NotifikasiSiswa(
                    user_id=user_id, jenis_notifikasi='tidak_lulus', sudah_dibaca=False
                )
                db.session.add(notifikasi)
                db.session.commit()
                kelulusan = DaftarKelulusanSementara.query.filter_by(user_id=user_id).first()
                if kelulusan:
                    db.session.delete(kelulusan)
                    db.session.commit()
                flash(f'{user.nama_decrypted} diupdate ke TIDAK LULUS.', 'info')
            else:
                flash(f'Status {user.nama_decrypted} berhasil diupdate!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat update status.', 'error')
            app.logger.error(f"Status update error: {str(e)}")
    return redirect(url_for('detail_siswa', user_id=user_id))

@app.route(f'{ADMIN_BASE_PATH}/update_dokumen_status/<int:dokumen_id>', methods=['POST'])
@admin_required
@csrf_protected
def update_dokumen_status(dokumen_id):
    status = request.form['status']
    dokumen = DokumenTambahan.query.get(dokumen_id)
    if dokumen:
        user_id = dokumen.user_id
        dokumen.status = status
        try:
            db.session.commit()
            flash('Status dokumen berhasil diupdate!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat update status dokumen.', 'error')
        return redirect(url_for('detail_siswa', user_id=user_id))
    flash('Dokumen tidak ditemukan!', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route(f'{ADMIN_BASE_PATH}/download_file/<int:file_id>/<string:file_type>')
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

@app.route(f'{ADMIN_BASE_PATH}/buat_pengumuman', methods=['POST'])
@admin_required
@csrf_protected
def buat_pengumuman():
    judul = sanitize_input(request.form['judul'])
    isi = sanitize_input(request.form['isi'])
    if not judul or not isi:
        flash('Judul dan isi pengumuman tidak boleh kosong!', 'error')
        return redirect(url_for('admin_dashboard'))
    new_pengumuman = Pengumuman(judul=judul, isi=isi)
    db.session.add(new_pengumuman)
    try:
        db.session.commit()
        flash('Pengumuman berhasil dibuat!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat membuat pengumuman.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route(f'{ADMIN_BASE_PATH}/daftar_kelulusan_sementara')
@admin_required
def daftar_kelulusan_sementara():
    daftar_kelulusan = DaftarKelulusanSementara.query.all()
    total_lulus = len(daftar_kelulusan)
    total_siswa = User.query.filter_by(role='siswa').count()
    return render_template('daftar_kelulusan_sementara.html',
                         daftar_kelulusan=daftar_kelulusan,
                         total_lulus=total_lulus,
                         total_siswa=total_siswa)

@app.route(f'{ADMIN_BASE_PATH}/publish_pengumuman_kelulusan', methods=['POST'])
@admin_required
@csrf_protected
def publish_pengumuman_kelulusan():
    judul = sanitize_input(request.form.get('judul', 'Pengumuman Kelulusan PPDB SMA Negeri 317'))
    tambahan_teks = sanitize_input(request.form.get('tambahan_teks', ''))
    daftar_kelulusan = DaftarKelulusanSementara.query.all()
    if not daftar_kelulusan:
        flash('Tidak ada siswa dalam daftar kelulusan!', 'error')
        return redirect(url_for('daftar_kelulusan_sementara'))
    isi_pengumuman = f"{tambahan_teks}\n\n" if tambahan_teks else ""
    isi_pengumuman += "DAFTAR SISWA YANG LULUS SELEKSI PPDB SMA NEGERI 317:\n\n"
    daftar_terurut = sorted(daftar_kelulusan, key=lambda x: x.user.nama_decrypted)
    for i, kelulusan in enumerate(daftar_terurut, 1):
        isi_pengumuman += f"{i}. {kelulusan.user.nama_decrypted} - NIS: {kelulusan.user.username}\n"
    isi_pengumuman += f"\nTotal: {len(daftar_kelulusan)} siswa\n"
    isi_pengumuman += "\nSelamat kepada seluruh siswa yang lulus!"
    isi_pengumuman += "\n\nBagi siswa yang lulus, silakan melakukan daftar ulang sesuai jadwal yang akan ditentukan."
    new_pengumuman = Pengumuman(judul=judul, isi=isi_pengumuman)
    try:
        db.session.add(new_pengumuman)
        db.session.commit()
        flash(f'Pengumuman kelulusan berhasil dipublish! {len(daftar_kelulusan)} siswa diumumkan.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat mempublish pengumuman.', 'error')
    return redirect(url_for('daftar_kelulusan_sementara'))

@app.route(f'{ADMIN_BASE_PATH}/hapus_dari_daftar_kelulusan/<int:kelulusan_id>')
@admin_required
def hapus_dari_daftar_kelulusan(kelulusan_id):
    kelulusan = DaftarKelulusanSementara.query.get(kelulusan_id)
    if kelulusan:
        nama_siswa = kelulusan.user.nama_decrypted
        db.session.delete(kelulusan)
        try:
            db.session.commit()
            flash(f'{nama_siswa} berhasil dihapus dari daftar kelulusan!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat menghapus dari daftar kelulusan.', 'error')
    return redirect(url_for('daftar_kelulusan_sementara'))

# ========== COMMON ROUTES ==========
@app.route('/logout')
def logout():
    user_info = f"{session.get('username', 'Unknown')} ({session.get('role', 'Unknown')})"
    log_security_event("LOGOUT", request.remote_addr, user_info, "User logged out")
    session.clear()
    return redirect(url_for('home'))

@app.route('/test')
def test_route():
    return "Flask server is working! Timestamp: " + str(datetime.utcnow())

@app.before_request
def before_request_debug():
    if request.method == 'POST':
        app.logger.debug(f"POST Request to: {request.endpoint}")

# ========== INITIALIZATION ==========
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()
        # Cek apakah admin dengan username ADMIN317 sudah ada
        admin_user = User.query.filter_by(username='ADMIN317', role='admin').first()
        if not admin_user:
            admin_password = os.environ.get('ADMIN_PASSWORD')
            if not admin_password:
                print("="*60)
                print("PERINGATAN: Admin username 'ADMIN317' belum ada.")
                print("Silakan set environment variable ADMIN_PASSWORD, lalu restart.")
                print("Atau buat admin secara manual dengan create_admin.py")
                print("="*60)
            else:
                # Buat admin default
                admin = User(username='ADMIN317', role='admin', status='aktif')
                admin.set_password(admin_password)
                admin.set_encrypted_data(nama='Administrator Utama')
                db.session.add(admin)
                db.session.commit()
                print("Admin default (ADMIN317) berhasil dibuat dari environment variable.")
        else:
            print("Admin default (ADMIN317) sudah ada.")

    print("="*60)
    print("FLASK SERVER STARTED SUCCESSFULLY!")
    print(f"Admin path: {ADMIN_BASE_PATH}")
    print("Pastikan environment variables sudah diset dengan benar.")
    print("="*60)
    app.run(debug=True, host='0.0.0.0', port=5000)