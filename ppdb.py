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
from models import db, User, BuktiPendaftaran, DokumenTambahan, Pengumuman, DaftarKelulusanSementara, NotifikasiSiswa

# Load environment variables
load_dotenv()

BACKGROUND_IMAGE_URL = "/static/images/latar_belakang.jpg"

app = Flask(__name__)

@app.context_processor
def inject_background_image():
    return dict(background_image_url=BACKGROUND_IMAGE_URL)

# ========== KONFIGURASI KEAMANAN ==========
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("FLASK_SECRET_KEY tidak diset")

app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY')
if not app.config['WTF_CSRF_SECRET_KEY']:
    raise RuntimeError("WTF_CSRF_SECRET_KEY tidak diset")

ADMIN_BASE_PATH = os.environ.get('ADMIN_SECRET_PATH', '/secure-admin')

app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 7200
app.config['WTF_CSRF_SSL_STRICT'] = False
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

csrf = CSRFProtect(app)

# ========== KONFIGURASI DATABASE ==========
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError("DATABASE_URL tidak diset")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
}

app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
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
def sanitize_input(input_string):
    return html.escape(input_string.strip()) if input_string else ""

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_security_event(event_type, ip_address, username, details=""):
    security_logger.warning(f"{event_type} - IP: {ip_address}, User: {username}, Details: {details}")

def get_popup_message(jenis_notifikasi, user):
    """Generate pesan popup berdasarkan jenis notifikasi"""
    messages = {
        'pendaftaran_selesai': (
            '✅ Terima kasih! Pendaftaran Anda telah berhasil diselesaikan.<br>'
            'Data Anda sudah dikunci dan tidak dapat diubah lagi.<br>'
            'Silakan menunggu pengumuman hasil seleksi.'
        ),
        'lulus': (
            f'🎉 <strong>SELAMAT {user.nama_decrypted}!</strong><br>'
            'Anda dinyatakan <strong>LULUS</strong> seleksi PPDB SMA Negeri 317.<br>'
            'Silakan melakukan daftar ulang sesuai jadwal yang telah ditentukan.'
        ),
        'tidak_lulus': (
            f'😔 <strong>Mohon maaf {user.nama_decrypted}</strong><br>'
            'Anda dinyatakan <strong>TIDAK LULUS</strong> seleksi PPDB SMA Negeri 317.<br>'
            'Tetap semangat dan terus berjuang untuk masa depan yang lebih baik.'
        )
    }
    return messages.get(jenis_notifikasi, "")

# ========== CSRF DECORATOR ==========
@app.context_processor
def inject_csrf():
    return dict(generate_csrf=generate_csrf, csrf_token=generate_csrf)

def csrf_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return f(*args, **kwargs)
        if request.endpoint in ['login', 'admin_login', 'register']:
            return f(*args, **kwargs)
        try:
            csrf.protect()
            return f(*args, **kwargs)
        except CSRFError:
            flash('Token keamanan tidak valid. Silakan refresh halaman.', 'error')
            return redirect(request.referrer or url_for('home'))
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Akses ditolak. Hanya admin.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Silakan login terlebih dahulu.', 'error')
            return redirect(url_for('pilihan_login'))
        return f(*args, **kwargs)
    return decorated

def siswa_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'siswa':
            flash('Akses ditolak. Hanya siswa.', 'error')
            return redirect(url_for('pilihan_login'))
        return f(*args, **kwargs)
    return decorated

def can_edit_data(user):
    """Cek apakah siswa masih bisa mengedit data"""
    # Status yang TIDAK BOLEH edit: selesai, lulus, tidak_lulus
    return user.status not in ['selesai', 'lulus', 'tidak_lulus']

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

    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role', 'siswa')
    ip_address = request.remote_addr

    if not username or not password:
        flash('Username dan password harus diisi!', 'error')
        return render_template('login.html', role=role)

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password) and user.role == role:
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['nama'] = user.nama_decrypted

        # Reset popup session setiap login
        session['show_popup'] = False
        session['popup_message'] = ""
        session['popup_type'] = ""

        # Cek notifikasi yang belum dibaca (HANYA untuk notifikasi lulus/tidak_lulus)
        # JANGAN tampilkan popup untuk pendaftaran_selesai
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
            
            # Tandai sudah dibaca
            notifikasi.sudah_dibaca = True
            notifikasi.tanggal_dibaca = datetime.utcnow()
            db.session.commit()

        log_security_event("LOGIN_SUCCESS", ip_address, username, f"Role: {role}")

        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard_siswa'))
    else:
        log_security_event("LOGIN_FAILED", ip_address, username, f"Role: {role}")
        flash('Username atau password salah!', 'error')
        return render_template('login.html', role=role)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html', role='siswa')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    nama = request.form.get('nama', '').strip()
    ip_address = request.remote_addr

    # ========== BACKEND VALIDASI ==========
    import re
    
    # Validasi Nama (HANYA HURUF dan SPASI)
    if not nama:
        flash('Nama lengkap harus diisi!', 'error')
        return redirect(url_for('register'))
    
    if not re.match(r'^[a-zA-Z\s]+$', nama):
        flash('Nama lengkap harus berupa HURUF dan SPASI saja! (tidak boleh angka atau simbol)', 'error')
        return redirect(url_for('register'))
    
    if len(nama) < 3 or len(nama) > 100:
        flash('Nama lengkap harus antara 3-100 karakter!', 'error')
        return redirect(url_for('register'))
    
    # Validasi Username (HANYA ANGKA)
    if not username:
        flash('NIS harus diisi!', 'error')
        return redirect(url_for('register'))
    
    if not re.match(r'^[0-9]+$', username):
        flash('NIS harus berupa ANGKA saja! (tidak boleh huruf atau simbol)', 'error')
        return redirect(url_for('register'))
    
    if len(username) < 8 or len(username) > 20:
        flash('NIS harus antara 8-20 digit angka!', 'error')
        return redirect(url_for('register'))
    
    # Validasi Password (HANYA HURUF dan ANGKA)
    if not password:
        flash('Password harus diisi!', 'error')
        return redirect(url_for('register'))
    
    if not re.match(r'^[a-zA-Z0-9]+$', password):
        flash('Password hanya boleh terdiri dari HURUF dan ANGKA saja! (tidak boleh simbol atau spasi)', 'error')
        return redirect(url_for('register'))
    
    if len(password) < 6 or len(password) > 50:
        flash('Password harus antara 6-50 karakter!', 'error')
        return redirect(url_for('register'))
    
    # Cek username sudah ada
    if User.query.filter_by(username=username).first():
        flash('NIS sudah terdaftar!', 'error')
        return redirect(url_for('register'))

    new_user = User(username=username, role='siswa', status='belum_lengkap')
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



@app.route('/dashboard_siswa')
@login_required
@siswa_required
def dashboard_siswa():
    user = User.query.get(session['user_id'])
    bukti = BuktiPendaftaran.query.filter_by(user_id=session['user_id']).first()
    pengumuman = Pengumuman.query.order_by(Pengumuman.tanggal.desc()).first()
    dokumen_count = DokumenTambahan.query.filter_by(user_id=session['user_id']).count()
    return render_template('dashboard_siswa.html', user=user, bukti=bukti, pengumuman=pengumuman, dokumen_count=dokumen_count)

# ========== ROUTE SISWA LENGKAP ==========

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

    import re
    
    # ========== BACKEND VALIDASI ==========
    
    # Tempat Lahir (hanya huruf dan spasi)
    tempat_lahir = request.form.get('tempat_lahir', '').strip()
    if not tempat_lahir:
        flash('Tempat Lahir harus diisi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    if not re.match(r'^[a-zA-Z\s]+$', tempat_lahir):
        flash('Tempat Lahir harus berupa HURUF dan SPASI saja!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    # No HP (hanya angka)
    no_hp = request.form.get('no_hp', '').strip()
    if not no_hp:
        flash('No. HP harus diisi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    if not re.match(r'^[0-9]+$', no_hp):
        flash('No. HP harus berupa ANGKA saja!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    if len(no_hp) < 10 or len(no_hp) > 15:
        flash('No. HP harus antara 10-15 digit angka!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    # Asal Sekolah (hanya huruf dan spasi)
    asal_sekolah = request.form.get('asal_sekolah', '').strip()
    if not asal_sekolah:
        flash('Asal Sekolah harus diisi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    if not re.match(r'^[a-zA-Z\s]+$', asal_sekolah):
        flash('Asal Sekolah harus berupa HURUF dan SPASI saja!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    # Nama Ayah (hanya huruf dan spasi)
    nama_ayah = request.form.get('nama_ayah', '').strip()
    if not nama_ayah:
        flash('Nama Ayah harus diisi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    if not re.match(r'^[a-zA-Z\s]+$', nama_ayah):
        flash('Nama Ayah harus berupa HURUF dan SPASI saja!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    # Pekerjaan Ayah (hanya huruf dan spasi)
    pekerjaan_ayah = request.form.get('pekerjaan_ayah', '').strip()
    if not pekerjaan_ayah:
        flash('Pekerjaan Ayah harus diisi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    if not re.match(r'^[a-zA-Z\s]+$', pekerjaan_ayah):
        flash('Pekerjaan Ayah harus berupa HURUF dan SPASI saja!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    # Nama Ibu (hanya huruf dan spasi)
    nama_ibu = request.form.get('nama_ibu', '').strip()
    if not nama_ibu:
        flash('Nama Ibu harus diisi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    if not re.match(r'^[a-zA-Z\s]+$', nama_ibu):
        flash('Nama Ibu harus berupa HURUF dan SPASI saja!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    # Pekerjaan Ibu (hanya huruf dan spasi)
    pekerjaan_ibu = request.form.get('pekerjaan_ibu', '').strip()
    if not pekerjaan_ibu:
        flash('Pekerjaan Ibu harus diisi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    if not re.match(r'^[a-zA-Z\s]+$', pekerjaan_ibu):
        flash('Pekerjaan Ibu harus berupa HURUF dan SPASI saja!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    # Alamat (huruf, angka, spasi, koma, titik)
    alamat = request.form.get('alamat', '').strip()
    if not alamat:
        flash('Alamat harus diisi!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    if not re.match(r'^[a-zA-Z0-9\s,\.\-]+$', alamat):
        flash('Alamat hanya boleh berisi huruf, angka, spasi, koma, dan titik!', 'error')
        return redirect(url_for('lengkapi_data_siswa'))
    
    # Lanjutkan penyimpanan data
    user.set_encrypted_data(
        tempat_lahir=tempat_lahir,
        jenis_kelamin=request.form.get('jenis_kelamin', ''),
        agama=request.form.get('agama', ''),
        alamat=alamat,
        no_hp=no_hp,
        asal_sekolah=asal_sekolah,
        nama_ayah=nama_ayah,
        pekerjaan_ayah=pekerjaan_ayah,
        nama_ibu=nama_ibu,
        pekerjaan_ibu=pekerjaan_ibu
    )

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
        app.logger.error(f"Data completion error: {str(e)}")
        flash('Terjadi kesalahan saat menyimpan data.', 'error')
        return redirect(url_for('lengkapi_data_siswa'))


@app.route('/upload_bukti', methods=['GET', 'POST'])
@login_required
@siswa_required
@csrf_protected
def upload_bukti():
    user = User.query.get(session['user_id'])

    # CEK: Jika status dalam kondisi final (selesai/lulus/tidak_lulus), TIDAK BISA upload bukti
    if not can_edit_data(user):
        if user.status == 'selesai':
            flash('Pendaftaran Anda sudah diselesaikan. Dokumen tidak dapat diubah lagi.', 'error')
        elif user.status == 'lulus':
            flash('Anda sudah dinyatakan LULUS. Dokumen tidak dapat diubah lagi.', 'error')
        elif user.status == 'tidak_lulus':
            flash('Anda sudah dinyatakan TIDAK LULUS. Dokumen tidak dapat diubah lagi.', 'error')
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

    # CEK: Jika status dalam kondisi final (selesai/lulus/tidak_lulus), TIDAK BISA upload dokumen
    if not can_edit_data(user):
        if user.status == 'selesai':
            flash('Pendaftaran Anda sudah diselesaikan. Dokumen tidak dapat diubah lagi.', 'error')
        elif user.status == 'lulus':
            flash('Anda sudah dinyatakan LULUS. Dokumen tidak dapat diubah lagi.', 'error')
        elif user.status == 'tidak_lulus':
            flash('Anda sudah dinyatakan TIDAK LULUS. Dokumen tidak dapat diubah lagi.', 'error')
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

    # CEK: Jika sudah selesai atau lulus/tidak_lulus, tidak bisa lagi
    if not can_edit_data(user):
        if user.status == 'selesai':
            flash('Pendaftaran Anda sudah diselesaikan sebelumnya.', 'error')
        elif user.status == 'lulus':
            flash('Anda sudah dinyatakan LULUS. Tidak perlu menyelesaikan pendaftaran lagi.', 'error')
        elif user.status == 'tidak_lulus':
            flash('Anda sudah dinyatakan TIDAK LULUS.', 'error')
        return redirect(url_for('dashboard_siswa'))

    # Cek kelengkapan data pribadi
    if not all([user.tempat_lahir, user.tanggal_lahir, user.jenis_kelamin, user.agama,
                user.alamat, user.no_hp, user.asal_sekolah,
                user.nama_ayah, user.pekerjaan_ayah, user.nama_ibu, user.pekerjaan_ibu]):
        flash('Data pribadi belum lengkap! Silakan lengkapi data terlebih dahulu.', 'error')
        return redirect(url_for('dashboard_siswa'))

    # Cek bukti pendaftaran
    bukti = BuktiPendaftaran.query.filter_by(user_id=session['user_id']).first()
    if not bukti:
        flash('Bukti pendaftaran belum diupload!', 'error')
        return redirect(url_for('dashboard_siswa'))

    # Cek minimal 3 dokumen tambahan
    dokumen_count = DokumenTambahan.query.filter_by(user_id=session['user_id']).count()
    if dokumen_count < 3:
        flash(f'Minimal harus upload 3 dokumen tambahan! Saat ini baru {dokumen_count} dokumen.', 'error')
        return redirect(url_for('dashboard_siswa'))

    # Update status menjadi 'selesai'
    user.status = 'selesai'

    try:
        db.session.commit()
        flash('✅ Pendaftaran berhasil diselesaikan! Data Anda telah dikunci dan tidak dapat diubah lagi.', 'success')
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


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# ========== ADMIN ROUTES ==========

@app.route(f'{ADMIN_BASE_PATH}/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')

    username = request.form.get('username')
    password = request.form.get('password')
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
    status = request.form.get('status')
    user = User.query.get(user_id)
    
    if user and user.role == 'siswa':
        status_sebelumnya = user.status
        user.status = status
        
        try:
            db.session.commit()
            
            # Jika status berubah ke LULUS
            if status == 'lulus' and status_sebelumnya != 'lulus':
                # Buat notifikasi (hanya untuk lulus, tidak untuk pendaftaran_selesai)
                notifikasi = NotifikasiSiswa(
                    user_id=user_id,
                    jenis_notifikasi='lulus',
                    sudah_dibaca=False
                )
                db.session.add(notifikasi)
                db.session.commit()
                app.logger.info(f"Notifikasi LULUS dibuat untuk user {user.username}")
                
                # Tambah ke daftar kelulusan sementara
                existing = DaftarKelulusanSementara.query.filter_by(user_id=user_id).first()
                if not existing:
                    kelulusan_baru = DaftarKelulusanSementara(
                        user_id=user_id,
                        status_pengumuman='belum_diumumkan'
                    )
                    db.session.add(kelulusan_baru)
                    db.session.commit()
                    app.logger.info(f"User {user.username} ditambahkan ke daftar kelulusan")
                
                flash(f'✅ {user.nama_decrypted} dinyatakan LULUS! Notifikasi akan muncul saat siswa login.', 'success')
            
            # Jika status berubah ke TIDAK LULUS
            elif status == 'tidak_lulus' and status_sebelumnya != 'tidak_lulus':
                notifikasi = NotifikasiSiswa(
                    user_id=user_id,
                    jenis_notifikasi='tidak_lulus',
                    sudah_dibaca=False
                )
                db.session.add(notifikasi)
                db.session.commit()
                app.logger.info(f"Notifikasi TIDAK LULUS dibuat untuk user {user.username}")
                
                # Hapus dari daftar kelulusan jika ada
                kelulusan = DaftarKelulusanSementara.query.filter_by(user_id=user_id).first()
                if kelulusan:
                    db.session.delete(kelulusan)
                    db.session.commit()
                    app.logger.info(f"User {user.username} dihapus dari daftar kelulusan")
                
                flash(f'⚠️ {user.nama_decrypted} dinyatakan TIDAK LULUS. Notifikasi akan muncul saat siswa login.', 'warning')
            
            else:
                flash(f'Status {user.nama_decrypted} berhasil diupdate ke {status}!', 'success')
                
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat update status.', 'error')
            app.logger.error(f"Status update error: {str(e)}")
    
    return redirect(url_for('detail_siswa', user_id=user_id))


@app.route(f'{ADMIN_BASE_PATH}/update_dokumen_status/<int:dokumen_id>', methods=['POST'])
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
            flash('Terjadi kesalahan saat update status dokumen.', 'error')
            app.logger.error(f"Dokumen status update error: {str(e)}")
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
    judul = sanitize_input(request.form.get('judul', ''))
    isi = sanitize_input(request.form.get('isi', ''))
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
        app.logger.error(f"Pengumuman creation error: {str(e)}")
    return redirect(url_for('admin_dashboard'))


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
    isi_pengumuman += "\n\nBagi siswa yang lulus, silakan melakukan daftar ulang sesuai jadwal."
    
    new_pengumuman = Pengumuman(judul=judul, isi=isi_pengumuman)
    try:
        db.session.add(new_pengumuman)
        db.session.commit()
        flash(f'Pengumuman kelulusan berhasil dipublish! {len(daftar_kelulusan)} siswa diumumkan.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat mempublish pengumuman.', 'error')
        app.logger.error(f"Publish pengumuman error: {str(e)}")
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


# ========== INITIALIZATION ==========
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()
        # Cek admin dengan username ADMIN412
        admin_user = User.query.filter_by(username='ADMIN412', role='admin').first()
        
        if not admin_user:
            admin_password = os.environ.get('ADMIN_PASSWORD')
            if admin_password:
                admin = User(username='ADMIN412', role='admin', status='aktif')
                admin.set_password(admin_password)
                admin.set_encrypted_data(nama='Administrator 412')
                db.session.add(admin)
                db.session.commit()
                print("✅ Admin ADMIN412 berhasil dibuat.")
            else:
                print("=" * 60)
                print("⚠️ PERINGATAN: Belum ada admin!")
                print("Buat admin dengan perintah:")
                print('export ADMIN_PASSWORD="bismillah412"')
                print("Atau buat manual dengan python")
                print("=" * 60)

    print("=" * 60)
    print("🚀 SERVER STARTED SUCCESSFULLY!")
    print(f"📁 Admin path: {ADMIN_BASE_PATH}")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
