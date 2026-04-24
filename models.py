from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
import base64
from cryptography.fernet import Fernet
import os

db = SQLAlchemy()

# Generate encryption key
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'ppdb-317-encryption-key-32-chars-long')
cipher_suite = Fernet(base64.urlsafe_b64encode(hashlib.sha256(ENCRYPTION_KEY.encode()).digest()))

def encrypt_data(data):
    """Encrypt data menggunakan symmetric encryption"""
    if data is None or data == '':
        return data
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return data

def decrypt_data(encrypted_data):
    """Decrypt data menggunakan symmetric encryption"""
    if encrypted_data is None or encrypted_data == '':
        return encrypted_data
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return encrypted_data

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    nama = db.Column(db.Text, nullable=False)
    tanggal_daftar = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='belum_lengkap')  # 'belum_lengkap', 'menunggu', 'lulus', 'tidak_lulus', 'selesai'

    # Additional fields for students - semua akan dienkripsi
    tempat_lahir = db.Column(db.Text, default='')
    tanggal_lahir = db.Column(db.Date, nullable=True)
    jenis_kelamin = db.Column(db.Text, default='')
    agama = db.Column(db.Text, default='')
    alamat = db.Column(db.Text, default='')
    no_hp = db.Column(db.Text, default='')
    asal_sekolah = db.Column(db.Text, default='')
    nama_ayah = db.Column(db.Text, default='')
    pekerjaan_ayah = db.Column(db.Text, default='')
    nama_ibu = db.Column(db.Text, default='')
    pekerjaan_ibu = db.Column(db.Text, default='')

    def set_password(self, password):
        """Hash password dengan SHA256"""
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        """Verifikasi password dengan SHA256"""
        try:
            return self.password_hash == hashlib.sha256(password.encode()).hexdigest()
        except Exception as e:
            print(f"Error checking password: {e}")
            return False

    # Property untuk mengakses data terdekripsi
    @property
    def nama_decrypted(self):
        return decrypt_data(self.nama)

    @property
    def tempat_lahir_decrypted(self):
        return decrypt_data(self.tempat_lahir)

    @property
    def jenis_kelamin_decrypted(self):
        return decrypt_data(self.jenis_kelamin)

    @property
    def agama_decrypted(self):
        return decrypt_data(self.agama)

    @property
    def alamat_decrypted(self):
        return decrypt_data(self.alamat)

    @property
    def no_hp_decrypted(self):
        return decrypt_data(self.no_hp)

    @property
    def asal_sekolah_decrypted(self):
        return decrypt_data(self.asal_sekolah)

    @property
    def nama_ayah_decrypted(self):
        return decrypt_data(self.nama_ayah)

    @property
    def pekerjaan_ayah_decrypted(self):
        return decrypt_data(self.pekerjaan_ayah)

    @property
    def nama_ibu_decrypted(self):
        return decrypt_data(self.nama_ibu)

    @property
    def pekerjaan_ibu_decrypted(self):
        return decrypt_data(self.pekerjaan_ibu)

    def set_encrypted_data(self, **kwargs):
        """Set data dengan enkripsi otomatis"""
        for key, value in kwargs.items():
            if hasattr(self, key) and value is not None:
                encrypted_value = encrypt_data(str(value))
                setattr(self, key, encrypted_value)

class BuktiPendaftaran(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    tanggal_upload = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='menunggu')

class DokumenTambahan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    jenis_dokumen = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    tanggal_upload = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='menunggu')

class Pengumuman(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    isi = db.Column(db.Text, nullable=False)
    tanggal = db.Column(db.DateTime, default=datetime.utcnow)

class DaftarKelulusanSementara(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tanggal_diluluskan = db.Column(db.DateTime, default=datetime.utcnow)
    status_pengumuman = db.Column(db.String(20), default='belum_diumumkan')

class NotifikasiSiswa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    jenis_notifikasi = db.Column(db.String(50), nullable=False)  # 'pendaftaran_selesai', 'lulus', 'tidak_lulus'
    sudah_dibaca = db.Column(db.Boolean, default=False)
    tanggal_dibuat = db.Column(db.DateTime, default=datetime.utcnow)
    tanggal_dibaca = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', backref='notifikasi')
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import base64
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

db = SQLAlchemy()

# ========== KONFIGURASI ENKRIPSI CHACHA20 ==========
ENCRYPTION_KEY_B64 = os.environ.get('CHACHA20_KEY')
if not ENCRYPTION_KEY_B64:
    raise RuntimeError("Environment variable CHACHA20_KEY tidak diset. Generate dengan: python -c 'import secrets; print(secrets.token_urlsafe(32))'")
ENCRYPTION_KEY = base64.urlsafe_b64decode(ENCRYPTION_KEY_B64)  # 32 bytes

# ========== ARGON2ID PASSWORD HASHER ==========
ph = PasswordHasher()

def encrypt_data(plaintext):
    """Enkripsi dengan ChaCha20. Output: base64(nonce (12 byte) + ciphertext)"""
    if plaintext is None or plaintext == '':
        return plaintext
    try:
        nonce = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.ChaCha20(ENCRYPTION_KEY, nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        combined = nonce + ciphertext
        return base64.urlsafe_b64encode(combined).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return plaintext

def decrypt_data(encrypted_b64):
    """Dekripsi data yang dienkripsi dengan encrypt_data"""
    if encrypted_b64 is None or encrypted_b64 == '':
        return encrypted_b64
    try:
        combined = base64.urlsafe_b64decode(encrypted_b64)
        nonce = combined[:12]
        ciphertext = combined[12:]
        cipher = Cipher(
            algorithms.ChaCha20(ENCRYPTION_KEY, nonce),
            mode=None,
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return encrypted_b64

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # Argon2 hash
    role = db.Column(db.String(10), nullable=False)
    nama = db.Column(db.Text, nullable=False)
    tanggal_daftar = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='belum_lengkap')

    # Field data pribadi (dienkripsi)
    tempat_lahir = db.Column(db.Text, default='')
    tanggal_lahir = db.Column(db.Date, nullable=True)
    jenis_kelamin = db.Column(db.Text, default='')
    agama = db.Column(db.Text, default='')
    alamat = db.Column(db.Text, default='')
    no_hp = db.Column(db.Text, default='')
    asal_sekolah = db.Column(db.Text, default='')
    nama_ayah = db.Column(db.Text, default='')
    pekerjaan_ayah = db.Column(db.Text, default='')
    nama_ibu = db.Column(db.Text, default='')
    pekerjaan_ibu = db.Column(db.Text, default='')

    def set_password(self, password):
        """Hash password dengan Argon2id"""
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        """Verifikasi password dengan Argon2id"""
        try:
            ph.verify(self.password_hash, password)
            # Rehash jika parameter berubah (opsional)
            if ph.check_needs_rehash(self.password_hash):
                self.password_hash = ph.hash(password)
                db.session.commit()
            return True
        except VerifyMismatchError:
            return False
        except Exception as e:
            print(f"Error checking password: {e}")
            return False

    # Property untuk data terdekripsi
    @property
    def nama_decrypted(self):
        return decrypt_data(self.nama)

    @property
    def tempat_lahir_decrypted(self):
        return decrypt_data(self.tempat_lahir)

    @property
    def jenis_kelamin_decrypted(self):
        return decrypt_data(self.jenis_kelamin)

    @property
    def agama_decrypted(self):
        return decrypt_data(self.agama)

    @property
    def alamat_decrypted(self):
        return decrypt_data(self.alamat)

    @property
    def no_hp_decrypted(self):
        return decrypt_data(self.no_hp)

    @property
    def asal_sekolah_decrypted(self):
        return decrypt_data(self.asal_sekolah)

    @property
    def nama_ayah_decrypted(self):
        return decrypt_data(self.nama_ayah)

    @property
    def pekerjaan_ayah_decrypted(self):
        return decrypt_data(self.pekerjaan_ayah)

    @property
    def nama_ibu_decrypted(self):
        return decrypt_data(self.nama_ibu)

    @property
    def pekerjaan_ibu_decrypted(self):
        return decrypt_data(self.pekerjaan_ibu)

    def set_encrypted_data(self, **kwargs):
        """Set data dengan enkripsi otomatis"""
        for key, value in kwargs.items():
            if hasattr(self, key) and value is not None:
                encrypted_value = encrypt_data(str(value))
                setattr(self, key, encrypted_value)

# ========== MODEL LAINNYA (TIDAK BERUBAH) ==========
class BuktiPendaftaran(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    tanggal_upload = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='menunggu')

class DokumenTambahan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    jenis_dokumen = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    tanggal_upload = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='menunggu')

class Pengumuman(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    isi = db.Column(db.Text, nullable=False)
    tanggal = db.Column(db.DateTime, default=datetime.utcnow)

class DaftarKelulusanSementara(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tanggal_diluluskan = db.Column(db.DateTime, default=datetime.utcnow)
    status_pengumuman = db.Column(db.String(20), default='belum_diumumkan')

class NotifikasiSiswa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    jenis_notifikasi = db.Column(db.String(50), nullable=False)
    sudah_dibaca = db.Column(db.Boolean, default=False)
    tanggal_dibuat = db.Column(db.DateTime, default=datetime.utcnow)
    tanggal_dibaca = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref='notifikasi')