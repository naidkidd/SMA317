from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import base64
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv

# Load environment variables FIRST
load_dotenv()

db = SQLAlchemy()

# ========== KONFIGURASI ENKRIPSI CHACHA20 ==========
ENCRYPTION_KEY_B64 = os.environ.get('CHACHA20_KEY')
if not ENCRYPTION_KEY_B64:
    # Coba baca dari file .env jika environment tidak terbaca
    env_file = '/var/www/html/SMA-317/.env'
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                if line.startswith('CHACHA20_KEY='):
                    ENCRYPTION_KEY_B64 = line.split('=')[1].strip()
                    break

    if not ENCRYPTION_KEY_B64:
        raise RuntimeError("CHACHA20_KEY tidak diset. Pastikan file .env ada dan berisi CHACHA20_KEY")

# Decode key - pastikan panjangnya 32 bytes
ENCRYPTION_KEY = base64.urlsafe_b64decode(ENCRYPTION_KEY_B64 + '==')
if len(ENCRYPTION_KEY) != 32:
    # Coba tanpa padding
    ENCRYPTION_KEY = base64.urlsafe_b64decode(ENCRYPTION_KEY_B64)
    if len(ENCRYPTION_KEY) != 32:
        raise RuntimeError(f"CHACHA20_KEY must be 32 bytes, got {len(ENCRYPTION_KEY)} bytes")

print(f"[INFO] Encryption key loaded: {ENCRYPTION_KEY_B64[:20]}...")

# ========== ARGON2ID PASSWORD HASHER ==========
ph = PasswordHasher()

def encrypt_data(plaintext):
    """Enkripsi dengan ChaCha20. Output: base64(nonce (12 byte) + ciphertext)"""
    if plaintext is None or plaintext == '':
        return plaintext
    
    # Jika sudah terenkripsi (mengandung karakter base64 yang valid), return as-is
    if isinstance(plaintext, str) and len(plaintext) > 20:
        try:
            # Coba decode - jika berhasil berarti sudah terenkripsi
            padded = plaintext + '=' * (4 - len(plaintext) % 4)
            base64.urlsafe_b64decode(padded)
            return plaintext
        except:
            pass
    
    try:
        nonce = secrets.token_bytes(16)
        cipher = Cipher(
            algorithms.ChaCha20(ENCRYPTION_KEY, nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        combined = nonce + ciphertext
        result = base64.urlsafe_b64encode(combined).decode('utf-8')
        return result
    except Exception as e:
        print(f"Encryption error for '{plaintext[:20]}...': {e}")
        return plaintext

def decrypt_data(encrypted_b64):
    """Dekripsi data yang dienkripsi dengan encrypt_data"""
    if encrypted_b64 is None or encrypted_b64 == '':
        return encrypted_b64
    
    if not isinstance(encrypted_b64, str):
        return encrypted_b64
    
    # Coba lihat apakah ini plain text (bukan base64)
    if len(encrypted_b64) < 20:
        return encrypted_b64
    
    try:
        # Handle padding base64
        padded = encrypted_b64
        missing_padding = len(padded) % 4
        if missing_padding:
            padded += '=' * (4 - missing_padding)
        
        combined = base64.urlsafe_b64decode(padded)
        
        if len(combined) < 13:  # Minimal 12 byte nonce + 1 byte data
            return encrypted_b64
        
        nonce = combined[:16]
        ciphertext = combined[16:]
        
        cipher = Cipher(
            algorithms.ChaCha20(ENCRYPTION_KEY, nonce),
            mode=None,
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        # Jika gagal, kemungkinan ini plain text
        return encrypted_b64

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
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
            if ph.check_needs_rehash(self.password_hash):
                self.password_hash = ph.hash(password)
                db.session.commit()
            return True
        except VerifyMismatchError:
            return False
        except Exception as e:
            print(f"Error checking password: {e}")
            return False

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
        for key, value in kwargs.items():
            if hasattr(self, key) and value is not None:
                encrypted_value = encrypt_data(str(value))
                setattr(self, key, encrypted_value)

# ========== MODEL LAINNYA ==========
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
