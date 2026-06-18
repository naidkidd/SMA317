from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import base64
import secrets
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv

load_dotenv()
db = SQLAlchemy()

logger = logging.getLogger(__name__)

# ========== CHACHA20 ENKRIPSI ==========
ENCRYPTION_KEY_B64 = os.environ.get('CHACHA20_KEY')
if not ENCRYPTION_KEY_B64:
    raise RuntimeError("CHACHA20_KEY tidak diset di environment variables")

try:
    ENCRYPTION_KEY = base64.urlsafe_b64decode(ENCRYPTION_KEY_B64 + '==')
    if len(ENCRYPTION_KEY) != 32:
        ENCRYPTION_KEY = base64.urlsafe_b64decode(ENCRYPTION_KEY_B64)
        if len(ENCRYPTION_KEY) != 32:
            raise ValueError(f"CHACHA20_KEY must be 32 bytes, got {len(ENCRYPTION_KEY)}")
except Exception as e:
    raise RuntimeError(f"Invalid CHACHA20_KEY: {e}")

logger.info(f"[INFO] ChaCha20 encryption active with key length: {len(ENCRYPTION_KEY)} bytes")

def encrypt_data(plaintext):
    """Encrypt data using ChaCha20"""
    if plaintext is None or plaintext == '':
        return plaintext
    
    if isinstance(plaintext, str) and len(plaintext) > 20:
        try:
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
        return base64.urlsafe_b64encode(combined).decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return plaintext

def decrypt_data(encrypted_b64):
    """Decrypt data using ChaCha20"""
    if encrypted_b64 is None or encrypted_b64 == '':
        return encrypted_b64
    
    if not isinstance(encrypted_b64, str) or len(encrypted_b64) < 20:
        return encrypted_b64
    
    try:
        padded = encrypted_b64
        missing_padding = len(padded) % 4
        if missing_padding:
            padded += '=' * (4 - missing_padding)
        
        combined = base64.urlsafe_b64decode(padded)
        if len(combined) < 17:
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
        logger.warning(f"Decryption error for value {encrypted_b64[:20]}...: {e}")
        return encrypted_b64

ph = PasswordHasher()

class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='siswa')
    email = db.Column(db.String(100), nullable=True, unique=True)  # Untuk admin OTP
    
    # Encrypted fields stored in database
    _nama = db.Column('nama', db.Text, nullable=False)
    _tempat_lahir = db.Column('tempat_lahir', db.Text, default='')
    _jenis_kelamin = db.Column('jenis_kelamin', db.Text, default='')
    _agama = db.Column('agama', db.Text, default='')
    _alamat = db.Column('alamat', db.Text, default='')
    _no_hp = db.Column('no_hp', db.Text, default='')
    _asal_sekolah = db.Column('asal_sekolah', db.Text, default='')
    _nama_ayah = db.Column('nama_ayah', db.Text, default='')
    _pekerjaan_ayah = db.Column('pekerjaan_ayah', db.Text, default='')
    _nama_ibu = db.Column('nama_ibu', db.Text, default='')
    _pekerjaan_ibu = db.Column('pekerjaan_ibu', db.Text, default='')
    
    # Non-encrypted fields
    tanggal_daftar = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='belum_lengkap')
    tanggal_lahir = db.Column(db.Date, nullable=True)
    
    # Relationships
    bukti_pendaftaran = db.relationship('BuktiPendaftaran', backref='user', lazy=True, cascade='all, delete-orphan')
    dokumen_tambahan = db.relationship('DokumenTambahan', backref='user', lazy=True, cascade='all, delete-orphan')
    notifikasi = db.relationship('NotifikasiSiswa', backref='user', lazy=True, cascade='all, delete-orphan')
    daftar_kelulusan = db.relationship('DaftarKelulusanSementara', backref='user', lazy=True, cascade='all, delete-orphan')

    # ========== PROPERTY GETTERS (AUTO-DECRYPT) ==========
    @property
    def nama(self):
        return decrypt_data(self._nama)
    
    @property
    def tempat_lahir(self):
        return decrypt_data(self._tempat_lahir)
    
    @property
    def jenis_kelamin(self):
        return decrypt_data(self._jenis_kelamin)
    
    @property
    def agama(self):
        return decrypt_data(self._agama)
    
    @property
    def alamat(self):
        return decrypt_data(self._alamat)
    
    @property
    def no_hp(self):
        return decrypt_data(self._no_hp)
    
    @property
    def asal_sekolah(self):
        return decrypt_data(self._asal_sekolah)
    
    @property
    def nama_ayah(self):
        return decrypt_data(self._nama_ayah)
    
    @property
    def pekerjaan_ayah(self):
        return decrypt_data(self._pekerjaan_ayah)
    
    @property
    def nama_ibu(self):
        return decrypt_data(self._nama_ibu)
    
    @property
    def pekerjaan_ibu(self):
        return decrypt_data(self._pekerjaan_ibu)
    
    @property
    def nama_decrypted(self):
        return self.nama
    
    @property
    def tempat_lahir_decrypted(self):
        return self.tempat_lahir
    
    @property
    def jenis_kelamin_decrypted(self):
        return self.jenis_kelamin
    
    @property
    def agama_decrypted(self):
        return self.agama
    
    @property
    def alamat_decrypted(self):
        return self.alamat
    
    @property
    def no_hp_decrypted(self):
        return self.no_hp
    
    @property
    def asal_sekolah_decrypted(self):
        return self.asal_sekolah
    
    @property
    def nama_ayah_decrypted(self):
        return self.nama_ayah
    
    @property
    def pekerjaan_ayah_decrypted(self):
        return self.pekerjaan_ayah
    
    @property
    def nama_ibu_decrypted(self):
        return self.nama_ibu
    
    @property
    def pekerjaan_ibu_decrypted(self):
        return self.pekerjaan_ibu

    # ========== PROPERTY SETTERS (AUTO-ENCRYPT) ==========
    @nama.setter
    def nama(self, value):
        if value is not None:
            self._nama = encrypt_data(str(value))
        else:
            self._nama = ''
    
    @tempat_lahir.setter
    def tempat_lahir(self, value):
        self._tempat_lahir = encrypt_data(str(value)) if value else ''
    
    @jenis_kelamin.setter
    def jenis_kelamin(self, value):
        self._jenis_kelamin = encrypt_data(str(value)) if value else ''
    
    @agama.setter
    def agama(self, value):
        self._agama = encrypt_data(str(value)) if value else ''
    
    @alamat.setter
    def alamat(self, value):
        self._alamat = encrypt_data(str(value)) if value else ''
    
    @no_hp.setter
    def no_hp(self, value):
        self._no_hp = encrypt_data(str(value)) if value else ''
    
    @asal_sekolah.setter
    def asal_sekolah(self, value):
        self._asal_sekolah = encrypt_data(str(value)) if value else ''
    
    @nama_ayah.setter
    def nama_ayah(self, value):
        self._nama_ayah = encrypt_data(str(value)) if value else ''
    
    @pekerjaan_ayah.setter
    def pekerjaan_ayah(self, value):
        self._pekerjaan_ayah = encrypt_data(str(value)) if value else ''
    
    @nama_ibu.setter
    def nama_ibu(self, value):
        self._nama_ibu = encrypt_data(str(value)) if value else ''
    
    @pekerjaan_ibu.setter
    def pekerjaan_ibu(self, value):
        self._pekerjaan_ibu = encrypt_data(str(value)) if value else ''

    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        try:
            ph.verify(self.password_hash, password)
            if ph.check_needs_rehash(self.password_hash):
                self.password_hash = ph.hash(password)
                db.session.commit()
            return True
        except VerifyMismatchError:
            return False
        except Exception as e:
            logger.error(f"Error checking password: {e}")
            return False

    def set_encrypted_data(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key) and value is not None:
                setattr(self, key, value)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'email': self.email,
            'nama': self.nama,
            'tempat_lahir': self.tempat_lahir,
            'tanggal_lahir': self.tanggal_lahir.strftime('%Y-%m-%d') if self.tanggal_lahir else None,
            'jenis_kelamin': self.jenis_kelamin,
            'agama': self.agama,
            'alamat': self.alamat,
            'no_hp': self.no_hp,
            'asal_sekolah': self.asal_sekolah,
            'nama_ayah': self.nama_ayah,
            'pekerjaan_ayah': self.pekerjaan_ayah,
            'nama_ibu': self.nama_ibu,
            'pekerjaan_ibu': self.pekerjaan_ibu,
            'status': self.status,
            'tanggal_daftar': self.tanggal_daftar.strftime('%Y-%m-%d %H:%M:%S')
        }


class BuktiPendaftaran(db.Model):
    __tablename__ = 'bukti_pendaftaran'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    tanggal_upload = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='menunggu')


class DokumenTambahan(db.Model):
    __tablename__ = 'dokumen_tambahan'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    jenis_dokumen = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    tanggal_upload = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='menunggu')
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'jenis_dokumen', name='unique_user_dokumen'),
    )


class Pengumuman(db.Model):
    __tablename__ = 'pengumuman'
    
    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    isi = db.Column(db.Text, nullable=False)
    tanggal = db.Column(db.DateTime, default=datetime.utcnow)


class DaftarKelulusanSementara(db.Model):
    __tablename__ = 'daftar_kelulusan_sementara'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, unique=True)
    tanggal_diluluskan = db.Column(db.DateTime, default=datetime.utcnow)
    status_pengumuman = db.Column(db.String(20), default='belum_diumumkan')


class NotifikasiSiswa(db.Model):
    __tablename__ = 'notifikasi_siswa'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    jenis_notifikasi = db.Column(db.String(50), nullable=False)
    sudah_dibaca = db.Column(db.Boolean, default=False)
    tanggal_dibuat = db.Column(db.DateTime, default=datetime.utcnow)
    tanggal_dibaca = db.Column(db.DateTime, nullable=True)
