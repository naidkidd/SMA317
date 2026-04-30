from ppdb import app
from models import db

with app.app_context():
    # Hapus semua tabel
    db.drop_all()
    
    # Buat ulang semua tabel dengan struktur yang benar
    db.create_all()
    print("✅ Tabel berhasil dibuat ulang!")
    
    # Buat admin default
    from models import User
    admin = User(username='admin', role='admin', status='aktif')
    admin.set_password('admin123')
    admin.set_encrypted_data(nama='Administrator')
    db.session.add(admin)
    db.session.commit()
    print("✅ Admin dibuat: username=admin, password=admin123")
    
    # Cek struktur kolom password_hash
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    columns = inspector.get_columns('user')
    for col in columns:
        if col['name'] == 'password_hash':
            print(f"✅ password_hash type: {col['type']}, length: {getattr(col['type'], 'length', 'N/A')}")
