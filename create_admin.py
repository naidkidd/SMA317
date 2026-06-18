#!/usr/bin/env python3
import sys
import os
from dotenv import load_dotenv

load_dotenv()

from ppdb import app
from models import db, User

def create_admin(username, password, email, nama="Administrator"):
    """Buat akun admin dengan email untuk OTP"""
    with app.app_context():
        existing = User.query.filter_by(username=username, role='admin').first()
        if existing:
            print(f"❌ Admin dengan username '{username}' sudah ada!")
            return False
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            print(f"❌ Email '{email}' sudah terdaftar!")
            return False
        
        admin = User(
            username=username,
            role='admin',
            status='admin',
            email=email
        )
        admin.set_password(password)
        admin.nama = nama
        
        db.session.add(admin)
        db.session.commit()
        
        print("=" * 60)
        print("✅ ADMIN BERHASIL DIBUAT!")
        print("=" * 60)
        print(f"📝 Username : {username}")
        print(f"📝 Email    : {email}")
        print(f"📝 Password : {password}")
        print(f"📝 Nama     : {nama}")
        print("=" * 60)
        print("🔐 Gunakan email dan password untuk login")
        print("📧 OTP akan dikirim ke email saat login")
        print("=" * 60)
        return True

def list_admins():
    with app.app_context():
        admins = User.query.filter_by(role='admin').all()
        if not admins:
            print("❌ Belum ada admin terdaftar.")
            return
        
        print("=" * 60)
        print("📋 DAFTAR ADMIN")
        print("=" * 60)
        for admin in admins:
            print(f"ID       : {admin.id}")
            print(f"Username : {admin.username}")
            print(f"Email    : {admin.email or '-'}")
            print(f"Nama     : {admin.nama}")
            print("-" * 40)

def reset_password(username, new_password):
    with app.app_context():
        admin = User.query.filter_by(username=username, role='admin').first()
        if not admin:
            print(f"❌ Admin '{username}' tidak ditemukan!")
            return False
        
        admin.set_password(new_password)
        db.session.commit()
        
        print(f"✅ Password admin '{username}' berhasil direset!")
        print(f"📝 Password baru: {new_password}")
        return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("=" * 60)
        print("🔐 ADMIN MANAGEMENT TOOL")
        print("=" * 60)
        print("\nUsage:")
        print("  python create_admin.py create <username> <password> <email> [nama]")
        print("  python create_admin.py list")
        print("  python create_admin.py reset <username> <new_password>")
        print("\nExamples:")
        print("  python create_admin.py create ADMIN412 bismillah412 fush1gurammm@gmail.com")
        print("  python create_admin.py list")
        print("  python create_admin.py reset ADMIN412 bismillah412baru")
        print("=" * 60)
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'create':
        if len(sys.argv) < 5:
            print("❌ Usage: python create_admin.py create <username> <password> <email> [nama]")
            sys.exit(1)
        
        username = sys.argv[2]
        password = sys.argv[3]
        email = sys.argv[4]
        nama = sys.argv[5] if len(sys.argv) > 5 else "Administrator"
        
        create_admin(username, password, email, nama)
    
    elif command == 'list':
        list_admins()
    
    elif command == 'reset':
        if len(sys.argv) < 4:
            print("❌ Usage: python create_admin.py reset <username> <new_password>")
            sys.exit(1)
        
        username = sys.argv[2]
        new_password = sys.argv[3]
        reset_password(username, new_password)
    
    else:
        print(f"❌ Perintah '{command}' tidak dikenal.")
        print("Perintah yang tersedia: create, list, reset")
