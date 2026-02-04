import sqlite3
import os
from config import DB_FILE

# Ensure database folder exists
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

# ------------------- DATABASE INIT -------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password_hash BLOB,
            vault_hash BLOB,
            salt BLOB
        )
    ''')
    # Password entries table
    c.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            website TEXT,
            username TEXT,
            iv BLOB,
            ciphertext BLOB,
            note TEXT
        )
    ''')
    conn.commit()
    conn.close()

# ------------------- USER FUNCTIONS -------------------
def create_user(email, password_hash, salt):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO users (email, password_hash, salt) VALUES (?,?,?)', (email, password_hash, salt))
    conn.commit()
    conn.close()

def get_user(email):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email=?', (email,))
    user = c.fetchone()
    conn.close()
    return user

def set_vault_hash(email, vault_hash):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE users SET vault_hash=? WHERE email=?', (vault_hash,email))
    conn.commit()
    conn.close()

# ------------------- PASSWORD FUNCTIONS -------------------
def save_password(user_email, website, username, iv, ciphertext, note):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO passwords (user_email, website, username, iv, ciphertext, note)
        VALUES (?,?,?,?,?,?)
    ''', (user_email, website, username, iv, ciphertext, note))
    conn.commit()
    conn.close()

def get_passwords(user_email):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM passwords WHERE user_email=? ORDER BY created_at DESC', (user_email,))
    rows = c.fetchall()
    conn.close()
    return rows

def update_password(entry_id, website, username, iv, ciphertext, note):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        UPDATE passwords
        SET website=?, username=?, iv=?, ciphertext=?, note=?
        WHERE id=?
    ''', (website, username, iv, ciphertext, note, entry_id))
    conn.commit()
    conn.close()

def delete_password(entry_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('DELETE FROM passwords WHERE id=?', (entry_id,))
    conn.commit()
    conn.close()
