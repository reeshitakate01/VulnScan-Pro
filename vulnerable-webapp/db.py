import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'vulnapp.db')

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE guestbook (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            message TEXT NOT NULL
        )
    ''')
    
    # Seed Data
    users = [
        ('admin', 'admin123', 'admin'),
        ('guest', 'guest', 'user')
    ]
    cursor.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", users)
    
    messages = [
        ('System', 'Welcome to the guestbook! Feel free to leave a message. HTML supported (oops).')
    ]
    cursor.executemany("INSERT INTO guestbook (name, message) VALUES (?, ?)", messages)
    
    conn.commit()
    conn.close()
    print(f"[*] Database initialized successfully at {DB_PATH}")

if __name__ == '__main__':
    init_db()
