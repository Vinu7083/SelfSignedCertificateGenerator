import sqlite3
from datetime import datetime
import time
import threading
from contextlib import contextmanager

DB_PATH = 'analysis_data.db'
MAX_RETRIES = 3
RETRY_DELAY = 0.1  # seconds

class AnalysisDB:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Initialize the database with proper settings."""
        try:
            with self._get_connection() as conn:
                conn.execute('PRAGMA journal_mode=WAL')  # Use Write-Ahead Logging
                conn.execute('PRAGMA busy_timeout=5000')  # 5 second timeout
                self.create_tables(conn)
        except Exception as e:
            print(f"Error initializing database: {e}")
            raise

    @contextmanager
    def _get_connection(self):
        """Get a database connection with retry logic."""
        conn = None
        try:
            for attempt in range(MAX_RETRIES):
                try:
                    conn = sqlite3.connect(self.db_path, timeout=5.0)
                    yield conn
                    return
                except sqlite3.OperationalError as e:
                    if attempt == MAX_RETRIES - 1:
                        raise
                    time.sleep(RETRY_DELAY)
                except Exception as e:
                    print(f"Unexpected error during database connection: {e}")
                    raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception as e:
                    print(f"Error closing database connection: {e}")

    def create_tables(self, conn=None):
        """Create the necessary tables if they don't exist."""
        try:
            with self._get_connection() as conn:
                c = conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_address TEXT,
                    message TEXT,
                    timestamp TEXT
                )''')
                c.execute('''CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_address TEXT,
                    event TEXT,
                    timestamp TEXT
                )''')
                conn.commit()
        except Exception as e:
            print(f"Error creating tables: {e}")
            raise

    def save_message(self, client_address, message, timestamp):
        """Save a message to the database with retry logic."""
        try:
            with self._lock:
                with self._get_connection() as conn:
                    c = conn.cursor()
                    c.execute('INSERT INTO messages (client_address, message, timestamp) VALUES (?, ?, ?)',
                             (client_address, message, timestamp.isoformat()))
                    conn.commit()
        except Exception as e:
            print(f"Error saving message: {e}")
            raise

    def save_connection_event(self, client_address, event, timestamp):
        """Save a connection event to the database with retry logic."""
        try:
            with self._lock:
                with self._get_connection() as conn:
                    c = conn.cursor()
                    c.execute('INSERT INTO connections (client_address, event, timestamp) VALUES (?, ?, ?)',
                             (client_address, event, timestamp.isoformat()))
                    conn.commit()
        except Exception as e:
            print(f"Error saving connection event: {e}")
            raise

    def load_messages(self):
        """Load messages from the database with retry logic."""
        try:
            with self._lock:
                with self._get_connection() as conn:
                    c = conn.cursor()
                    c.execute('SELECT client_address, message, timestamp FROM messages ORDER BY id ASC')
                    rows = c.fetchall()
                    return [(addr, msg, datetime.fromisoformat(ts)) for addr, msg, ts in rows]
        except Exception as e:
            print(f"Error loading messages: {e}")
            raise

    def load_connections(self):
        """Load connection events from the database with retry logic."""
        try:
            with self._lock:
                with self._get_connection() as conn:
                    c = conn.cursor()
                    c.execute('SELECT client_address, event, timestamp FROM connections ORDER BY id ASC')
                    rows = c.fetchall()
                    return [(addr, event, datetime.fromisoformat(ts)) for addr, event, ts in rows]
        except Exception as e:
            print(f"Error loading connections: {e}")
            raise
