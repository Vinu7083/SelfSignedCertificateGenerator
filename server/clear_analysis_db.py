import sqlite3

DB_PATH = 'analysis_data.db'

def clear_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM messages')
    c.execute('DELETE FROM connections')
    conn.commit()
    conn.close()
    print("All analysis data has been deleted.")

if __name__ == "__main__":
    clear_db()
