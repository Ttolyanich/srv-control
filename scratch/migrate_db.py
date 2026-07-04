import sqlite3
import os
import sys

def migrate(db_path):
    print(f"Connecting to database: {db_path}")
    if not os.path.exists(db_path):
        print(f"Error: Database file does not exist at {db_path}")
        return False
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Получаем структуру таблицы server
    cursor.execute("PRAGMA table_info(server)")
    columns = [col[1] for col in cursor.fetchall()]
    
    new_cols = {
        "cpu_price": "FLOAT DEFAULT NULL",
        "ram_price_gb": "FLOAT DEFAULT NULL",
        "ssd_price_gb": "FLOAT DEFAULT NULL",
        "hdd_price_gb": "FLOAT DEFAULT NULL",
        "backup_price_gb": "FLOAT DEFAULT NULL"
    }
    
    mutated = False
    for col_name, col_type in new_cols.items():
        if col_name not in columns:
            print(f"Adding column {col_name} to table 'server'...")
            cursor.execute(f"ALTER TABLE server ADD COLUMN {col_name} {col_type}")
            mutated = True
        else:
            print(f"Column {col_name} already exists.")
            
    if mutated:
        conn.commit()
        print("Migration applied successfully!")
    else:
        print("No migration needed.")
        
    conn.close()
    return True

if __name__ == "__main__":
    path = "instance/srv_control.db"
    if len(sys.argv) > 1:
        path = sys.argv[1]
    migrate(path)
