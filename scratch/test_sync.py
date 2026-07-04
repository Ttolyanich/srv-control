import os
import sys
# Добавляем корневой путь в sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from models import db, Server
from sync_engine import run_sync

def test():
    with app.app_context():
        # Находим сервер по ID
        server_id = 2
        if len(sys.argv) > 1:
            server_id = int(sys.argv[1])
            
        server = Server.query.get(server_id)
        if not server:
            print(f"Error: Server with ID {server_id} not found!")
            return
            
        print(f"Starting test sync for server: {server.name} ({server.ip_address}, type: {server.type})")
        success, message = run_sync(server)
        print("Sync execution completed.")
        print(f"Result (Success): {success}")
        print(f"Result (Message): {message}")

if __name__ == '__main__':
    test()
