import os
import sys
# Добавляем корневой путь в sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from models import db, Server, CompanyQuota

def run():
    with app.app_context():
        print("Starting cleanup of subusers...")
        # Находим все бэкап-серверы
        backup_servers = Server.query.filter_by(deleted=False, type='backup_ssh').all()
        for server in backup_servers:
            print(f"Checking server: {server.name} (ID: {server.id})")
            all_quotas = CompanyQuota.query.filter_by(server_id=server.id).all()
            
            group_names = set()
            for q in all_quotas:
                if q.system_type == 'group' and q.system_name and q.system_name.startswith('G-'):
                    base_name = q.system_name[2:]
                    if base_name:
                        group_names.add(base_name)
            
            updated_count = 0
            if group_names:
                for q in all_quotas:
                    if q.system_type == 'user' and q.system_name:
                        is_subuser = False
                        for base in group_names:
                            if q.system_name == base or q.system_name.startswith(base + '-'):
                                is_subuser = True
                                break
                        if is_subuser and not q.is_hidden:
                            q.is_hidden = True
                            updated_count += 1
            
            if updated_count > 0:
                print(f"  Marked {updated_count} user quotas as hidden.")
            else:
                print("  No new user quotas to hide.")
                
        db.session.commit()
        print("Cleanup completed successfully.")

if __name__ == '__main__':
    run()
