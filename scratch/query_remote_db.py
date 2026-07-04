import sqlite3
import sys
import paramiko
import io

def main():
    db_path = 'instance/srv_control.db'
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    
    conn = sqlite3.connect(db_path)
    # Получаем учетные данные сервера ID 2
    server = conn.execute('SELECT ip_address, backup_path FROM server WHERE id=2').fetchone()
    config = conn.execute('SELECT username, password_or_token, extra_param FROM sync_config WHERE server_id=2').fetchone()
    conn.close()
    
    if not server or not config:
        print("Server or config not found in DB!")
        return
        
    ip = server[0]
    username = config[0]
    secret = config[1] or ""
    port = int(config[2] or 22)
    
    print(f"Connecting to backup server: {ip}:{port} as {username}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if secret.strip().startswith("-----BEGIN"):
            key_file = io.StringIO(secret)
            pkey = paramiko.RSAKey.from_private_key(key_file)
            ssh.connect(ip, port=port, username=username, pkey=pkey, timeout=15)
        else:
            ssh.connect(ip, port=port, username=username, password=secret, timeout=15)
            
        print("SSH Connection successful!")
        
        # Запускаем repquota -g -a
        stdin, stdout, stderr = ssh.exec_command("sudo repquota -g -a")
        output = stdout.read().decode('utf-8', errors='ignore')
        
        print("\n=== RAW output of sudo repquota -g -a ===")
        # Ищем строку с G-elite-stroy-group
        lines = output.strip().split('\n')
        found = False
        for line in lines:
            if 'G-elite-stroy-group' in line:
                print("FOUND:", line)
                found = True
        
        if not found:
            print("G-elite-stroy-group NOT found in output. Printing first 20 lines of output:")
            for l in lines[:20]:
                print(l)
                
    except Exception as e:
        print("SSH Error:", e)
    finally:
        ssh.close()

if __name__ == '__main__':
    main()
