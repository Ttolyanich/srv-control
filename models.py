import os
import base64
import hashlib
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

db = SQLAlchemy()

def _get_fernet_cipher():
    key = os.environ.get('FERNET_KEY')
    if not key:
        secret = os.environ.get('SECRET_KEY', 'srv_control_secret_key_9988_secure_prod')
        hash_bytes = hashlib.sha256(secret.encode()).digest()
        key = base64.urlsafe_b64encode(hash_bytes)
    return Fernet(key)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' или 'user'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(100), nullable=True)
    type = db.Column(db.String(20), default='manual')  # 'manual', 'proxmox', 'proxmox_node', 'backup_ssh'
    cpu = db.Column(db.Integer, default=0)              # Всего ядер физически
    ram = db.Column(db.Integer, default=0)              # Всего оперативной памяти (ГБ)
    ssd = db.Column(db.Integer, default=0)              # Всего SSD (ГБ)
    hdd = db.Column(db.Integer, default=0)              # Всего HDD (ГБ)
    status = db.Column(db.String(20), default='unknown') # 'online', 'offline', 'unknown'
    last_sync = db.Column(db.DateTime, nullable=True)
    deleted = db.Column(db.Boolean, default=False)       # Мягкое удаление
    expense = db.Column(db.Float, default=0.0, nullable=True) # Расходы хоста в месяц (себестоимость)
    backup_path = db.Column(db.String(200), default='/') # Путь к бэкап-директории для df

    # Индивидуальная ценовая политика для сервера/кластера
    cpu_price = db.Column(db.Float, nullable=True, default=None)
    ram_price_gb = db.Column(db.Float, nullable=True, default=None)
    ssd_price_gb = db.Column(db.Float, nullable=True, default=None)
    hdd_price_gb = db.Column(db.Float, nullable=True, default=None)
    backup_price_gb = db.Column(db.Float, nullable=True, default=None)

    parent_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=True)
    child_nodes = db.relationship('Server', backref=db.backref('parent', remote_side=[id]), cascade="all, delete-orphan")

    virtual_machines = db.relationship('VirtualMachine', backref='server', lazy=True, cascade="all, delete-orphan")
    quotas = db.relationship('CompanyQuota', backref='server', lazy=True, cascade="all, delete-orphan")
    sync_config = db.relationship('SyncConfig', backref='server', uselist=False, cascade="all, delete-orphan")
    
    storages = db.relationship('ProxmoxStorage', backref='server', lazy=True, cascade="all, delete-orphan")

    def get_allocated_resources(self):
        vms = [vm for vm in self.virtual_machines if not vm.deleted]
        return {
            'cpu': sum(vm.cpu for vm in vms),
            'ram': sum(vm.ram for vm in vms),
            'ssd': sum(vm.ssd for vm in vms),
            'hdd': sum(vm.hdd for vm in vms)
        }

class VirtualMachine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    vmid = db.Column(db.Integer, nullable=True)          # ID в Proxmox
    name = db.Column(db.String(100), nullable=False)
    cpu = db.Column(db.Integer, default=0)
    ram = db.Column(db.Integer, default=0)              # ГБ
    ssd = db.Column(db.Integer, default=0)              # ГБ
    hdd = db.Column(db.Integer, default=0)              # ГБ
    status = db.Column(db.String(20), default='unknown') # 'running', 'stopped', 'unknown'
    deleted = db.Column(db.Boolean, default=False)
    manual_price = db.Column(db.Float, nullable=True, default=None) # Ручной ценник (переопределение)
    comment = db.Column(db.String(255), nullable=True, default=None) # Комментарий (клиент / назначение)

class CompanyQuota(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    system_name = db.Column(db.String(100), nullable=True)
    system_type = db.Column(db.String(10), default='user')   # 'user' или 'group'
    allocated_quota = db.Column(db.Integer, default=0)       # Выделено по договору (ГБ)
    system_hard_limit = db.Column(db.Float, default=0.0)     # Жесткий лимит из ОС (ГБ)
    actual_usage = db.Column(db.Float, default=0.0)          # Использовано по факту (ГБ)
    last_sync = db.Column(db.DateTime, nullable=True)
    is_hidden = db.Column(db.Boolean, default=False)         # Скрывать из общих отчетов
    manual_price = db.Column(db.Float, nullable=True, default=None) # Ручной ценник (переопределение)
    comment = db.Column(db.String(255), nullable=True, default=None) # Комментарий (клиент / назначение)

class SyncConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    username = db.Column(db.String(100), nullable=True)
    password_or_token = db.Column(db.Text, nullable=True)
    extra_param = db.Column(db.String(200), nullable=True)

    def set_password(self, password):
        if not password:
            self.password_or_token = None
            return
        
        f = _get_fernet_cipher()
        self.password_or_token = f.encrypt(password.encode()).decode()

    def get_password(self):
        if not self.password_or_token:
            return None
            
        f = _get_fernet_cipher()
        try:
            # Fernet-токены обычно начинаются с gAAAAA
            # Если это не Fernet-токен, то decrypt выбросит ошибку, и мы вернем исходную строку
            return f.decrypt(self.password_or_token.encode()).decode()
        except Exception:
            return self.password_or_token

class ProxmoxStorage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    storage_name = db.Column(db.String(100), nullable=False)
    storage_type = db.Column(db.String(20), default='ssd')                        # 'ssd', 'hdd', 'ignore'

class PricingPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cpu_price = db.Column(db.Float, default=2000.0)
    ram_price_gb = db.Column(db.Float, default=800.0)
    ssd_price_gb = db.Column(db.Float, default=80.0)
    hdd_price_gb = db.Column(db.Float, default=30.0)
    backup_price_gb = db.Column(db.Float, default=40.0)
    sync_interval_hours = db.Column(db.Integer, default=1, nullable=False)
