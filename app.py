from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, session, flash
from models import db, User, Server, VirtualMachine, CompanyQuota, SyncConfig, ProxmoxStorage, PricingPolicy
from datetime import datetime
from functools import wraps
import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', os.environ.get('DATABASE_URL', 'sqlite:///srv_control.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Рекомендуется заменить SECRET_KEY на случайную строку в продакшене
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'srv_control_secret_key_9988_secure_prod')

# Инициализация базы данных
db.init_app(app)

# Регистрация стандартных функций в шаблонах Jinja2
app.jinja_env.globals.update(min=min, max=max, round=round)

# -------------------- Декораторы безопасности --------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return "Доступ запрещен. Требуются права Администратора.", 403
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_user():
    if 'user_id' in session:
        return {
            'current_user': {
                'id': session.get('user_id'),
                'username': session.get('username'),
                'role': session.get('role')
            }
        }
    return {'current_user': None}

# -------------------- Инициализация и миграция БД --------------------

def migrate_db():
    """
    Автоматическая миграция схемы БД SQLite на лету.
    Добавляет новые колонки manual_price, comment и expense, если они отсутствуют, без удаления данных.
    """
    with app.app_context():
        # Пытаемся добавить колонку manual_price в таблицу virtual_machine
        try:
            db.session.execute(db.text("ALTER TABLE virtual_machine ADD COLUMN manual_price FLOAT"))
            db.session.commit()
            print("Миграция: Добавлена колонка manual_price в virtual_machine")
        except Exception:
            db.session.rollback()

        # Пытаемся добавить колонку comment в таблицу virtual_machine
        try:
            db.session.execute(db.text("ALTER TABLE virtual_machine ADD COLUMN comment VARCHAR(255)"))
            db.session.commit()
            print("Миграция: Добавлена колонка comment в virtual_machine")
        except Exception:
            db.session.rollback()

        # Пытаемся добавить колонку expense в таблицу server
        try:
            db.session.execute(db.text("ALTER TABLE server ADD COLUMN expense FLOAT"))
            db.session.commit()
            print("Миграция: Добавлена колонка expense в server")
        except Exception:
            db.session.rollback()

        # Пытаемся добавить колонку manual_price в таблицу company_quota
        try:
            db.session.execute(db.text("ALTER TABLE company_quota ADD COLUMN manual_price FLOAT"))
            db.session.commit()
            print("Миграция: Добавлена колонка manual_price в company_quota")
        except Exception:
            db.session.rollback()

        # Пытаемся добавить колонку comment в таблицу company_quota
        try:
            db.session.execute(db.text("ALTER TABLE company_quota ADD COLUMN comment VARCHAR(255)"))
            db.session.commit()
            print("Миграция: Добавлена колонка comment в company_quota")
        except Exception:
            db.session.rollback()

        # Пытаемся добавить колонку sync_interval_hours в таблицу pricing_policy
        try:
            db.session.execute(db.text("ALTER TABLE pricing_policy ADD COLUMN sync_interval_hours INTEGER DEFAULT 1"))
            db.session.commit()
            print("Миграция: Добавлена колонка sync_interval_hours в pricing_policy")
        except Exception:
            db.session.rollback()

def init_db():
    db.create_all()
    print("Таблицы базы данных проверены/созданы.")

# -------------------- Авторизация --------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('index'))
        else:
            flash("Неверное имя пользователя или пароль!")
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        
        user = User.query.get(session['user_id'])
        if user and user.check_password(current_password):
            user.set_password(new_password)
            db.session.commit()
            flash("Пароль успешно изменен!", "success")
            return redirect(url_for('change_password'))
        else:
            flash("Неверный текущий пароль!", "danger")
            
    return render_template('change_password.html')

# -------------------- Администрирование пользователей --------------------

@app.route('/admin/users')
@admin_required
def users_admin():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form['username'].strip()
    password = request.form['password']
    role = request.form['role']
    
    if not username or not password:
        flash("Заполните все поля!", "danger")
        return redirect(url_for('users_admin'))
        
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash("Пользователь с таким логином уже существует!", "danger")
        return redirect(url_for('users_admin'))
        
    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    flash(f"Пользователь {username} успешно создан!", "success")
    return redirect(url_for('users_admin'))

@app.route('/admin/users/edit/<int:user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Не даем админу менять собственную роль (чтобы случайно не лишить себя прав)
    if user.username != session.get('username'):
        user.role = request.form.get('role', user.role)
        
    # Если введен новый пароль — обновляем его
    new_password = request.form.get('password')
    if new_password and new_password.strip():
        user.set_password(new_password)
        
    db.session.commit()
    flash(f"Данные пользователя {user.username} обновлены!", "success")
    return redirect(url_for('users_admin'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Запрещаем удаление самого себя
    if user.username == session.get('username'):
        flash("Вы не можете удалить свою собственную учетную запись!", "danger")
        return redirect(url_for('users_admin'))
        
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f"Пользователь {username} успешно удален!", "success")
    return redirect(url_for('users_admin'))

# -------------------- Основные маршруты --------------------

@app.route('/')
@login_required
def index():
    all_servers = Server.query.filter_by(deleted=False).filter(Server.type.in_(['manual', 'proxmox_node'])).all()
    
    servers_data_map = {}
    total_phys_resources = {'cpu': 0, 'ram': 0, 'ssd': 0, 'hdd': 0}
    total_alloc_resources = {'cpu': 0, 'ram': 0, 'ssd': 0, 'hdd': 0}
    
    for s in all_servers:
        alloc = s.get_allocated_resources()
        
        total_phys_resources['cpu'] += s.cpu
        total_phys_resources['ram'] += s.ram
        total_phys_resources['ssd'] += s.ssd
        total_phys_resources['hdd'] += s.hdd
        
        total_alloc_resources['cpu'] += alloc['cpu']
        total_alloc_resources['ram'] += alloc['ram']
        total_alloc_resources['ssd'] += alloc['ssd']
        total_alloc_resources['hdd'] += alloc['hdd']
        
        free_resources = {
            'cpu': s.cpu - alloc['cpu'],
            'ram': s.ram - alloc['ram'],
            'ssd': s.ssd - alloc['ssd'],
            'hdd': s.hdd - alloc['hdd']
        }
        
        usage_pct = {
            'cpu': round((alloc['cpu'] / s.cpu * 100) if s.cpu > 0 else 0, 1),
            'ram': round((alloc['ram'] / s.ram * 100) if s.ram > 0 else 0, 1),
            'ssd': round((alloc['ssd'] / s.ssd * 100) if s.ssd > 0 else 0, 1),
            'hdd': round((alloc['hdd'] / s.hdd * 100) if s.hdd > 0 else 0, 1)
        }
        
        servers_data_map[s.id] = {
            'server': s,
            'allocated': alloc,
            'free': free_resources,
            'usage_pct': usage_pct
        }
        
    global_metrics = {
        'total_phys': total_phys_resources,
        'total_alloc': total_alloc_resources,
        'pct': {
            'cpu': round((total_alloc_resources['cpu'] / total_phys_resources['cpu'] * 100) if total_phys_resources['cpu'] > 0 else 0, 1),
            'ram': round((total_alloc_resources['ram'] / total_phys_resources['ram'] * 100) if total_phys_resources['ram'] > 0 else 0, 1),
            'ssd': round((total_alloc_resources['ssd'] / total_phys_resources['ssd'] * 100) if total_phys_resources['ssd'] > 0 else 0, 1),
            'hdd': round((total_alloc_resources['hdd'] / total_phys_resources['hdd'] * 100) if total_phys_resources['hdd'] > 0 else 0, 1)
        }
    }
    
    clusters = {}
    standalone = []
    
    for s_id, s_data in servers_data_map.items():
        s = s_data['server']
        if s.parent_id:
            parent = Server.query.get(s.parent_id)
            if parent:
                if parent.id not in clusters:
                    clusters[parent.id] = {
                        'cluster': parent,
                        'nodes': []
                    }
                clusters[parent.id]['nodes'].append(s_data)
        else:
            standalone.append(s_data)
            
    return render_template('dashboard.html', 
                           clusters=list(clusters.values()), 
                           standalone=standalone, 
                           global_metrics=global_metrics)

@app.route('/quotas')
@login_required
def quotas():
    backup_servers = Server.query.filter_by(deleted=False, type='backup_ssh').all()
    
    servers_data = []
    for s in backup_servers:
        role = session.get('role', 'user')
        if role == 'admin':
            quotas_list = [q for q in s.quotas]
        else:
            quotas_list = [q for q in s.quotas if not q.is_hidden]
        
        total_storage = s.hdd if s.hdd > 0 else s.ssd
        total_allocated = sum(q.allocated_quota for q in quotas_list if not q.is_hidden)
        total_actual = sum(q.actual_usage for q in quotas_list if not q.is_hidden)
        
        physical_free = total_storage - total_actual
        allocated_free = total_allocated - total_actual
        
        servers_data.append({
            'server': s,
            'quotas': quotas_list,
            'total_storage': total_storage,
            'total_allocated': total_allocated,
            'total_actual': round(total_actual, 2),
            'physical_free': round(physical_free, 2),
            'allocated_free': round(allocated_free, 2)
        })
        
    return render_template('quotas.html', servers=servers_data)

@app.route('/server/<int:server_id>')
@login_required
def server_detail(server_id):
    server = Server.query.get_or_404(server_id)
    if server.deleted:
        return "Сервер находится в архиве", 404
        
    if server.type == 'backup_ssh':
        role = session.get('role', 'user')
        if role == 'admin':
            quotas = server.quotas
        else:
            quotas = [q for q in server.quotas if not q.is_hidden]
        return render_template('server_detail_quota.html', server=server, quotas=quotas)
    else:
        vms = [vm for vm in server.virtual_machines if not vm.deleted]
        alloc = server.get_allocated_resources()
        free = {
            'cpu': server.cpu - alloc['cpu'],
            'ram': server.ram - alloc['ram'],
            'ssd': server.ssd - alloc['ssd'],
            'hdd': server.hdd - alloc['hdd']
        }
        return render_template('server_detail_compute.html', server=server, vms=vms, alloc=alloc, free=free)

# -------------------- Управление серверами --------------------

@app.route('/server/add', methods=['POST'])
@admin_required
def add_server():
    def parse_float_or_none(value):
        if value is None or value.strip() == '':
            return None
        try:
            return float(value)
        except ValueError:
            return None

    name = request.form['name']
    ip_address = request.form['ip_address']
    srv_type = request.form['type']
    cpu = int(request.form.get('cpu', 0) or 0)
    ram = int(request.form.get('ram', 0) or 0)
    ssd = int(request.form.get('ssd', 0) or 0)
    hdd = int(request.form.get('hdd', 0) or 0)
    backup_path = request.form.get('backup_path', '/')

    server = Server(
        name=name, ip_address=ip_address, type=srv_type,
        cpu=cpu, ram=ram, ssd=ssd, hdd=hdd, status='unknown',
        backup_path=backup_path,
        cpu_price=parse_float_or_none(request.form.get('cpu_price')),
        ram_price_gb=parse_float_or_none(request.form.get('ram_price_gb')),
        ssd_price_gb=parse_float_or_none(request.form.get('ssd_price_gb')),
        hdd_price_gb=parse_float_or_none(request.form.get('hdd_price_gb')),
        backup_price_gb=parse_float_or_none(request.form.get('backup_price_gb'))
    )
    db.session.add(server)
    db.session.commit()

    if srv_type in ['proxmox', 'backup_ssh']:
        username = request.form.get('username')
        password = request.form.get('password')
        extra = request.form.get('extra_param')
        
        config = SyncConfig(
            server_id=server.id,
            username=username,
            extra_param=extra
        )
        config.set_password(password)
        db.session.add(config)
        db.session.commit()

    return redirect(url_for('settings'))

@app.route('/server/edit/<int:server_id>', methods=['POST'])
@admin_required
def edit_server(server_id):
    def parse_float_or_none(value):
        if value is None or value.strip() == '':
            return None
        try:
            return float(value)
        except ValueError:
            return None

    server = Server.query.get_or_404(server_id)
    server.name = request.form['name']
    server.ip_address = request.form['ip_address']
    
    server.cpu_price = parse_float_or_none(request.form.get('cpu_price'))
    server.ram_price_gb = parse_float_or_none(request.form.get('ram_price_gb'))
    server.ssd_price_gb = parse_float_or_none(request.form.get('ssd_price_gb'))
    server.hdd_price_gb = parse_float_or_none(request.form.get('hdd_price_gb'))
    server.backup_price_gb = parse_float_or_none(request.form.get('backup_price_gb'))

    if server.type in ['manual', 'backup_ssh']:
        server.cpu = int(request.form.get('cpu', 0) or 0)
        server.ram = int(request.form.get('ram', 0) or 0)
        server.ssd = int(request.form.get('ssd', 0) or 0)
        server.hdd = int(request.form.get('hdd', 0) or 0)
        server.backup_path = request.form.get('backup_path', '/')

    if server.type in ['proxmox', 'backup_ssh']:
        config = SyncConfig.query.filter_by(server_id=server.id).first()
        if not config:
            config = SyncConfig(server_id=server.id)
            db.session.add(config)
        
        config.username = request.form.get('username')
        if request.form.get('password'):
            config.set_password(request.form.get('password'))
        config.extra_param = request.form.get('extra_param')
        
    db.session.commit()
    return redirect(url_for('settings'))

@app.route('/server/delete/<int:server_id>', methods=['POST'])
@admin_required
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)
    action = request.form.get('action', 'soft')
    
    if action == 'permanent':
        db.session.delete(server)
    else:
        server.deleted = True
        if server.type == 'proxmox':
            for node in server.child_nodes:
                node.deleted = True
        
    db.session.commit()
    return redirect(url_for('settings'))

@app.route('/server/restore/<int:server_id>', methods=['POST'])
@admin_required
def restore_server(server_id):
    server = Server.query.get_or_404(server_id)
    server.deleted = False
    if server.type == 'proxmox':
        for node in server.child_nodes:
            node.deleted = False
    db.session.commit()
    return redirect(url_for('settings'))

# -------------------- Настройка сопоставления хранилищ Proxmox --------------------

@app.route('/server/storage/update/<int:server_id>', methods=['POST'])
@admin_required
def update_server_storages(server_id):
    server = Server.query.get_or_404(server_id)
    storages = ProxmoxStorage.query.filter_by(server_id=server.id).all()
    
    for s in storages:
        new_type = request.form.get(f"storage_type_{s.id}")
        if new_type in ['ssd', 'hdd', 'ignore']:
            s.storage_type = new_type
            
    db.session.commit()
    return redirect(url_for('settings'))

# -------------------- Управление ВМ (для ручных серверов) --------------------

@app.route('/vm/add/<int:server_id>', methods=['POST'])
@admin_required
def add_vm(server_id):
    server = Server.query.get_or_404(server_id)
    name = request.form['name']
    cpu = int(request.form.get('cpu', 0) or 0)
    ram = int(request.form.get('ram', 0) or 0)
    ssd = int(request.form.get('ssd', 0) or 0)
    hdd = int(request.form.get('hdd', 0) or 0)
    status = request.form.get('status', 'running')
    comment = request.form.get('comment', '').strip() or None

    vm = VirtualMachine(
        server_id=server.id, name=name, cpu=cpu, ram=ram,
        ssd=ssd, hdd=hdd, status=status, deleted=False,
        comment=comment
    )
    db.session.add(vm)
    db.session.commit()
    return redirect(url_for('server_detail', server_id=server_id))

@app.route('/vm/edit/<int:vm_id>', methods=['POST'])
@login_required
def edit_vm(vm_id):
    if session.get('role') not in ['admin', 'financier']:
        return "Доступ запрещен", 403
    vm = VirtualMachine.query.get_or_404(vm_id)
    
    # Если сервер ручной и роль админ, разрешаем редактировать всё
    if vm.server.type == 'manual' and session.get('role') == 'admin':
        vm.name = request.form['name']
        vm.cpu = int(request.form.get('cpu', 0) or 0)
        vm.ram = int(request.form.get('ram', 0) or 0)
        vm.ssd = int(request.form.get('ssd', 0) or 0)
        vm.hdd = int(request.form.get('hdd', 0) or 0)
        vm.status = request.form.get('status', 'running')
        
    # Комментарий разрешаем редактировать и админу, и финансисту
    vm.comment = request.form.get('comment', '').strip() or None
    
    db.session.commit()
    return redirect(url_for('server_detail', server_id=vm.server_id))

@app.route('/vm/delete/<int:vm_id>', methods=['POST'])
@admin_required
def delete_vm(vm_id):
    vm = VirtualMachine.query.get_or_404(vm_id)
    server_id = vm.server_id
    
    if vm.server.type == 'manual':
        db.session.delete(vm)
    else:
        vm.deleted = True
        
    db.session.commit()
    return redirect(url_for('server_detail', server_id=server_id))

# -------------------- Управление Квотами Компаний --------------------

@app.route('/quota/add/<int:server_id>', methods=['POST'])
@admin_required
def add_quota(server_id):
    server = Server.query.get_or_404(server_id)
    company_name = request.form['company_name']
    system_name = request.form.get('system_name')
    system_type = request.form.get('system_type', 'user')
    allocated_quota = int(request.form.get('allocated_quota', 0) or 0)
    is_hidden = 'is_hidden' in request.form

    quota = CompanyQuota(
        server_id=server.id, company_name=company_name,
        system_name=system_name, system_type=system_type,
        allocated_quota=allocated_quota, actual_usage=0.0,
        is_hidden=is_hidden,
        comment=request.form.get('comment', '').strip() or None
    )
    db.session.add(quota)
    db.session.commit()
    return redirect(url_for('server_detail', server_id=server_id))

@app.route('/quota/edit/<int:quota_id>', methods=['POST'])
@login_required
def edit_quota(quota_id):
    if session.get('role') not in ['admin', 'financier']:
        flash("У вас нет прав для этого действия", "danger")
        return redirect(url_for('dashboard'))
        
    quota = CompanyQuota.query.get_or_404(quota_id)
    
    # Комментарий могут менять и админ, и финансист
    quota.comment = request.form.get('comment', '').strip() or None
    
    # Остальные поля - только админ
    if session.get('role') == 'admin':
        quota.company_name = request.form['company_name']
        quota.system_name = request.form.get('system_name')
        quota.system_type = request.form.get('system_type', 'user')
        quota.allocated_quota = int(request.form.get('allocated_quota', 0) or 0)
        quota.is_hidden = 'is_hidden' in request.form
        
        if quota.server.type == 'manual':
            quota.actual_usage = float(request.form.get('actual_usage', 0.0) or 0.0)
            
    db.session.commit()
    return redirect(url_for('server_detail', server_id=quota.server_id))

@app.route('/quota/delete/<int:quota_id>', methods=['POST'])
@admin_required
def delete_quota(quota_id):
    quota = CompanyQuota.query.get_or_404(quota_id)
    server_id = quota.server_id
    db.session.delete(quota)
    db.session.commit()
    return redirect(url_for('server_detail', server_id=server_id))

# -------------------- Ценообразование и Ручные ценники --------------------

@app.route('/pricing', methods=['GET', 'POST'])
@login_required
def pricing():
    policy = PricingPolicy.query.first()
    
    if request.method == 'POST':
        # Изменять глобальные тарифы могут админы и финансисты
        if session.get('role') not in ['admin', 'financier']:
            return "Доступ запрещен. Требуются права Администратора или Финансиста.", 403
            
        policy.cpu_price = float(request.form['cpu_price'])
        policy.ram_price_gb = float(request.form['ram_price_gb'])
        policy.ssd_price_gb = float(request.form['ssd_price_gb'])
        policy.hdd_price_gb = float(request.form['hdd_price_gb'])
        policy.backup_price_gb = float(request.form['backup_price_gb'])
        db.session.commit()
        return redirect(url_for('pricing'))

    vms = VirtualMachine.query.filter_by(deleted=False).all()
    servers_vms = {}
    total_vms_revenue = 0.0
    
    # Сначала группируем ВМ по серверам
    vms_by_server = {}
    for vm in vms:
        srv = vm.server
        if not srv:
            continue
        if srv.id not in vms_by_server:
            vms_by_server[srv.id] = []
        vms_by_server[srv.id].append(vm)
        
    for srv_id, srv_vms in vms_by_server.items():
        srv = Server.query.get(srv_id)
        if not srv:
            continue
            
        # Определяем эффективные тарифы с учетом настроек кластера/сервера
        pricing_source = srv.parent if srv.parent else srv
        cpu_pr = pricing_source.cpu_price if pricing_source.cpu_price is not None else policy.cpu_price
        ram_pr = pricing_source.ram_price_gb if pricing_source.ram_price_gb is not None else policy.ram_price_gb
        ssd_pr = pricing_source.ssd_price_gb if pricing_source.ssd_price_gb is not None else policy.ssd_price_gb
        hdd_pr = pricing_source.hdd_price_gb if pricing_source.hdd_price_gb is not None else policy.hdd_price_gb

        commented_groups = {}
        grouped_items = []
        
        for vm in srv_vms:
            client_name = vm.comment.strip() if (vm.comment and vm.comment.strip()) else None
            
            # Расчет автостоимости для ВМ
            cpu_cost = vm.cpu * cpu_pr
            ram_cost = vm.ram * ram_pr
            ssd_cost = vm.ssd * ssd_pr
            hdd_cost = vm.hdd * hdd_pr
            auto_cost = cpu_cost + ram_cost + ssd_cost + hdd_cost
            
            if client_name:
                if client_name not in commented_groups:
                    commented_groups[client_name] = {
                        'client_name': client_name,
                        'is_group': True,
                        'vms_list': [],
                        'cpu': 0,
                        'ram': 0,
                        'ssd': 0,
                        'hdd': 0,
                        'auto_cost': 0.0,
                        'manual_price': 0.0,
                        'has_manual': False,
                        'representative_vm_id': vm.id
                    }
                g = commented_groups[client_name]
                g['vms_list'].append(vm)
                g['cpu'] += vm.cpu
                g['ram'] += vm.ram
                g['ssd'] += vm.ssd
                g['hdd'] += vm.hdd
                g['auto_cost'] += auto_cost
                if vm.manual_price is not None:
                    g['manual_price'] += vm.manual_price
                    g['has_manual'] = True
            else:
                # ВМ без комментария - отдельная строка
                grouped_items.append({
                    'client_name': vm.name,
                    'is_group': False,
                    'vms_list': [vm],
                    'cpu': vm.cpu,
                    'ram': vm.ram,
                    'ssd': vm.ssd,
                    'hdd': vm.hdd,
                    'auto_cost': auto_cost,
                    'manual_price': vm.manual_price if vm.manual_price is not None else 0.0,
                    'has_manual': vm.manual_price is not None,
                    'representative_vm_id': vm.id
                })
                
        # Добавляем сгруппированные ВМ с комментариями
        for g in commented_groups.values():
            grouped_items.append(g)
            
        # Общие физические объемы ресурсов хоста
        total_host_cpu = srv.cpu if srv.cpu > 0 else sum(vm.cpu for vm in srv_vms)
        if total_host_cpu == 0:
            total_host_cpu = 1
            
        total_host_ram = srv.ram if srv.ram > 0 else sum(vm.ram for vm in srv_vms)
        if total_host_ram == 0:
            total_host_ram = 1
            
        total_host_ssd = srv.ssd if srv.ssd > 0 else sum(vm.ssd for vm in srv_vms)
        if total_host_ssd == 0:
            total_host_ssd = 1
            
        total_host_hdd = srv.hdd if srv.hdd > 0 else sum(vm.hdd for vm in srv_vms)
        if total_host_hdd == 0:
            total_host_hdd = 1
            
        host_expense = srv.expense if srv.expense else 0.0
        
        server_income = 0.0
        server_expense = 0.0
        processed_items = []
        
        for item in grouped_items:
            # Доли по разным ресурсам
            share_cpu = (item['cpu'] / total_host_cpu) * 100
            share_ram = (item['ram'] / total_host_ram) * 100
            share_ssd = (item['ssd'] / total_host_ssd) * 100
            share_hdd = (item['hdd'] / total_host_hdd) * 100
            
            # Доход
            income = item['manual_price'] if item['has_manual'] else item['auto_cost']
            total_vms_revenue += income
            server_income += income
            
            # Расход (Себестоимость распределяется по доле RAM, как в Excel)
            expense = host_expense * (item['ram'] / total_host_ram)
            server_expense += expense
            
            # Прибыль и рентабельность
            profit = income - expense
            rentability = (profit / expense * 100) if expense > 0 else 0.0
            
            # Примечание (список ВМ)
            if item['is_group']:
                other_vms = [v.name for v in item['vms_list']]
                note = "также " + ", ".join(other_vms)
            else:
                note = "ВМ"
                
            processed_items.append({
                'client_name': item['client_name'],
                'is_group': item['is_group'],
                'cpu': item['cpu'],
                'ram': item['ram'],
                'ssd': item['ssd'],
                'hdd': item['hdd'],
                'auto_cost': item['auto_cost'],
                'manual_price': item['manual_price'],
                'has_manual': item['has_manual'],
                'representative_vm_id': item['representative_vm_id'],
                'share_cpu': round(share_cpu, 1),
                'share_ram': round(share_ram, 1),
                'share_ssd': round(share_ssd, 1),
                'share_hdd': round(share_hdd, 1),
                'income': income,
                'expense': expense,
                'profit': profit,
                'rentability': rentability,
                'note': note
            })
            
        server_profit = server_income - server_expense
        
        # Суммы долей
        total_share_cpu = sum(item['share_cpu'] for item in processed_items)
        total_share_ram = sum(item['share_ram'] for item in processed_items)
        total_share_ssd = sum(item['share_ssd'] for item in processed_items)
        total_share_hdd = sum(item['share_hdd'] for item in processed_items)
        
        server_rentability = (server_profit / server_expense * 100) if server_expense > 0 else 0.0
        
        servers_vms[srv.id] = {
            'server': srv,
            'grouped_items': processed_items,
            'total_income': server_income,
            'total_expense': server_expense,
            'total_profit': server_profit,
            'total_rentability': server_rentability,
            'total_share_cpu': total_share_cpu,
            'total_share_ram': total_share_ram,
            'total_share_ssd': total_share_ssd,
            'total_share_hdd': total_share_hdd,
            'cpu_price': cpu_pr,
            'ram_price': ram_pr,
            'ssd_price': ssd_pr,
            'hdd_price': hdd_pr
        }

    # Исключаем скрытые квоты из финансовых отчетов
    quotas_list = CompanyQuota.query.filter_by(is_hidden=False).all()

    # Группировка квот по комментариям
    commented_quota_groups = {}
    grouped_quotas = []
    
    for q in quotas_list:
        client_name = q.comment.strip() if (q.comment and q.comment.strip()) else None
        
        srv = q.server
        backup_pr = srv.backup_price_gb if (srv and srv.backup_price_gb is not None) else policy.backup_price_gb
        auto_cost = q.allocated_quota * backup_pr
        
        if client_name:
            if client_name not in commented_quota_groups:
                commented_quota_groups[client_name] = {
                    'client_name': client_name,
                    'is_group': True,
                    'quotas_list': [],
                    'allocated_quota': 0,
                    'actual_usage': 0.0,
                    'auto_cost': 0.0,
                    'manual_price': 0.0,
                    'has_manual': False,
                    'representative_quota_id': q.id,
                    'server_names': set()
                }
            g = commented_quota_groups[client_name]
            g['quotas_list'].append(q)
            g['allocated_quota'] += q.allocated_quota
            g['actual_usage'] += q.actual_usage
            g['auto_cost'] += auto_cost
            if q.manual_price is not None:
                g['manual_price'] += q.manual_price
                g['has_manual'] = True
            g['server_names'].add(q.server.name)
        else:
            # Отдельная строка без комментария
            grouped_quotas.append({
                'client_name': q.company_name,
                'is_group': False,
                'quotas_list': [q],
                'allocated_quota': q.allocated_quota,
                'actual_usage': q.actual_usage,
                'auto_cost': auto_cost,
                'manual_price': q.manual_price if q.manual_price is not None else 0.0,
                'has_manual': q.manual_price is not None,
                'representative_quota_id': q.id,
                'server_names': {q.server.name}
            })
            
    for g in commented_quota_groups.values():
        grouped_quotas.append(g)
        
    quotas_pricing = []
    total_quotas_revenue = 0.0
    
    for item in grouped_quotas:
        income = item['manual_price'] if item['has_manual'] else item['auto_cost']
        total_quotas_revenue += income
        
        # Формируем примечание (список бэкап-серверов или системных аккаунтов)
        server_list = ", ".join(sorted(list(item['server_names'])))
        if item['is_group']:
            other_names = [q.company_name for q in item['quotas_list']]
            note = f"Серверы: {server_list} (аккаунты: {', '.join(other_names)})"
        else:
            note = f"Сервер: {server_list}"
            
        quotas_pricing.append({
            'client_name': item['client_name'],
            'is_group': item['is_group'],
            'allocated_quota': item['allocated_quota'],
            'actual_usage': round(item['actual_usage'], 2),
            'auto_cost': item['auto_cost'],
            'manual_price': item['manual_price'],
            'has_manual': item['has_manual'],
            'representative_quota_id': item['representative_quota_id'],
            'current_cost': income,
            'note': note
        })

    backup_servers = Server.query.filter_by(deleted=False, type='backup_ssh').all()

    return render_template('pricing.html', 
                           policy=policy, 
                           servers_vms=servers_vms, 
                           quotas=quotas_pricing,
                           backup_servers=backup_servers,
                           total_vms_revenue=round(total_vms_revenue, 2),
                           total_quotas_revenue=round(total_quotas_revenue, 2))

@app.route('/server/pricing/update', methods=['POST'])
@login_required
def update_server_pricing():
    if session.get('role') not in ['admin', 'financier']:
        return "Доступ запрещен. Требуются права Администратора или Финансиста.", 403
        
    server_id = int(request.form.get('server_id'))
    server = Server.query.get_or_404(server_id)
    
    def parse_float_or_none(value):
        if value is None or value.strip() == '':
            return None
        try:
            return float(value)
        except ValueError:
            return None
            
    if server.type == 'backup_ssh':
        server.backup_price_gb = parse_float_or_none(request.form.get('backup_price_gb'))
    else:
        server.cpu_price = parse_float_or_none(request.form.get('cpu_price'))
        server.ram_price_gb = parse_float_or_none(request.form.get('ram_price_gb'))
        server.ssd_price_gb = parse_float_or_none(request.form.get('ssd_price_gb'))
        server.hdd_price_gb = parse_float_or_none(request.form.get('hdd_price_gb'))
        
    db.session.commit()
    return redirect(url_for('pricing'))

@app.route('/pricing/update_manual_price', methods=['POST'])
@login_required
def update_manual_price():
    if session.get('role') not in ['admin', 'financier']:
        return jsonify({'status': 'error', 'message': 'Доступ запрещен.'}), 403
        
    item_type = request.form.get('item_type')
    item_id = int(request.form.get('item_id', 0) or 0)
    price_str = request.form.get('manual_price')
    
    if price_str is None or price_str.strip() == '':
        manual_price = None
    else:
        try:
            manual_price = float(price_str)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Некорректное значение цены!'}), 400
            
    if item_type == 'vm_group':
        client_name = request.form.get('client_name')
        server_id = int(request.form.get('server_id', 0) or 0)
        
        if client_name:
            # Ищем все активные ВМ с этим комментарием на сервере
            vms = VirtualMachine.query.filter_by(server_id=server_id, deleted=False).all()
            target_vms = [v for v in vms if v.comment and v.comment.strip() == client_name.strip()]
            
            if target_vms:
                # Записываем цену на первую ВМ группы, у остальных зануляем
                target_vms[0].manual_price = manual_price
                for extra_vm in target_vms[1:]:
                    extra_vm.manual_price = None
            else:
                return jsonify({'status': 'error', 'message': 'Группа ВМ не найдена!'}), 404
        else:
            # Одиночная ВМ
            vm = VirtualMachine.query.get_or_404(item_id)
            vm.manual_price = manual_price
            
    elif item_type == 'vm':
        vm = VirtualMachine.query.get_or_404(item_id)
        vm.manual_price = manual_price
    elif item_type == 'quota_group':
        client_name = request.form.get('client_name')
        if client_name:
            # Ищем все квоты с этим комментарием
            quotas = CompanyQuota.query.all()
            target_quotas = [q for q in quotas if q.comment and q.comment.strip() == client_name.strip()]
            
            if target_quotas:
                # Записываем цену на первую квоту группы, у остальных зануляем
                target_quotas[0].manual_price = manual_price
                for extra_q in target_quotas[1:]:
                    extra_q.manual_price = None
            else:
                return jsonify({'status': 'error', 'message': 'Группа квот не найдена!'}), 404
        else:
            # Одиночная квота без комментария
            quota = CompanyQuota.query.get_or_404(item_id)
            quota.manual_price = manual_price
    elif item_type == 'quota':
        quota = CompanyQuota.query.get_or_404(item_id)
        quota.manual_price = manual_price
    else:
        return jsonify({'status': 'error', 'message': 'Неверный тип объекта!'}), 400
        
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Ручной ценник успешно сохранен!'})

@app.route('/pricing/update_host_expense', methods=['POST'])
@login_required
def update_host_expense():
    if session.get('role') not in ['admin', 'financier']:
        return jsonify({'status': 'error', 'message': 'Доступ запрещен.'}), 403
        
    try:
        server_id = int(request.form.get('server_id'))
        expense = float(request.form.get('expense', '0') or 0)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Некорректная сумма расходов хоста!'}), 400
        
    server = Server.query.get_or_404(server_id)
    server.expense = expense
    db.session.commit()
    return jsonify({'status': 'success', 'message': f'Расходы хоста {server.name} успешно обновлены!'})

# -------------------- Настройки --------------------

@app.route('/settings')
@admin_required
def settings():
    active_servers = Server.query.filter_by(deleted=False).filter(Server.type != 'proxmox_node').all()
    archived_servers = Server.query.filter_by(deleted=True).filter(Server.type != 'proxmox_node').all()
    policy = PricingPolicy.query.first()
    return render_template('settings.html', active_servers=active_servers, archived_servers=archived_servers, policy=policy)

@app.route('/settings/sync-interval', methods=['POST'])
@admin_required
def save_sync_interval():
    try:
        interval = int(request.form.get('sync_interval_hours', 1))
        if interval < 1:
            interval = 1
    except (ValueError, TypeError):
        interval = 1
        
    policy = PricingPolicy.query.first()
    if not policy:
        policy = PricingPolicy()
        db.session.add(policy)
    policy.sync_interval_hours = interval
    db.session.commit()
    flash("Интервал автоматической синхронизации успешно обновлен!", "success")
    return redirect(url_for('settings'))

# -------------------- API Синхронизации --------------------

@app.route('/api/sync/<int:server_id>')
def sync_server(server_id):
    # Разрешаем cron-запросы (localhost) или роли admin/financier
    is_local = request.remote_addr in ['127.0.0.1', '::1', 'localhost']
    is_auth = ('user_id' in session) and (session.get('role') in ['admin', 'financier'])
    if not (is_local or is_auth):
        return jsonify({'status': 'error', 'message': 'Доступ запрещен'}), 403
    server = Server.query.get_or_404(server_id)
    
    target_server = server
    if server.type == 'proxmox_node' and server.parent_id:
        target_server = Server.query.get(server.parent_id)
        if not target_server:
            return jsonify({'status': 'error', 'message': 'Родительский кластер Proxmox не найден'}), 404

    if target_server.type == 'manual':
        return jsonify({'status': 'error', 'message': 'Для ручных серверов синхронизация недоступна'}), 400
        
    try:
        from sync_engine import run_sync
        success, message = run_sync(target_server)
        if success:
            target_server.status = 'online'
            target_server.last_sync = datetime.now()
            if server.type == 'proxmox_node':
                server.status = 'online'
                server.last_sync = datetime.now()
            db.session.commit()
            return jsonify({'status': 'success', 'message': message})
        else:
            target_server.status = 'offline'
            if server.type == 'proxmox_node':
                server.status = 'offline'
            db.session.commit()
            return jsonify({'status': 'error', 'message': message}), 500
    except Exception as e:
        target_server.status = 'offline'
        if server.type == 'proxmox_node':
            server.status = 'offline'
        db.session.commit()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/sync/all')
def sync_all():
    # Разрешаем cron-запросы (localhost) или роли admin/financier
    is_local = request.remote_addr in ['127.0.0.1', '::1', 'localhost']
    is_auth = ('user_id' in session) and (session.get('role') in ['admin', 'financier'])
    if not (is_local or is_auth):
        return jsonify({'status': 'error', 'message': 'Доступ запрещен'}), 403
    servers = Server.query.filter_by(deleted=False).filter(Server.type.in_(['proxmox', 'backup_ssh'])).all()
    from sync_engine import run_sync
    
    results = []
    for s in servers:
        try:
            success, message = run_sync(s)
            if success:
                s.status = 'online'
                s.last_sync = datetime.now()
                results.append({'server_id': s.id, 'name': s.name, 'status': 'success', 'message': message})
            else:
                s.status = 'offline'
                results.append({'server_id': s.id, 'name': s.name, 'status': 'error', 'message': message})
        except Exception as e:
            s.status = 'offline'
            results.append({'server_id': s.id, 'name': s.name, 'status': 'error', 'message': str(e)})
            
    db.session.commit()
    return jsonify({'status': 'completed', 'results': results})

# -------------------- Автоматический планировщик --------------------

def scheduled_sync_all():
    with app.app_context():
        try:
            policy = PricingPolicy.query.first()
            interval_hours = policy.sync_interval_hours if (policy and policy.sync_interval_hours) else 1
            
            servers = Server.query.filter_by(deleted=False).filter(Server.type.in_(['proxmox', 'backup_ssh'])).all()
            from sync_engine import run_sync
            from datetime import timedelta
            
            for s in servers:
                should_sync = False
                if not s.last_sync:
                    should_sync = True
                else:
                    elapsed = datetime.now() - s.last_sync
                    if elapsed >= timedelta(hours=interval_hours):
                        should_sync = True
                        
                if should_sync:
                    print(f"[{datetime.now()}] Запуск фоновой автосинхронизации для сервера: {s.name}")
                    try:
                        success, message = run_sync(s)
                        if success:
                            s.status = 'online'
                            s.last_sync = datetime.now()
                        else:
                            s.status = 'offline'
                    except Exception as e:
                         s.status = 'offline'
                         print(f"Ошибка фоновой автосинхронизации сервера {s.name}: {e}")
            db.session.commit()
        except Exception as e:
            print(f"[{datetime.now()}] Ошибка фоновой автосинхронизации: {e}")

def start_scheduler():
    try:
        import fcntl
        try:
            f = open('.scheduler.lock', 'wb')
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            
            scheduler = BackgroundScheduler(daemon=True)
            # Запускаем проверку каждые 5 минут
            scheduler.add_job(func=scheduled_sync_all, trigger="interval", minutes=5)
            scheduler.start()
            print("Планировщик APScheduler запущен в режиме чеккера (захвачена блокировка воркера).")
        except (IOError, BlockingIOError):
            # Блокировка уже захвачена другим процессом Gunicorn
            pass
    except ImportError:
        # Для сред без fcntl (например, разработка под Windows)
        if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
            scheduler = BackgroundScheduler(daemon=True)
            scheduler.add_job(func=scheduled_sync_all, trigger="interval", minutes=5)
            scheduler.start()
            print("Планировщик APScheduler запущен в режиме чеккера (окружение Windows / без fcntl).")

# -------------------- Запуск приложения --------------------

with app.app_context():
    init_db()
    migrate_db()
    
    # Создаем администратора и ценовую политику по умолчанию после применения миграций
    if not User.query.first():
        default_admin = User(username='admin', role='admin')
        default_admin.set_password('admin123')
        db.session.add(default_admin)
        db.session.commit()
        print("Создан администратор по умолчанию: admin / admin123")
        
    if not PricingPolicy.query.first():
        default_policy = PricingPolicy()
        db.session.add(default_policy)
        db.session.commit()
        
    print("Инициализация базы данных завершена.")
    start_scheduler()

if __name__ == '__main__':
    bind_host = os.environ.get('BIND_HOST', os.environ.get('HOST', '0.0.0.0'))
    port = int(os.environ.get('BIND_PORT', os.environ.get('PORT', 5002)))
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1' or os.environ.get('FLASK_ENV') == 'development'
    app.run(host=bind_host, port=port, debug=debug_mode)
