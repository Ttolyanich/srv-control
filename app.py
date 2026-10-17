from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, session, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from models import db, User, LoginRateLimit, Server, VirtualMachine, CompanyQuota, SyncConfig, ProxmoxStorage, PricingPolicy
from sqlalchemy.orm import joinedload, selectinload
from datetime import datetime
from functools import wraps
import os
import time
import secrets
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from apscheduler.schedulers.background import BackgroundScheduler

# Попытка импорта ldap3 для авторизации через Active Directory / LDAP
try:
    from ldap3 import Server as LdapServer, Connection as LdapConnection, ALL, SUBTREE
    from ldap3.utils.conv import escape_filter_chars
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', os.environ.get('DATABASE_URL', 'sqlite:///srv_control.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

def _load_or_create_secret(filename, nbytes=32):
    """Секрет из файла в instance/; при отсутствии генерируется и сохраняется."""
    os.makedirs(app.instance_path, exist_ok=True)
    path = os.path.join(app.instance_path, filename)
    try:
        with open(path, 'r') as f:
            value = f.read().strip()
            if value:
                return value
    except FileNotFoundError:
        pass
    value = secrets.token_hex(nbytes)
    with open(path, 'w') as f:
        f.write(value)
    print(f"AUTO-CONFIG: Сгенерирован новый секрет и сохранен в {path}")
    return value

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or _load_or_create_secret('.secret_key')
os.environ['SECRET_KEY'] = app.config['SECRET_KEY']
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ('true', '1', 'yes'),
)

# Токен для cron-запросов к API синхронизации. Проверка по remote_addr убрана:
# за reverse-proxy все запросы приходят с 127.0.0.1, что открывало API всем.
SYNC_API_TOKEN = os.environ.get('SYNC_API_TOKEN') or _load_or_create_secret('sync_token')

# -------------------- Настройки Active Directory / LDAP (.env) --------------------
def _env_bool(name, fallback_name=None, default=False):
    val = os.environ.get(name)
    if val is None and fallback_name:
        val = os.environ.get(fallback_name)
    if val is None:
        return default
    return val.strip().lower() in ('true', '1', 'yes')

LDAP_CONFIG = {
    'enabled': _env_bool('LDAP_ENABLED', 'AD_ENABLED', False),
    'server': (os.environ.get('LDAP_SERVER') or os.environ.get('AD_SERVER') or '').strip(),
    'port': int(os.environ.get('LDAP_PORT') or os.environ.get('AD_PORT') or 389),
    'use_ssl': _env_bool('LDAP_USE_SSL', 'AD_USE_SSL', False),
    'domain': (os.environ.get('LDAP_DOMAIN') or os.environ.get('AD_DOMAIN') or '').strip(),
    'base_dn': (os.environ.get('LDAP_BASE_DN') or os.environ.get('AD_BASE_DN') or '').strip(),
    'bind_user': (os.environ.get('LDAP_BIND_USER') or os.environ.get('AD_BIND_USER') or '').strip(),
    'bind_password': os.environ.get('LDAP_BIND_PASSWORD') or os.environ.get('AD_BIND_PASSWORD') or '',
    'required_group': (os.environ.get('LDAP_REQUIRED_GROUP') or os.environ.get('AD_REQUIRED_GROUP') or '').strip(),
    'admin_group': (os.environ.get('LDAP_ADMIN_GROUP') or os.environ.get('AD_ADMIN_GROUP') or '').strip(),
    'financier_group': (os.environ.get('LDAP_FINANCIER_GROUP') or os.environ.get('AD_FINANCIER_GROUP') or '').strip(),
    'admin_users': [u.strip().lower() for u in (os.environ.get('LDAP_ADMIN_USERS') or os.environ.get('AD_ADMIN_USERS') or '').split(',') if u.strip()],
    'financier_users': [u.strip().lower() for u in (os.environ.get('LDAP_FINANCIER_USERS') or os.environ.get('AD_FINANCIER_USERS') or '').split(',') if u.strip()],
    'nested_groups': _env_bool('LDAP_NESTED_GROUPS', 'AD_NESTED_GROUPS', True),
}

# Инициализация базы данных
db.init_app(app)

# Настройка SQLite для повышения производительности и устранения блокировок (WAL-режим)
from sqlalchemy import event, inspect
from sqlalchemy.engine import Engine
import sqlite3

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

# Регистрация стандартных функций в шаблонах Jinja2
app.jinja_env.globals.update(min=min, max=max, round=round)

# -------------------- Безопасность и Rate Limiting --------------------

LOGIN_MAX_ATTEMPTS = 10
LOGIN_WINDOW_SECONDS = 300

def login_rate_limited(key):
    now = time.time()
    cutoff = now - LOGIN_WINDOW_SECONDS
    try:
        LoginRateLimit.query.filter(LoginRateLimit.attempt_time < cutoff).delete()
        count = LoginRateLimit.query.filter(
            LoginRateLimit.rate_key == key,
            LoginRateLimit.attempt_time >= cutoff
        ).count()
        db.session.commit()
        return count >= LOGIN_MAX_ATTEMPTS
    except Exception as e:
        db.session.rollback()
        print(f"Rate limit check error: {e}")
        return False

def register_failed_login(key):
    try:
        db.session.add(LoginRateLimit(rate_key=key, attempt_time=time.time()))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Register failed login error: {e}")

# -------------------- Аутентификация через Active Directory / LDAP --------------------

def _clean_ldap_host(server_str):
    if not server_str:
        return "", None, None
    cleaned = server_str.strip().strip('"').strip("'")
    use_ssl = None
    if cleaned.lower().startswith("ldaps://"):
        use_ssl = True
        cleaned = cleaned[8:]
    elif cleaned.lower().startswith("ldap://"):
        use_ssl = False
        cleaned = cleaned[7:]
    cleaned = cleaned.rstrip("/").strip()
    port = None
    if ":" in cleaned:
        host_part, port_part = cleaned.rsplit(":", 1)
        if port_part.isdigit():
            cleaned = host_part
            port = int(port_part)
    return cleaned, port, use_ssl

def authenticate_ldap(identifier, password):
    """
    Проверяет учетные данные пользователя (по корпоративной почте mail, UPN или логину sAMAccountName)
    в домене Active Directory / LDAP.
    Возвращает: (success: bool, resolved_username: str, ad_role: str|None, display_name: str, error_msg: str|None)
    """
    if not LDAP_CONFIG['enabled']:
        return False, None, None, None, "Авторизация через Active Directory отключена"

    if not LDAP_AVAILABLE:
        return False, None, None, None, "Модуль ldap3 не установлен на сервере"

    host, parsed_port, parsed_ssl = _clean_ldap_host(LDAP_CONFIG['server'])
    port = parsed_port or LDAP_CONFIG['port']
    use_ssl = parsed_ssl if parsed_ssl is not None else LDAP_CONFIG['use_ssl']
    ldap_domain = LDAP_CONFIG['domain']
    base_dn = LDAP_CONFIG['base_dn']
    bind_user = LDAP_CONFIG['bind_user']
    bind_password = LDAP_CONFIG['bind_password']
    req_group = LDAP_CONFIG['required_group']
    admin_group = LDAP_CONFIG['admin_group']
    financier_group = LDAP_CONFIG['financier_group']

    if not host or not base_dn:
        return False, None, None, None, "Не настроены LDAP_SERVER или LDAP_BASE_DN в .env"

    clean_id = identifier.strip()
    clean_user = clean_id
    if "@" in clean_user:
        clean_user = clean_user.split("@")[0].strip()
    elif "\\" in clean_user:
        clean_user = clean_user.split("\\")[-1].strip()

    domain_short = ldap_domain.split(".")[0].upper() if ldap_domain else ""

    try:
        server = LdapServer(host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=5)
        user_entry = None
        user_dn = None
        user_conn = None

        # Шаг 1: Поиск пользователя через сервисную учетную запись (Search-then-Bind)
        if bind_user and bind_password:
            bind_candidates = [bind_user]
            if domain_short and "\\" not in bind_user and "@" not in bind_user:
                bind_candidates.append(f"{domain_short}\\{bind_user}")
            if ldap_domain and "@" not in bind_user and "\\" not in bind_user:
                bind_candidates.append(f"{bind_user}@{ldap_domain}")

            svc_conn = None
            for b_cand in dict.fromkeys(bind_candidates):
                try:
                    tc = LdapConnection(server, user=b_cand, password=bind_password, auto_bind=True)
                    if tc.bound:
                        svc_conn = tc
                        break
                except Exception:
                    continue

            if svc_conn and svc_conn.bound:
                safe_id = escape_filter_chars(clean_id)
                safe_user = escape_filter_chars(clean_user)
                upn_cand = escape_filter_chars(f"{clean_user}@{ldap_domain}") if ldap_domain else safe_id
                search_filter = (
                    f"(&(objectCategory=person)(objectClass=user)"
                    f"(|(mail={safe_id})(userPrincipalName={safe_id})(userPrincipalName={upn_cand})"
                    f"(sAMAccountName={safe_id})(sAMAccountName={safe_user})))"
                )
                svc_conn.search(
                    search_base=base_dn,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=['distinguishedName', 'sAMAccountName', 'userPrincipalName', 'displayName', 'mail', 'memberOf']
                )
                if not svc_conn.entries:
                    svc_conn.unbind()
                    return False, None, None, None, f"Пользователь «{clean_id}» не найден в Active Directory"

                user_entry = svc_conn.entries[0]
                user_dn = str(user_entry.entry_dn) if hasattr(user_entry, 'entry_dn') else str(user_entry.distinguishedName)
                user_upn = str(user_entry.userPrincipalName) if hasattr(user_entry, 'userPrincipalName') and user_entry.userPrincipalName else None
                user_sam = str(user_entry.sAMAccountName) if hasattr(user_entry, 'sAMAccountName') and user_entry.sAMAccountName else clean_user
                svc_conn.unbind()

                # Шаг 2: Проверяем пароль найденного пользователя
                verify_candidates = [user_dn, user_upn]
                if domain_short:
                    verify_candidates.append(f"{domain_short}\\{user_sam}")
                if ldap_domain:
                    verify_candidates.append(f"{user_sam}@{ldap_domain}")
                verify_candidates.append(user_sam)

                for cand in dict.fromkeys([c for c in verify_candidates if c]):
                    try:
                        tc = LdapConnection(server, user=cand, password=password, auto_bind=True)
                        if tc.bound:
                            user_conn = tc
                            break
                    except Exception:
                        continue

                if not user_conn or not user_conn.bound:
                    return False, None, None, None, "Неверный пароль доменной учетной записи Active Directory"
                user_conn.unbind()

        # Шаг 2 (Fallback): Прямой Bind, если сервисная учетная запись не задана
        if not user_entry:
            direct_candidates = [clean_id]
            if domain_short:
                direct_candidates.append(f"{domain_short}\\{clean_user}")
            if ldap_domain:
                direct_candidates.append(f"{clean_user}@{ldap_domain}")
            direct_candidates.append(clean_user)

            for cand in dict.fromkeys([c for c in direct_candidates if c]):
                try:
                    tc = LdapConnection(server, user=cand, password=password, auto_bind=True)
                    if tc.bound:
                        user_conn = tc
                        break
                except Exception:
                    continue

            if not user_conn or not user_conn.bound:
                return False, None, None, None, "Неверный корпоративный email/логин или пароль Active Directory"

            # Читаем атрибуты пользователя под его собственным подключением
            safe_id = escape_filter_chars(clean_id)
            safe_user = escape_filter_chars(clean_user)
            upn_cand = escape_filter_chars(f"{clean_user}@{ldap_domain}") if ldap_domain else safe_id
            search_filter = (
                f"(&(objectCategory=person)(objectClass=user)"
                f"(|(mail={safe_id})(userPrincipalName={safe_id})(userPrincipalName={upn_cand})"
                f"(sAMAccountName={safe_id})(sAMAccountName={safe_user})))"
            )
            user_conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['distinguishedName', 'sAMAccountName', 'userPrincipalName', 'displayName', 'mail', 'memberOf']
            )
            if user_conn.entries:
                user_entry = user_conn.entries[0]
                user_dn = str(user_entry.entry_dn) if hasattr(user_entry, 'entry_dn') else str(user_entry.distinguishedName)
            user_conn.unbind()

        # Определяем почту / логин и отображаемое имя
        display_name = clean_user
        resolved_email = clean_id.lower() if "@" in clean_id else (f"{clean_user}@{ldap_domain}".lower() if ldap_domain else clean_user.lower())
        user_groups = []

        if user_entry:
            if hasattr(user_entry, 'displayName') and user_entry.displayName:
                display_name = str(user_entry.displayName)
            if hasattr(user_entry, 'mail') and user_entry.mail:
                resolved_email = str(user_entry.mail).strip().lower()
            elif hasattr(user_entry, 'userPrincipalName') and user_entry.userPrincipalName and "@" in str(user_entry.userPrincipalName):
                if "@" not in clean_id:
                    resolved_email = str(user_entry.userPrincipalName).strip().lower()
            if hasattr(user_entry, 'memberOf') and user_entry.memberOf:
                user_groups = [str(g).lower() for g in user_entry.memberOf]

        # Шаг 3: Проверка членства в группах AD (включая вложенные группы)
        def is_member_of_group(target_group):
            if not target_group:
                return False
            target_lower = target_group.lower()
            for g in user_groups:
                if target_lower == g or f"cn={target_lower}," in g:
                    return True
            if LDAP_CONFIG['nested_groups'] and user_dn and bind_user and bind_password:
                try:
                    s_conn = LdapConnection(server, user=bind_user, password=bind_password, auto_bind=True)
                    safe_grp = escape_filter_chars(target_group)
                    grp_filter = f"(&(objectCategory=group)(|(cn={safe_grp})(distinguishedName={safe_grp})))"
                    s_conn.search(search_base=base_dn, search_filter=grp_filter, search_scope=SUBTREE, attributes=['distinguishedName'])
                    if s_conn.entries:
                        group_dn = escape_filter_chars(str(s_conn.entries[0].entry_dn if hasattr(s_conn.entries[0], 'entry_dn') else s_conn.entries[0].distinguishedName))
                        safe_user_dn = escape_filter_chars(user_dn)
                        nested_filter = f"(&(objectCategory=person)(objectClass=user)(distinguishedName={safe_user_dn})(memberOf:1.2.840.113556.1.4.1941:={group_dn}))"
                        s_conn.search(search_base=base_dn, search_filter=nested_filter, search_scope=SUBTREE, attributes=['distinguishedName'])
                        is_member = len(s_conn.entries) > 0
                        s_conn.unbind()
                        return is_member
                    s_conn.unbind()
                except Exception as e:
                    print(f"[LDAP] Ошибка проверки вложенных групп: {e}")
            return False

        if req_group and not is_member_of_group(req_group):
            return False, None, None, None, f"Доступ запрещен: учетная запись не состоит в группе «{req_group}»"

        # Шаг 4: Определение роли из AD (если применимо)
        ad_role = None
        admin_users_list = LDAP_CONFIG['admin_users']
        financier_users_list = LDAP_CONFIG['financier_users']
        user_candidates = {clean_user.lower(), resolved_email.lower(), clean_id.lower()}
        if (user_candidates & set(admin_users_list)) or (admin_group and is_member_of_group(admin_group)):
            ad_role = 'admin'
        elif (user_candidates & set(financier_users_list)) or (financier_group and is_member_of_group(financier_group)):
            ad_role = 'financier'

        return True, resolved_email, ad_role, display_name, None

    except Exception as e:
        print(f"[LDAP ERROR] Ошибка соединения с контроллером домена: {e}")
        return False, None, None, None, f"Ошибка соединения с контроллером домена AD: {e}"

def sync_access_allowed():
    token = request.headers.get('X-Sync-Token') or request.args.get('token')
    if token and secrets.compare_digest(token, SYNC_API_TOKEN):
        return True
    return ('user_id' in session) and (session.get('role') in ['admin', 'financier'])

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

def get_known_clients():
    """Собирает список уникальных имен клиентов из комментариев ВМ и квот для автодополнения (<datalist>)."""
    try:
        clients = set()
        for (c,) in db.session.query(VirtualMachine.comment).filter(VirtualMachine.deleted == False, VirtualMachine.comment.isnot(None)).distinct():
            if c and c.strip():
                clients.add(c.strip())
        for (c, comp) in db.session.query(CompanyQuota.comment, CompanyQuota.company_name).filter(CompanyQuota.is_hidden == False).all():
            if c and c.strip():
                clients.add(c.strip())
            elif comp and comp.strip():
                clients.add(comp.strip())
        return sorted(clients, key=lambda s: s.lower())
    except Exception:
        return []

@app.context_processor
def inject_user():
    ctx = {
        'current_user': None,
        'ldap_enabled': LDAP_CONFIG['enabled'],
        'known_clients': []
    }
    if 'user_id' in session:
        ctx['current_user'] = {
            'id': session.get('user_id'),
            'username': session.get('username'),
            'display_name': session.get('display_name') or session.get('username'),
            'role': session.get('role'),
            'auth_source': session.get('auth_source', 'local')
        }
        ctx['known_clients'] = get_known_clients()
    return ctx

# -------------------- Инициализация и миграция БД --------------------

def migrate_db():
    """
    Автоматическая миграция схемы БД SQLite на лету.
    Проверяет наличие колонок через инспектор SQLAlchemy перед выполнением ALTER TABLE.
    """
    migrations = [
        ('virtual_machine', 'manual_price', 'FLOAT'),
        ('virtual_machine', 'comment', 'VARCHAR(255)'),
        ('server', 'expense', 'FLOAT'),
        ('company_quota', 'manual_price', 'FLOAT'),
        ('company_quota', 'comment', 'VARCHAR(255)'),
        ('pricing_policy', 'sync_interval_hours', 'INTEGER DEFAULT 1'),
        ('user', 'auth_source', "VARCHAR(20) DEFAULT 'local'"),
        ('user', 'display_name', 'VARCHAR(120)'),
    ]
    with app.app_context():
        inspector = inspect(db.engine)
        existing_tables = set(inspector.get_table_names())
        for table_name, col_name, col_type in migrations:
            if table_name not in existing_tables:
                continue
            existing_cols = {c['name'] for c in inspector.get_columns(table_name)}
            if col_name not in existing_cols:
                try:
                    db.session.execute(db.text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}"))
                    db.session.commit()
                    print(f"Миграция: Добавлена колонка {col_name} в {table_name}")
                except Exception as e:
                    db.session.rollback()
                    print(f"Ошибка миграции {table_name}.{col_name}: {e}")

def init_db():
    db.create_all()
    print("Таблицы базы данных проверены/созданы.")

# -------------------- Авторизация --------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        rate_key = request.remote_addr or 'unknown'
        if login_rate_limited(rate_key):
            flash("Слишком много неудачных попыток входа. Попробуйте через 5 минут.")
            return render_template('login.html')

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Введите логин/почту и пароль!")
            return render_template('login.html')

        # 1. Проверяем локальную учетную запись (например, локальный admin)
        local_user = User.query.filter(db.func.lower(User.username) == username.lower()).first()
        if local_user and local_user.auth_source != 'ldap' and local_user.check_password(password):
            session['user_id'] = local_user.id
            session['username'] = local_user.username
            session['display_name'] = local_user.display_name or local_user.username
            session['role'] = local_user.role
            session['auth_source'] = 'local'
            return redirect(url_for('index'))

        # 2. Если включена авторизация через Active Directory / LDAP — проверяем по почте или логину в домене
        if LDAP_CONFIG['enabled']:
            ldap_ok, resolved_email, ad_role, display_name, ldap_err = authenticate_ldap(username, password)
            if ldap_ok:
                # Ищем пользователя в БД по почте или логину
                short_login = username.split('@')[0].strip().lower()
                db_user = User.query.filter(
                    db.func.lower(User.username).in_([resolved_email.lower(), username.lower(), short_login])
                ).first()

                if not db_user:
                    db_user = User(
                        username=resolved_email.lower(),
                        role=ad_role or 'user',
                        auth_source='ldap',
                        display_name=display_name
                    )
                    db_user.set_password(None)
                    db.session.add(db_user)
                else:
                    db_user.username = resolved_email.lower()
                    db_user.auth_source = 'ldap'
                    db_user.display_name = display_name
                    # Если роль явно определена группами AD / списком админов — обновляем, иначе сохраняем назначенную в панели роль
                    if ad_role:
                        db_user.role = ad_role
                db.session.commit()

                session['user_id'] = db_user.id
                session['username'] = db_user.username
                session['display_name'] = db_user.display_name or db_user.username
                session['role'] = db_user.role
                session['auth_source'] = 'ldap'
                return redirect(url_for('index'))
            else:
                register_failed_login(rate_key)
                flash(ldap_err or "Неверный корпоративный email/логин или пароль!")
                return render_template('login.html')

        register_failed_login(rate_key)
        flash("Неверное имя пользователя или пароль!")
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if session.get('auth_source') == 'ldap':
        flash("Вы вошли через Active Directory. Смена пароля выполняется в домене Windows.", "info")
        return redirect(url_for('index'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        
        user = db.session.get(User, session['user_id'])
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
    users = User.query.order_by(User.id.asc()).all()
    return render_template('users.html', users=users)

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'user')
    auth_source = request.form.get('auth_source', 'local')

    if role not in ('admin', 'financier', 'user'):
        role = 'user'
    
    if not username:
        flash("Укажите логин или корпоративную почту пользователя!", "danger")
        return redirect(url_for('users_admin'))

    if auth_source == 'local' and not password:
        flash("Для локального пользователя необходимо указать пароль!", "danger")
        return redirect(url_for('users_admin'))
        
    existing_user = User.query.filter(db.func.lower(User.username) == username.lower()).first()
    if existing_user:
        flash("Пользователь с таким логином или почтой уже существует!", "danger")
        return redirect(url_for('users_admin'))
        
    new_user = User(
        username=username.lower() if auth_source == 'ldap' else username,
        role=role,
        auth_source='ldap' if auth_source == 'ldap' else 'local'
    )
    new_user.set_password(password if auth_source == 'local' else None)
    db.session.add(new_user)
    db.session.commit()
    
    flash(f"Пользователь {new_user.username} успешно создан!", "success")
    return redirect(url_for('users_admin'))

@app.route('/admin/users/edit/<int:user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Не даем админу менять собственную роль (чтобы случайно не лишить себя прав)
    if user.username != session.get('username'):
        new_role = request.form.get('role', user.role)
        if new_role in ('admin', 'financier', 'user'):
            user.role = new_role
        
    # Если введен новый пароль для локального пользователя — обновляем его
    new_password = request.form.get('password')
    if new_password and new_password.strip():
        user.auth_source = 'local'
        user.set_password(new_password.strip())
        
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
    all_servers = Server.query.options(selectinload(Server.virtual_machines)).filter_by(deleted=False).filter(Server.type.in_(['manual', 'proxmox_node'])).all()
    
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

    # Родительские кластеры выбираем одним запросом вместо запроса на каждый сервер
    parent_ids = {d['server'].parent_id for d in servers_data_map.values() if d['server'].parent_id}
    parents_map = {p.id: p for p in Server.query.filter(Server.id.in_(parent_ids)).all()} if parent_ids else {}

    for s_id, s_data in servers_data_map.items():
        s = s_data['server']
        if s.parent_id:
            parent = parents_map.get(s.parent_id)
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
    
    # Обновляем тарифы только если поля явно переданы в форме, чтобы не затирать индивидуальные тарифы хоста
    if 'cpu_price' in request.form:
        server.cpu_price = parse_float_or_none(request.form.get('cpu_price'))
    if 'ram_price_gb' in request.form:
        server.ram_price_gb = parse_float_or_none(request.form.get('ram_price_gb'))
    if 'ssd_price_gb' in request.form:
        server.ssd_price_gb = parse_float_or_none(request.form.get('ssd_price_gb'))
    if 'hdd_price_gb' in request.form:
        server.hdd_price_gb = parse_float_or_none(request.form.get('hdd_price_gb'))
    if 'backup_price_gb' in request.form:
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
        return redirect(url_for('index'))
        
    quota = CompanyQuota.query.get_or_404(quota_id)
    
    # Комментарий могут менять и админ, и финансисту
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

def _build_pricing_data(policy):
    vms = VirtualMachine.query.options(joinedload(VirtualMachine.server)).filter_by(deleted=False).all()

    # Сначала группируем ВМ по серверам (хостам)
    vms_by_server = {}
    servers_by_id = {}
    for vm in vms:
        srv = vm.server
        if not srv:
            continue
        if srv.id not in vms_by_server:
            vms_by_server[srv.id] = []
            servers_by_id[srv.id] = srv
        vms_by_server[srv.id].append(vm)

    # Инициализируем кластеры
    clusters = Server.query.filter_by(deleted=False, type='proxmox').all()
    clusters_data = {}
    for c in clusters:
        clusters_data[c.id] = {
            'cluster': c,
            'hosts': []
        }
        
    standalone_hosts = []
    total_vms_revenue = 0.0
    
    def get_effective_pricing(srv, policy):
        # 1. Свой тариф хоста
        if srv.cpu_price is not None:
            return srv.cpu_price, srv.ram_price_gb, srv.ssd_price_gb, srv.hdd_price_gb, 'host'
        # 2. Тариф родительского кластера
        if srv.parent_id:
            parent = srv.parent
            if parent and parent.cpu_price is not None:
                return parent.cpu_price, parent.ram_price_gb, parent.ssd_price_gb, parent.hdd_price_gb, 'cluster'
        # 3. Глобальный базовый тариф
        return policy.cpu_price, policy.ram_price_gb, policy.ssd_price_gb, policy.hdd_price_gb, 'global'
        
    for srv_id, srv_vms in vms_by_server.items():
        srv = servers_by_id[srv_id]
        if srv.deleted:
            continue
            
        # Определяем эффективные тарифы хоста (свой -> кластера -> глобальный)
        cpu_pr, ram_pr, ssd_pr, hdd_pr, pricing_source_type = get_effective_pricing(srv, policy)

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
                
        for g in commented_groups.values():
            grouped_items.append(g)
            
        # Общие физические объемы ресурсов хоста
        total_host_cpu = srv.cpu if srv.cpu > 0 else sum(vm.cpu for vm in srv_vms)
        if total_host_cpu == 0: total_host_cpu = 1
        
        total_host_ram = srv.ram if srv.ram > 0 else sum(vm.ram for vm in srv_vms)
        if total_host_ram == 0: total_host_ram = 1
        
        total_host_ssd = srv.ssd if srv.ssd > 0 else sum(vm.ssd for vm in srv_vms)
        if total_host_ssd == 0: total_host_ssd = 1
        
        total_host_hdd = srv.hdd if srv.hdd > 0 else sum(vm.hdd for vm in srv_vms)
        if total_host_hdd == 0: total_host_hdd = 1
        
        host_expense = srv.expense if srv.expense else 0.0
        server_income = 0.0
        server_expense = 0.0
        processed_items = []
        
        for item in grouped_items:
            share_cpu = (item['cpu'] / total_host_cpu) * 100
            share_ram = (item['ram'] / total_host_ram) * 100
            share_ssd = (item['ssd'] / total_host_ssd) * 100
            share_hdd = (item['hdd'] / total_host_hdd) * 100
            
            income = item['manual_price'] if item['has_manual'] else item['auto_cost']
            total_vms_revenue += income
            server_income += income
            
            expense = host_expense * (item['ram'] / total_host_ram)
            server_expense += expense
            
            profit = income - expense
            rentability = (profit / expense * 100) if expense > 0 else 0.0
            
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
        total_share_cpu = sum(item['share_cpu'] for item in processed_items)
        total_share_ram = sum(item['share_ram'] for item in processed_items)
        total_share_ssd = sum(item['share_ssd'] for item in processed_items)
        total_share_hdd = sum(item['share_hdd'] for item in processed_items)
        server_rentability = (server_profit / server_expense * 100) if server_expense > 0 else 0.0
        
        host_data = {
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
            'hdd_price': hdd_pr,
            'pricing_source_type': pricing_source_type
        }
        
        # Группируем хост под кластер или в одиночные
        if srv.parent_id and srv.parent_id in clusters_data:
            clusters_data[srv.parent_id]['hosts'].append(host_data)
        else:
            standalone_hosts.append(host_data)

    # Группируем квоты по серверам
    backup_servers = Server.query.filter_by(deleted=False, type='backup_ssh').all()
    backup_servers_data = []
    total_quotas_revenue = 0.0
    
    for s in backup_servers:
        # Исключаем скрытые квоты
        server_quotas = CompanyQuota.query.filter_by(server_id=s.id, is_hidden=False).all()
        if not server_quotas:
            continue
            
        backup_pr = s.backup_price_gb if s.backup_price_gb is not None else policy.backup_price_gb
        
        commented_groups = {}
        grouped_items = []
        
        for q in server_quotas:
            client_name = q.comment.strip() if (q.comment and q.comment.strip()) else None
            auto_cost = q.allocated_quota * backup_pr
            
            if client_name:
                if client_name not in commented_groups:
                    commented_groups[client_name] = {
                        'client_name': client_name,
                        'is_group': True,
                        'quotas_list': [],
                        'allocated_quota': 0,
                        'actual_usage': 0.0,
                        'auto_cost': 0.0,
                        'manual_price': 0.0,
                        'has_manual': False,
                        'representative_quota_id': q.id
                    }
                g = commented_groups[client_name]
                g['quotas_list'].append(q)
                g['allocated_quota'] += q.allocated_quota
                g['actual_usage'] += q.actual_usage
                g['auto_cost'] += auto_cost
                if q.manual_price is not None:
                    g['manual_price'] += q.manual_price
                    g['has_manual'] = True
            else:
                grouped_items.append({
                    'client_name': q.company_name,
                    'is_group': False,
                    'quotas_list': [q],
                    'allocated_quota': q.allocated_quota,
                    'actual_usage': q.actual_usage,
                    'auto_cost': auto_cost,
                    'manual_price': q.manual_price if q.manual_price is not None else 0.0,
                    'has_manual': q.manual_price is not None,
                    'representative_quota_id': q.id
                })
                
        for g in commented_groups.values():
            grouped_items.append(g)
            
        processed_items = []
        server_income = 0.0
        
        for item in grouped_items:
            income = item['manual_price'] if item['has_manual'] else item['auto_cost']
            total_quotas_revenue += income
            server_income += income
            
            if item['is_group']:
                other_names = [q.company_name for q in item['quotas_list']]
                note = f"аккаунты: {', '.join(other_names)}"
            else:
                note = "Аккаунт"
                
            processed_items.append({
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
            
        backup_servers_data.append({
            'server': s,
            'grouped_items': processed_items,
            'total_income': server_income,
            'backup_price_gb': backup_pr
        })

    return clusters_data, standalone_hosts, backup_servers_data, total_vms_revenue, total_quotas_revenue


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
        flash("Глобальные базовые тарифы успешно обновлены!", "success")
        return redirect(url_for('pricing'))

    clusters_data, standalone_hosts, backup_servers_data, total_vms_revenue, total_quotas_revenue = _build_pricing_data(policy)

    return render_template('pricing.html', 
                           policy=policy, 
                           clusters_data=clusters_data,
                           standalone_hosts=standalone_hosts, 
                           backup_servers_data=backup_servers_data,
                           total_vms_revenue=round(total_vms_revenue, 2),
                           total_quotas_revenue=round(total_quotas_revenue, 2))


@app.route('/pricing/export/csv')
@login_required
def export_pricing_csv():
    import csv
    import io
    policy = PricingPolicy.query.first()
    clusters_data, standalone_hosts, backup_servers_data, total_vms_revenue, total_quotas_revenue = _build_pricing_data(policy)

    output = io.StringIO()
    output.write('\ufeff')  # UTF-8 BOM для Excel
    writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_MINIMAL)

    writer.writerow([
        'Раздел',
        'Кластер / Сервер',
        'Клиент / Группа',
        'Состав / Примечание',
        'CPU (ядер)',
        'RAM (ГБ)',
        'SSD (ГБ)',
        'HDD (ГБ)',
        'Квота бэкапа (ГБ)',
        'Факт бэкапа (ГБ)',
        'Расчет по тарифу (₸)',
        'Ручной ценник (₸)',
        'Итоговый доход (₸)',
        'Расход хоста на клиента (₸)',
        'Прибыль (₸)',
        'Рентабельность (%)'
    ])

    all_hosts = []
    for c_data in clusters_data.values():
        cluster_name = c_data['cluster'].name
        for h_data in c_data['hosts']:
            all_hosts.append((f"{cluster_name} / {h_data['server'].name}", h_data))
    for h_data in standalone_hosts:
        all_hosts.append((h_data['server'].name, h_data))

    for host_label, h_data in all_hosts:
        for item in h_data['grouped_items']:
            writer.writerow([
                'Вычислительные ресурсы (ВМ)',
                host_label,
                item['client_name'],
                item['note'],
                item['cpu'],
                item['ram'],
                item['ssd'],
                item['hdd'],
                '',
                '',
                round(item['auto_cost'], 2),
                round(item['manual_price'], 2) if item['has_manual'] else '',
                round(item['income'], 2),
                round(item['expense'], 2),
                round(item['profit'], 2),
                round(item['rentability'], 1)
            ])

    for b_data in backup_servers_data:
        srv_name = b_data['server'].name
        for item in b_data['grouped_items']:
            writer.writerow([
                'Дисковые квоты (Бэкап)',
                srv_name,
                item['client_name'],
                item['note'],
                '',
                '',
                '',
                '',
                item['allocated_quota'],
                item['actual_usage'],
                round(item['auto_cost'], 2),
                round(item['manual_price'], 2) if item['has_manual'] else '',
                round(item['current_cost'], 2),
                '',
                '',
                ''
            ])

    writer.writerow([])
    writer.writerow(['ИТОГО ДОХОД ВМ (₸)', '', '', '', '', '', '', '', '', '', '', '', round(total_vms_revenue, 2), '', '', ''])
    writer.writerow(['ИТОГО ДОХОД КВОТ (₸)', '', '', '', '', '', '', '', '', '', '', '', round(total_quotas_revenue, 2), '', '', ''])
    writer.writerow(['ОБЩАЯ ВЫРУЧКА (₸)', '', '', '', '', '', '', '', '', '', '', '', round(total_vms_revenue + total_quotas_revenue, 2), '', '', ''])

    response = make_response(output.getvalue())
    filename = f"finansovyi_otchet_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response

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
        server_id = int(request.form.get('server_id', 0) or 0)
        if client_name:
            # Ищем все видимые квоты с этим комментарием на конкретном бэкап-сервере
            query = CompanyQuota.query.filter_by(is_hidden=False)
            if server_id:
                query = query.filter_by(server_id=server_id)
            quotas = query.all()
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

# -------------------- Отчет по компаниям и ресурсам --------------------

def get_companies_report_data():
    vms = VirtualMachine.query.options(
        joinedload(VirtualMachine.server).joinedload(Server.parent)
    ).filter_by(deleted=False).all()

    quotas = CompanyQuota.query.options(
        joinedload(CompanyQuota.server)
    ).filter_by(is_hidden=False).all()

    companies_dict = {}

    def get_or_create_company(display_name, key=None):
        norm_key = (key or display_name).strip().lower()
        if norm_key not in companies_dict:
            companies_dict[norm_key] = {
                'name': display_name.strip(),
                'norm_key': norm_key,
                'cpu': 0,
                'ram': 0,
                'ssd': 0,
                'hdd': 0,
                'total_disk': 0,
                'quota_allocated': 0,
                'quota_used': 0.0,
                'vms': [],
                'quotas': []
            }
        return companies_dict[norm_key]

    # 1. Заполняем ВМ
    for vm in vms:
        display_name = vm.comment.strip() if (vm.comment and vm.comment.strip()) else vm.name.strip()
        comp = get_or_create_company(display_name)
        comp['cpu'] += vm.cpu or 0
        comp['ram'] += vm.ram or 0
        comp['ssd'] += vm.ssd or 0
        comp['hdd'] += vm.hdd or 0
        comp['total_disk'] += (vm.ssd or 0) + (vm.hdd or 0)
        
        server_info = vm.server.name if vm.server else "—"
        if vm.server and vm.server.parent:
            server_info = f"{vm.server.parent.name} / {vm.server.name}"
            
        comp['vms'].append({
            'id': vm.id,
            'name': vm.name,
            'vmid': vm.vmid,
            'server_name': server_info,
            'cpu': vm.cpu or 0,
            'ram': vm.ram or 0,
            'ssd': vm.ssd or 0,
            'hdd': vm.hdd or 0,
            'status': vm.status or 'unknown'
        })

    # 2. Заполняем дисковые квоты
    for q in quotas:
        if q.comment and q.comment.strip():
            display_name = q.comment.strip()
            comp = get_or_create_company(display_name)
        else:
            raw_comp = q.company_name.strip()
            lower_comp = raw_comp.lower()
            if lower_comp in companies_dict:
                comp = companies_dict[lower_comp]
            elif lower_comp.startswith('g-') and lower_comp[2:] in companies_dict:
                comp = companies_dict[lower_comp[2:]]
            else:
                comp = get_or_create_company(raw_comp)

        comp['quota_allocated'] += q.allocated_quota or 0
        comp['quota_used'] += q.actual_usage or 0.0

        comp['quotas'].append({
            'id': q.id,
            'company_name': q.company_name,
            'system_name': q.system_name or q.company_name,
            'server_name': q.server.name if q.server else "—",
            'system_type': q.system_type or 'user',
            'allocated_quota': q.allocated_quota or 0,
            'actual_usage': round(q.actual_usage or 0.0, 1),
            'system_hard_limit': round(q.system_hard_limit or 0.0, 1)
        })

    for comp in companies_dict.values():
        comp['quota_used'] = round(comp['quota_used'], 1)
        comp['vms'].sort(key=lambda x: x['name'].lower())
        comp['quotas'].sort(key=lambda x: x['company_name'].lower())

    companies_list = sorted(companies_dict.values(), key=lambda x: x['name'].lower())

    totals = {
        'total_companies': len(companies_list),
        'total_cpu': sum(c['cpu'] for c in companies_list),
        'total_ram': sum(c['ram'] for c in companies_list),
        'total_ssd': sum(c['ssd'] for c in companies_list),
        'total_hdd': sum(c['hdd'] for c in companies_list),
        'total_disk': sum(c['total_disk'] for c in companies_list),
        'total_quota_allocated': sum(c['quota_allocated'] for c in companies_list),
        'total_quota_used': round(sum(c['quota_used'] for c in companies_list), 1),
        'total_vms_count': sum(len(c['vms']) for c in companies_list),
        'total_quotas_count': sum(len(c['quotas']) for c in companies_list),
    }

    return companies_list, totals


@app.route('/companies')
@login_required
def companies_report():
    companies_list, totals = get_companies_report_data()
    return render_template('companies_report.html', companies=companies_list, totals=totals)


@app.route('/companies/print')
@login_required
def companies_print_report():
    companies_list, totals = get_companies_report_data()
    show_details = request.args.get('details', '0') == '1'
    user = User.query.get(session.get('user_id'))
    current_time = datetime.now().strftime('%d.%m.%Y %H:%M')
    return render_template(
        'companies_print.html',
        companies=companies_list,
        totals=totals,
        show_details=show_details,
        generated_at=current_time,
        current_username=user.username if user else 'Пользователь'
    )


@app.route('/companies/export/csv')
@login_required
def export_companies_csv():
    import csv
    import io
    companies_list, totals = get_companies_report_data()
    
    output = io.StringIO()
    output.write('\ufeff')  # UTF-8 BOM для корректного отображения в Microsoft Excel
    writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_MINIMAL)
    
    writer.writerow([
        'Компания / Клиент',
        'CPU (ядер)',
        'RAM (ГБ)',
        'SSD (ГБ)',
        'HDD (ГБ)',
        'Всего диск ВМ (ГБ)',
        'Квота бэкапа (ГБ)',
        'Факт бэкапа (ГБ)',
        'Кол-во ВМ',
        'Список виртуальных машин',
        'Кол-во квот бэкапа',
        'Список бэкап-аккаунтов'
    ])
    
    for c in companies_list:
        vms_str = ", ".join([f"{vm['name']} (CPU:{vm['cpu']}, RAM:{vm['ram']}G, SSD:{vm['ssd']}G, HDD:{vm['hdd']}G)" for vm in c['vms']])
        quotas_str = ", ".join([f"{q['company_name']} ({q['server_name']}: выд.{q['allocated_quota']}G, факт {q['actual_usage']}G)" for q in c['quotas']])
        
        writer.writerow([
            c['name'],
            c['cpu'],
            c['ram'],
            c['ssd'],
            c['hdd'],
            c['total_disk'],
            c['quota_allocated'],
            c['quota_used'],
            len(c['vms']),
            vms_str,
            len(c['quotas']),
            quotas_str
        ])
        
    writer.writerow([
        'ИТОГО ПО ВСЕМ КОМПАНИЯМ',
        totals['total_cpu'],
        totals['total_ram'],
        totals['total_ssd'],
        totals['total_hdd'],
        totals['total_disk'],
        totals['total_quota_allocated'],
        totals['total_quota_used'],
        totals['total_vms_count'],
        '',
        totals['total_quotas_count'],
        ''
    ])
    
    response = make_response(output.getvalue())
    filename = f"otchet_kompanii_resursy_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response

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

@app.route('/api/sync/<int:server_id>', methods=['GET', 'POST'])
def sync_server(server_id):
    # Доступ: сессия admin/financier или cron-запрос с токеном (X-Sync-Token / ?token=)
    if not sync_access_allowed():
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

@app.route('/api/sync/servers', methods=['GET', 'POST'])
def sync_servers_list():
    # Доступ: сессия admin/financier или cron-запрос с токеном (X-Sync-Token / ?token=)
    if not sync_access_allowed():
        return jsonify({'status': 'error', 'message': 'Доступ запрещен'}), 403
    servers = Server.query.filter_by(deleted=False).filter(Server.type.in_(['proxmox', 'backup_ssh'])).all()
    return jsonify({
        'status': 'success',
        'servers': [{'id': s.id, 'name': s.name, 'type': s.type} for s in servers]
    })

@app.route('/api/sync/all', methods=['GET', 'POST'])
def sync_all():
    # Доступ: сессия admin/financier или cron-запрос с токеном (X-Sync-Token / ?token=)
    if not sync_access_allowed():
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
        # Фиксируем статус каждого сервера сразу
        try:
            db.session.commit()
        except Exception as commit_err:
            db.session.rollback()
            print(f"Ошибка коммита статуса сервера {s.id}: {commit_err}")
            
    return jsonify({'status': 'completed', 'results': results})

# -------------------- Автоматический планировщик --------------------

def scheduled_sync_all():
    with app.app_context():
        try:
            policy = PricingPolicy.query.first()
            interval_hours = policy.sync_interval_hours if (policy and policy.sync_interval_hours) else 1
            
            servers = Server.query.filter_by(deleted=False).filter(Server.type.in_(['proxmox', 'backup_ssh'])).all()
            from datetime import timedelta
            servers_to_sync = []
            
            for s in servers:
                should_sync = False
                if not s.last_sync:
                    should_sync = True
                else:
                    elapsed = datetime.now() - s.last_sync
                    if elapsed >= timedelta(hours=interval_hours):
                        should_sync = True
                if should_sync:
                    servers_to_sync.append(s.id)
            
            # Закрываем сессию, чтобы освободить базу от блокировок на время долгой сетевой работы
            db.session.remove()
            
            from sync_engine import run_sync
            for server_id in servers_to_sync:
                s_name = ""
                # Запрашиваем имя сервера в быстрой транзакции
                s = Server.query.get(server_id)
                if s:
                    s_name = s.name
                    print(f"[{datetime.now()}] Запуск фоновой автосинхронизации для сервера: {s_name}")
                db.session.remove()
                
                if not s_name:
                    continue
                
                # Сетевой запрос выполняется без удержания открытой сессии БД
                try:
                    s_obj = Server.query.get(server_id)
                    if s_obj:
                        success, message = run_sync(s_obj)
                    else:
                        success, message = False, "Сервер не найден"
                except Exception as e:
                    success, message = False, str(e)
                    print(f"Ошибка фоновой автосинхронизации сервера {s_name}: {e}")
                
                # Записываем результаты в отдельной короткой транзакции
                try:
                    s_obj = Server.query.get(server_id)
                    if s_obj:
                        if success:
                            s_obj.status = 'online'
                            s_obj.last_sync = datetime.now()
                        else:
                            s_obj.status = 'offline'
                        db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    print(f"Ошибка сохранения статуса фоновой синхронизации для {s_name}: {e}")
                finally:
                    db.session.remove()
                    
        except Exception as e:
            print(f"[{datetime.now()}] Ошибка фоновой автосинхронизации: {e}")

_scheduler_lock_file = None

def start_scheduler():
    global _scheduler_lock_file
    try:
        import fcntl
        try:
            os.makedirs(app.instance_path, exist_ok=True)
            lock_path = os.path.join(app.instance_path, '.scheduler.lock')
            _scheduler_lock_file = open(lock_path, 'wb')
            fcntl.flock(_scheduler_lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            
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
