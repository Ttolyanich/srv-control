import requests
import paramiko
import io
import re
from datetime import datetime
from models import db, Server, VirtualMachine, CompanyQuota, SyncConfig, ProxmoxStorage

# Отключаем предупреждения о самоподписанных сертификатах SSL
requests.packages.urllib3.disable_warnings()

def run_sync(server):
    """
    Основная функция запуска синхронизации для конкретного сервера.
    Возвращает (success: bool, message: str)
    """
    config = SyncConfig.query.filter_by(server_id=server.id).first()
    if not config:
        return False, "Синхронизация не настроена (отсутствуют учетные данные)"

    if server.type == 'proxmox':
        return sync_proxmox(server, config)
    elif server.type == 'backup_ssh':
        return sync_ssh_quota(server, config)
    else:
        return False, f"Неподдерживаемый тип сервера для синхронизации: {server.type}"


# -------------------- Синхронизация Proxmox API --------------------

def sync_proxmox(server, config):
    try:
        ip = server.ip_address
        username = config.username
        secret = config.get_password()
        extra = config.extra_param  # Имя токена (например, "monitoring") или пусто для пароля

        base_url = f"https://{ip}:8006/api2/json"
        session = requests.Session()
        session.verify = False  # Игнорируем самоподписанные сертификаты

        is_token = bool(extra and ('!' in username or extra))

        if is_token:
            # Авторизация по API Токену
            token_id = f"{username}!{extra}" if '!' not in username else username
            session.headers.update({
                "Authorization": f"PVEAPIToken={token_id}={secret}"
            })
        else:
            # Авторизация по паролю (получение тикета)
            ticket_url = f"{base_url}/access/ticket"
            res = session.post(ticket_url, data={
                "username": username,
                "password": secret
            }, timeout=30)
            res.raise_for_status()
            res_data = res.json().get("data", {})
            
            session.cookies.set("PVEAuthCookie", res_data.get("ticket"))
            session.headers.update({
                "CSRFPreventionToken": res_data.get("CSRFPreventionToken")
            })

        # 0. Попробуем получить IP-адреса нод из статуса кластера
        node_ips = {}
        try:
            cluster_res = session.get(f"{base_url}/cluster/status", timeout=15)
            if cluster_res.status_code == 200:
                cluster_data = cluster_res.json().get("data", [])
                for item in cluster_data:
                    if item.get("type") == "node":
                        node_ips[item.get("name")] = item.get("ip") or item.get("address")
        except Exception:
            pass

        # 0.1 Получаем список хранилищ из Proxmox для классификации дисков
        try:
            storage_res = session.get(f"{base_url}/storage", timeout=15)
            if storage_res.status_code == 200:
                pve_storages = storage_res.json().get("data", [])
                db_storages = {s.storage_name: s for s in server.storages}
                
                for pve_store in pve_storages:
                    store_name = pve_store.get("storage")
                    if store_name not in db_storages:
                        # Автоматически определяем тип по умолчанию
                        content = pve_store.get("content", "")
                        is_vm_disk = "images" in content or "rootdir" in content
                        
                        if not is_vm_disk:
                            store_type = "ignore"
                        elif any(x in store_name.lower() for x in ["ssd", "nvme", "fast"]):
                            store_type = "ssd"
                        elif any(x in store_name.lower() for x in ["backup", "bkp", "iso", "template", "pbs"]):
                            store_type = "ignore"
                        else:
                            store_type = "hdd"
                            
                        new_store = ProxmoxStorage(
                            server_id=server.id,
                            storage_name=store_name,
                            storage_type=store_type
                        )
                        db.session.add(new_store)
                db.session.commit()
        except Exception as e:
            print(f"Ошибка при получении списка хранилищ: {e}")

        # Заново считываем хранилища из БД
        storages_map = {s.storage_name: s.storage_type for s in ProxmoxStorage.query.filter_by(server_id=server.id).all()}

        # 1. Получаем информацию о нодах (физических ресурсах сервера)
        nodes_url = f"{base_url}/nodes"
        res = session.get(nodes_url, timeout=30)
        res.raise_for_status()
        nodes = res.json().get("data", [])
        
        if not nodes:
            return False, "Не найдено ни одной ноды в кластере Proxmox"

        active_node_ids = []

        # Обходим каждую ноду в кластере
        for node in nodes:
            node_name = node.get("node")
            status = node.get("status", "unknown")
            
            # Физические ресурсы ноды
            cpu_total = int(node.get("maxcpu") or 0)
            ram_total = int((node.get("maxmem") or 0) / (1024**3))   # в ГБ
            disk_total = int((node.get("maxdisk") or 0) / (1024**3)) # в ГБ
            
            # Определяем IP-адрес конкретной ноды
            node_ip = node_ips.get(node_name) or server.ip_address

            # Ищем ноду в БД. Если её нет — создаем автоматически
            db_node = Server.query.filter_by(parent_id=server.id, name=node_name).first()
            if not db_node:
                db_node = Server(
                    parent_id=server.id,
                    name=node_name,
                    type='proxmox_node'
                )
                db.session.add(db_node)
                db.session.flush()  # Получаем ID новой ноды

            # Получаем реальный объем SSD и HDD хранилищ для этой ноды
            node_ssd_total = 0
            node_hdd_total = 0
            
            if status == 'online':
                try:
                    node_storage_res = session.get(f"{base_url}/nodes/{node_name}/storage", timeout=15)
                    if node_storage_res.status_code == 200:
                        node_storages = node_storage_res.json().get("data", [])
                        for n_store in node_storages:
                            if n_store.get("active") == 1:
                                store_id = n_store.get("storage")
                                store_total_gb = int((n_store.get("total") or 0) / (1024**3))
                                
                                store_type = storages_map.get(store_id)
                                if not store_type:
                                    # Дефолтная логика автоопределения, если тип не задан в настройках
                                    if any(x in store_id.lower() for x in ["ssd", "nvme", "fast"]):
                                        store_type = "ssd"
                                    elif any(x in store_id.lower() for x in ["backup", "bkp", "iso", "template", "pbs"]):
                                        store_type = "ignore"
                                    else:
                                        store_type = "hdd"
                                
                                if store_type == "ssd":
                                    node_ssd_total += store_total_gb
                                elif store_type == "hdd":
                                    node_hdd_total += store_total_gb
                except Exception as e:
                    print(f"Ошибка получения дисков для ноды {node_name}: {e}")
            
            # Если не удалось получить данные о хранилищах, откатываемся на размер диска ОС
            if node_ssd_total == 0 and node_hdd_total == 0:
                node_ssd_total = disk_total

            # Обновляем характеристики физической ноды
            db_node.ip_address = node_ip
            db_node.cpu = cpu_total
            db_node.ram = ram_total
            db_node.ssd = node_ssd_total
            db_node.hdd = node_hdd_total
            db_node.status = 'online' if status == 'online' else 'offline'
            db_node.last_sync = datetime.now()
            db_node.deleted = False
            
            active_node_ids.append(db_node.id)

            # Если нода отключена, не опрашиваем её виртуальные машины
            if status != 'online':
                continue

            # 2. Получаем список виртуальных машин и контейнеров для данной ноды
            active_vmid_list = []
            
            # ВМ (QEMU)
            qemu_url = f"{base_url}/nodes/{node_name}/qemu"
            res = session.get(qemu_url, timeout=30)
            res.raise_for_status()
            vms = res.json().get("data", [])

            # Контейнеры (LXC)
            lxc_url = f"{base_url}/nodes/{node_name}/lxc"
            res = session.get(lxc_url, timeout=30)
            res.raise_for_status()
            lxcs = res.json().get("data", [])

            all_resources = []
            for vm in vms:
                vm['type'] = 'qemu'
                all_resources.append(vm)
            for lxc in lxcs:
                lxc['type'] = 'lxc'
                all_resources.append(lxc)

            for item in all_resources:
                vmid = int(item.get('vmid'))
                name = item.get('name', f"VM {vmid}")
                vm_status = item.get('status', 'stopped')
                
                cpu_allocated = int(item.get('cpus') or 1)
                ram_allocated = int((item.get('maxmem') or 0) / (1024**3)) # ГБ
                
                # 2.1 Подетальный опрос дисков для разделения SSD и HDD
                vm_ssd = 0
                vm_hdd = 0
                try:
                    cfg_type = 'qemu' if item['type'] == 'qemu' else 'lxc'
                    cfg_url = f"{base_url}/nodes/{node_name}/{cfg_type}/{vmid}/config"
                    cfg_res = session.get(cfg_url, timeout=15)
                    if cfg_res.status_code == 200:
                        cfg_data = cfg_res.json().get("data", {})
                        for key, val in cfg_data.items():
                            is_disk = False
                            if item['type'] == 'qemu':
                                is_disk = any(key.startswith(prefix) for prefix in ['ide', 'sata', 'scsi', 'virtio']) and 'media=cdrom' not in val
                            else:
                                is_disk = key == 'rootfs' or key.startswith('mp')
                                
                            if is_disk:
                                if ':' in val:
                                    parts = val.split(':')
                                    storage_id = parts[0].strip()
                                    
                                    # Ищем размер (например, size=32G)
                                    size_gb = 0
                                    size_match = re.search(r'size=(\d+)([GMT]?)', val)
                                    if size_match:
                                        size_val = int(size_match.group(1))
                                        unit = size_match.group(2)
                                        if unit == 'G' or unit == '':
                                            size_gb = size_val
                                        elif unit == 'M':
                                            size_gb = size_val / 1024
                                        elif unit == 'T':
                                            size_gb = size_val * 1024
                                    else:
                                        # LXC простой формат: "local-SSD:8"
                                        try:
                                            second_part = parts[1].split(',')[0]
                                            if second_part.isdigit():
                                                size_gb = int(second_part)
                                        except Exception:
                                            pass
                                            
                                    if size_gb > 0:
                                        store_type = storages_map.get(storage_id, 'ssd') # по умолчанию ssd
                                        if store_type == 'ssd':
                                            vm_ssd += size_gb
                                        elif store_type == 'hdd':
                                            vm_hdd += size_gb
                except Exception as e:
                    print(f"Не удалось прочесть конфиг дисков для VMID {vmid}: {e}")

                # Если не удалось распределить диски, падаем на дефолтное поведение (все в SSD)
                if vm_ssd == 0 and vm_hdd == 0:
                    disk_allocated = int((item.get('maxdisk') or 0) / (1024**3))
                    vm_ssd = disk_allocated

                active_vmid_list.append(vmid)

                # Ищем ВМ в нашей базе именно для этой ноды
                db_vm = VirtualMachine.query.filter_by(server_id=db_node.id, vmid=vmid).first()
                if not db_vm:
                    db_vm = VirtualMachine(server_id=db_node.id, vmid=vmid)
                    db.session.add(db_vm)

                db_vm.name = name
                db_vm.cpu = cpu_allocated
                db_vm.ram = int(ram_allocated)
                db_vm.ssd = int(vm_ssd)
                db_vm.hdd = int(vm_hdd)
                db_vm.status = 'running' if vm_status == 'running' else 'stopped'
                db_vm.deleted = False

            # Помечаем удаленными те ВМ на этой ноде, которых больше нет в Proxmox
            existing_vms = VirtualMachine.query.filter_by(server_id=db_node.id).all()
            for vm in existing_vms:
                if vm.vmid and vm.vmid not in active_vmid_list:
                    vm.deleted = True

        # Помечаем удаленными ноды, которые пропали из кластера Proxmox
        all_child_nodes = Server.query.filter_by(parent_id=server.id).all()
        for node in all_child_nodes:
            if node.id not in active_node_ids:
                node.deleted = True

        db.session.commit()
        return True, f"Кластер успешно синхронизирован. Найдено нод: {len(nodes)}."

    except Exception as e:
        db.session.rollback()
        return False, f"Ошибка Proxmox API: {str(e)}"


# -------------------- Синхронизация SSH Quota --------------------

def parse_repquota_output(output_text):
    """
    Парсит вывод команды repquota.
    Возвращает словарь {имя_пользователя_или_группы: {'used': блоки_КБ, 'hard': блоки_КБ}}
    """
    results = {}
    lines = output_text.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('-') or line.startswith('*') or line.startswith('User') or line.startswith('Group'):
            continue
        
        parts = line.split()
        if len(parts) >= 5:
            name = parts[0]
            if not parts[1].isdigit():
                try:
                    used = int(parts[2])
                    soft = int(parts[3])
                    hard = int(parts[4])
                    limit = hard if hard > 0 else soft
                    results[name] = {'used': used, 'hard': limit}
                except ValueError:
                    continue
            else:
                try:
                    used = int(parts[1])
                    soft = int(parts[2])
                    hard = int(parts[3])
                    limit = hard if hard > 0 else soft
                    results[name] = {'used': used, 'hard': limit}
                except ValueError:
                    continue
    return results

def sync_ssh_quota(server, config):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ip = server.ip_address
        username = config.username
        secret = config.get_password() or ""
        port = int(config.extra_param or 22)

        if secret.strip().startswith("-----BEGIN"):
            key_file = io.StringIO(secret)
            pkey = paramiko.RSAKey.from_private_key(key_file)
            ssh.connect(ip, port=port, username=username, pkey=pkey, timeout=15)
        else:
            ssh.connect(ip, port=port, username=username, password=secret, timeout=15)

        # 1. Автоматически определяем физический объем диска через df
        try:
            path = server.backup_path or '/'
            stdin, stdout, stderr = ssh.exec_command(f"df -k -P {path}")
            df_output = stdout.read().decode('utf-8', errors='ignore').strip().split('\n')
            if len(df_output) >= 2:
                parts = df_output[1].split()
                if len(parts) >= 2 and parts[1].isdigit():
                    total_gb = int(int(parts[1]) / 1048576) # КБ в ГБ
                    server.hdd = total_gb
        except Exception as e:
            print(f"Ошибка определения объема диска через df: {e}")

        # 2. Считываем вывод repquota для пользователей и групп
        stdin, stdout, stderr = ssh.exec_command("sudo repquota -a")
        user_output = stdout.read().decode('utf-8', errors='ignore')
        user_quotas = parse_repquota_output(user_output)

        stdin, stdout, stderr = ssh.exec_command("sudo repquota -g -a")
        group_output = stdout.read().decode('utf-8', errors='ignore')
        group_quotas = parse_repquota_output(group_output)

        # 2. Объединяем все отсканированные аккаунты
        scanned_quotas = []
        for name, data in user_quotas.items():
            scanned_quotas.append((name, 'user', data))
        for name, data in group_quotas.items():
            scanned_quotas.append((name, 'group', data))

        # 3. Получаем список уже сохраненных квот из нашей базы
        local_quotas = {f"{lq.system_type}_{lq.system_name}": lq for lq in CompanyQuota.query.filter_by(server_id=server.id).all()}
        
        updated_count = 0
        created_count = 0

        # 4. Сопоставляем или автоматически импортируем
        for name, q_type, data in scanned_quotas:
            used_gb = round(data['used'] / 1048576, 2)
            hard_gb = round(data['hard'] / 1048576, 2)

            # Исключаем системные неиспользуемые аккаунты (0 ГБ занято и 0 ГБ лимит)
            if used_gb == 0 and hard_gb == 0:
                continue

            # Исключаем пользователя root, если у него нет лимитов
            if name == 'root' and hard_gb == 0:
                continue

            key = f"{q_type}_{name}"
            
            if key in local_quotas:
                # Обновляем существующий
                lq = local_quotas[key]
                lq.actual_usage = used_gb
                lq.system_hard_limit = hard_gb
                lq.last_sync = datetime.now()
                updated_count += 1
            else:
                # Автоматически импортируем нового пользователя/группу!
                # За договорной лимит берем жесткий лимит диска из ОС. Если он равен 0, берем факт.
                allocated_val = int(hard_gb) if hard_gb > 0 else int(used_gb)
                if allocated_val == 0:
                    allocated_val = 1 # Дефолт минимальный 1 ГБ, если всё по нулям

                new_quota = CompanyQuota(
                    server_id=server.id,
                    company_name=name,  # По умолчанию название совпадает с именем в ОС
                    system_name=name,
                    system_type=q_type,
                    allocated_quota=allocated_val,
                    system_hard_limit=hard_gb,
                    actual_usage=used_gb,
                    last_sync=datetime.now()
                )
                db.session.add(new_quota)
                created_count += 1

        # 5. Автоматически скрываем пользователей, если для них есть группа G-
        all_quotas = CompanyQuota.query.filter_by(server_id=server.id).all()
        group_names = set()
        for q in all_quotas:
            if q.system_type == 'group' and q.system_name and q.system_name.startswith('G-'):
                base_name = q.system_name[2:]
                if base_name:
                    group_names.add(base_name)
        
        if group_names:
            for q in all_quotas:
                if q.system_type == 'user' and q.system_name:
                    is_subuser = False
                    for base in group_names:
                        if q.system_name == base or q.system_name.startswith(base + '-'):
                            is_subuser = True
                            break
                    if is_subuser:
                        q.is_hidden = True

        server.status = 'online'
        db.session.commit()
        
        msg = f"Синхронизация завершена. Обновлено существующих квот: {updated_count}."
        if created_count > 0:
            msg += f" Автоматически импортировано новых квот: {created_count}."
        return True, msg

    except Exception as e:
        db.session.rollback()
        return False, f"Ошибка SSH подключения: {str(e)}"
    finally:
        ssh.close()
