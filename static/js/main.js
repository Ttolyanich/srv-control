// Modal Operations
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('show');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('show');
    }
}

// --- Collapse/Expand Cluster Groups ---
function toggleCluster(header) {
    const group = header.closest('.cluster-group');
    group.classList.toggle('collapsed');
}

// --- VM Modals ---
function openAddVmModal() {
    openModal('add-vm-modal');
}

// --- Toast Notification System ---
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position: fixed; bottom: 24px; right: 24px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; pointer-events: none;';
        document.body.appendChild(container);
    }
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.style.pointerEvents = 'auto';
    
    let icon = 'ℹ️';
    if (type === 'success') icon = '✅';
    if (type === 'error' || type === 'danger') icon = '❌';
    if (type === 'warning') icon = '⚠️';
    
    toast.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
            <span>${icon}</span>
            <span style="font-size: 13px; font-weight: 500;">${message}</span>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()" style="margin-left: 10px;">&times;</button>
    `;
    
    container.appendChild(toast);
    
    // Trigger transition
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    // Auto-remove after 4 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 4000);
}

function openEditVmModal(vmId, name, cpu, ram, ssd, hdd, status, serverType = 'manual', comment = '') {
    const form = document.getElementById('edit-vm-form');
    if (!form) return;
    form.action = `/vm/edit/${vmId}`;
    
    document.getElementById('edit_vm_name').value = name;
    document.getElementById('edit_vm_cpu').value = cpu;
    document.getElementById('edit_vm_ram').value = ram;
    document.getElementById('edit_vm_ssd').value = ssd;
    document.getElementById('edit_vm_hdd').value = hdd;
    document.getElementById('edit_vm_status').value = status;
    
    const commentInput = document.getElementById('edit_vm_comment');
    if (commentInput) {
        commentInput.value = comment;
    }
    
    // Управление предупреждением и доступностью полей для Proxmox ВМ
    const isProxmox = serverType === 'proxmox';
    const warningNote = document.getElementById('proxmox-warning-note');
    if (warningNote) {
        warningNote.style.display = isProxmox ? 'block' : 'none';
    }
    
    const fields = ['edit_vm_name', 'edit_vm_cpu', 'edit_vm_ram', 'edit_vm_ssd', 'edit_vm_hdd', 'edit_vm_status'];
    fields.forEach(fieldId => {
        const el = document.getElementById(fieldId);
        if (el) {
            if (isProxmox) {
                el.setAttribute('disabled', 'disabled');
            } else {
                el.removeAttribute('disabled');
            }
        }
    });
    
    openModal('edit-vm-modal');
}

// --- Quota Modals ---
function openAddQuotaModal(serverId, serverName) {
    const form = document.getElementById('add-quota-form');
    form.action = `/quota/add/${serverId}`;
    document.getElementById('modal-server-name').innerText = serverName;
    openModal('add-quota-modal');
}

function openEditQuotaModal(quotaId, companyName, systemName, systemType, allocatedQuota, actualUsage, serverType, isHidden, comment = '') {
    const form = document.getElementById('edit-quota-form');
    form.action = `/quota/edit/${quotaId}`;
    
    document.getElementById('edit-modal-title').innerText = companyName;
    document.getElementById('edit_company_name').value = companyName;
    document.getElementById('edit_system_name').value = systemName;
    document.getElementById('edit_system_type').value = systemType;
    document.getElementById('edit_allocated_quota').value = allocatedQuota;
    
    // Установка чекбокса скрытия
    const isHiddenChecked = isHidden === true || isHidden === 'true';
    const isHiddenEl = document.getElementById('edit_is_hidden');
    if (isHiddenEl) {
        isHiddenEl.checked = isHiddenChecked;
    }
    
    const commentInput = document.getElementById('edit_comment');
    if (commentInput) {
        commentInput.value = comment;
    }
    
    const warningNote = document.getElementById('backup-warning-note');
    if (warningNote) {
        warningNote.style.display = (serverType === 'backup_ssh') ? 'block' : 'none';
    }
    
    // Если сервер ручной, даем редактировать фактическое использование
    const actualUsageGroup = document.getElementById('edit-actual-usage-group');
    if (serverType === 'manual') {
        actualUsageGroup.style.display = 'block';
        document.getElementById('edit_actual_usage').value = actualUsage;
        document.getElementById('edit_actual_usage').setAttribute('required', 'required');
    } else {
        actualUsageGroup.style.display = 'none';
        document.getElementById('edit_actual_usage').removeAttribute('required');
    }
    
    openModal('edit-quota-modal');
}

// --- Server Modals ---
function openEditServerModal(serverId, name, ipAddress, type, cpu, ram, ssd, hdd, username, extraParam, backupPath) {
    const form = document.getElementById('edit-server-form');
    form.action = `/server/edit/${serverId}`;
    
    document.getElementById('edit_name').value = name;
    document.getElementById('edit_ip_address').value = ipAddress;
    document.getElementById('edit_cpu').value = cpu;
    document.getElementById('edit_ram').value = ram;
    document.getElementById('edit_ssd').value = ssd;
    document.getElementById('edit_hdd').value = hdd;
    document.getElementById('edit_backup_path').value = backupPath || '/';
    
    // Если есть функция toggleSyncFields, вызываем ее
    if (typeof toggleSyncFields === 'function') {
        toggleSyncFields(type, 'edit');
    }
    
    if (type !== 'manual') {
        document.getElementById('edit_username').value = username;
        document.getElementById('edit_extra_param').value = extraParam;
        document.getElementById('edit_password').value = ''; // Пароль не показываем в целях безопасности
    }
    
    openModal('edit-server-modal');
}

// --- Sync Functions ---

function syncServer(serverId, button) {
    if (!button) return;
    
    // Сохраняем оригинальный HTML кнопки
    const originalHtml = button.innerHTML;
    
    // Добавляем эффект анимации загрузки
    button.disabled = true;
    button.innerHTML = `
        <svg class="spinner" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite; margin-right: 6px;">
            <line x1="12" y1="2" x2="12" y2="6"></line>
            <line x1="12" y1="18" x2="12" y2="22"></line>
            <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line>
            <line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line>
            <line x1="2" y1="12" x2="6" y2="12"></line>
            <line x1="18" y1="12" x2="22" y2="12"></line>
            <line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line>
            <line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line>
        </svg>
        Синхронизация...
    `;
    
    // Добавляем стиль для спиннера, если его еще нет
    if (!document.getElementById('spinner-style')) {
        const style = document.createElement('style');
        style.id = 'spinner-style';
        style.innerHTML = `
            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
        `;
        document.head.appendChild(style);
    }

    fetch(`/api/sync/${serverId}`)
        .then(response => {
            const contentType = response.headers.get("content-type");
            if (contentType && contentType.indexOf("application/json") !== -1) {
                return response.json().then(data => ({ status: response.status, body: data }));
            } else {
                return response.text().then(text => ({ status: response.status, body: null, rawText: text }));
            }
        })
        .then(result => {
            if (result.status === 200 && result.body) {
                showToast(result.body.message, 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } else if (result.body) {
                showToast(`Ошибка: ${result.body.message}`, 'error');
                button.disabled = false;
                button.innerHTML = originalHtml;
            } else {
                console.error("Non-JSON response from server:", result.rawText);
                const snippet = result.rawText ? result.rawText.substring(0, 150).replace(/</g, "&lt;").replace(/>/g, "&gt;") : "Empty response";
                showToast(`Сетевая ошибка: Получен некорректный ответ от прокси/сервера. Статус: ${result.status}. Ответ: ${snippet}...`, 'error');
                button.disabled = false;
                button.innerHTML = originalHtml;
            }
        })
        .catch(error => {
            showToast(`Сетевая ошибка: ${error}`, 'error');
            button.disabled = false;
            button.innerHTML = originalHtml;
        });
}

function syncAllServers() {
    const btn = document.getElementById('sync-all-btn');
    if (!btn) return;
    
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `
        <svg class="spinner" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite; margin-right: 6px;">
            <line x1="12" y1="2" x2="12" y2="6"></line>
            <line x1="12" y1="18" x2="12" y2="22"></line>
            <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line>
            <line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line>
            <line x1="2" y1="12" x2="6" y2="12"></line>
            <line x1="18" y1="12" x2="22" y2="12"></line>
            <line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line>
            <line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line>
        </svg>
        Синхронизация всех серверов...
    `;

    fetch('/api/sync/all')
        .then(response => {
            const contentType = response.headers.get("content-type");
            if (contentType && contentType.indexOf("application/json") !== -1) {
                return response.json().then(data => ({ status: response.status, body: data }));
            } else {
                return response.text().then(text => ({ status: response.status, body: null, rawText: text }));
            }
        })
        .then(result => {
            if (result.status === 200 && result.body) {
                let successCount = 0;
                let errorCount = 0;
                result.body.results.forEach(res => {
                    if (res.status === 'success') successCount++;
                    else errorCount++;
                });
                
                if (errorCount === 0) {
                    showToast(`Синхронизация успешно завершена для всех серверов (${successCount})!`, 'success');
                } else {
                    showToast(`Синхронизация завершена. Успешно: ${successCount}, Ошибок: ${errorCount}.`, 'warning');
                }
                
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            } else if (result.body) {
                showToast(`Ошибка: ${result.body.message}`, 'error');
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            } else {
                console.error("Non-JSON response from server:", result.rawText);
                const snippet = result.rawText ? result.rawText.substring(0, 150).replace(/</g, "&lt;").replace(/>/g, "&gt;") : "Empty response";
                showToast(`Сетевая ошибка: Получен некорректный ответ от прокси/сервера. Статус: ${result.status}. Ответ: ${snippet}...`, 'error');
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            }
        })
        .catch(error => {
            showToast(`Сетевая ошибка: ${error}`, 'error');
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        });
}

// --- Логика кастомного выпадающего списка (Custom Select) ---
function toggleCustomSelect(trigger) {
    const container = trigger.closest('.custom-select-container');
    container.classList.toggle('open');
}

function selectCustomOption(option, value) {
    const container = option.closest('.custom-select-container');
    const triggerText = container.querySelector('.custom-select-text');
    const hiddenInput = container.querySelector('input[type="hidden"]');
    
    // Снимаем активный класс со всех пунктов и добавляем на текущий
    container.querySelectorAll('.custom-select-option').forEach(opt => {
        opt.classList.remove('active');
    });
    option.classList.add('active');
    
    // Обновляем текст на кнопке и значение в скрытом input
    triggerText.innerText = option.innerText;
    hiddenInput.value = value;
    
    // Закрываем меню
    container.classList.remove('open');
    
    // Вызываем показ/скрытие полей учетных данных
    if (typeof toggleSyncFields === 'function') {
        toggleSyncFields(value, 'add');
    }
}

// Закрытие всех кастомных селектов при клике мимо них
document.addEventListener('click', function(event) {
    if (!event.target.closest('.custom-select-container')) {
        document.querySelectorAll('.custom-select-container').forEach(container => {
            container.classList.remove('open');
        });
    }
});

function selectStorageOption(option, value, storageId) {
    const container = option.closest('.custom-select-container');
    const triggerText = container.querySelector('.custom-select-text');
    const hiddenInput = container.querySelector('input[type="hidden"]');
    
    // Снимаем активный класс со всех пунктов и добавляем на текущий
    container.querySelectorAll('.custom-select-option').forEach(opt => {
        opt.classList.remove('active');
    });
    option.classList.add('active');
    
    // Обновляем текст на кнопке и значение в скрытом input
    triggerText.innerHTML = option.innerHTML;
    hiddenInput.value = value;
    
    // Закрываем меню
    container.classList.remove('open');
}

// --- Delete Confirmation Modal Logic ---
let formToSubmit = null;

function showConfirmDeleteModal(formElement, message) {
    formToSubmit = formElement;
    const modal = document.getElementById('confirm-delete-modal');
    const messageEl = document.getElementById('confirm-delete-message');
    if (modal && messageEl) {
        messageEl.textContent = message;
        openModal('confirm-delete-modal');
    }
}

function submitConfirmedDelete() {
    if (formToSubmit) {
        formToSubmit.submit();
        formToSubmit = null;
    }
    closeModal('confirm-delete-modal');
}
