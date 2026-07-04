# 🖥️ SRV-Control Infrastructure & Quota Billing

[![Stack](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Flask-3.0%2B-lightgrey.svg?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/SQLite-3-blue.svg?style=for-the-badge&logo=sqlite)](https://www.sqlite.org/)

Легковесная веб-панель управления и финансового учета ИТ-инфраструктуры. Предназначена для мониторинга кластеров Proxmox VE (потребление CPU, RAM, дисков), учета квот бэкап-хранилищ (парсинг `repquota` по SSH) и автоматического биллинга ресурсов клиентов с гибкой тарификацией и ручными ценниками.

---

## ⚡ Основные возможности

* **Мониторинг вычислений (Proxmox VE):** Синхронизация с кластерами PVE через API, расчет утилизации CPU, RAM, SSD/HDD по нодам, LXC-контейнерам и виртуальным машинам.
* **Учет дисковых квот (Бэкап-серверы):** Подключение к бэкап-серверам по SSH с парсингом команды `repquota` для пользователей/групп и мониторинг занятого места.
* **Биллинг и ценообразование:** Автоматический расчет стоимости по тарифам (за ядро, ГБ RAM, ГБ диска, ГБ бэкапа) с поддержкой ручной фиксации цен (overrides) и прогнозирования месячной выручки.
* **Ролевая модель:** Роли Администратора (`admin`), Финансиста (`financier` — только просмотр ресурсов и ценников) и Пользователя (`user`).
* **Группировка ресурсов:** Объединение ВМ и квот под клиентов по текстовым комментариям и расчет долей физических ресурсов хостов.
* **Безопасность:** Двухфакторное шифрование паролей/токенов доступа (Fernet).

---

## 📂 Структура проекта

```text
/opt/srv-control/
├── app.py                  # Главный исполняемый файл приложения Flask
├── models.py               # Описание схемы БД и методов шифрования
├── sync_engine.py          # Модуль фоновой синхронизации с PVE и SSH квотами
├── docker-compose.yml      # Файл Docker Compose для запуска
├── .env.example            # Шаблон переменных окружения
├── requirements.txt        # Список зависимостей Python
├── static/                 # Статические файлы стилей (темная/светлая темы)
└── templates/              # HTML-шаблоны панели управления
```

---

## ⚙️ Конфигурация окружения (`.env`)

Создайте файл `.env` на основе примера `.env.example`:

| Переменная | Описание | Значение по умолчанию |
| :--- | :--- | :---: |
| `SECRET_KEY` | Секретный ключ подписи Flask сессий | `srv_control_secure_token...` |
| `FERNET_KEY` | Ключ шифрования PVE/SSH паролей в БД (`Fernet.generate_key()`) | *Генерируется на базе SECRET_KEY* |
| `DATABASE_URI` | Подключение к БД | `sqlite:///srv_control.db` |
| `BIND_HOST` | Хост для запуска веб-сервера | `0.0.0.0` |
| `BIND_PORT` | Порт для запуска веб-сервера | `5002` |
| `FLASK_DEBUG` | Режим разработки (1) или продакшна (0) | `0` |

---

## 🚀 Варианты развертывания

### Вариант 1. Запуск через Docker Compose (Рекомендуемый)

1. **Клонирование проекта:**
   ```bash
   git clone https://github.com/Ttolyanich/srv-control.git /opt/srv-control
   cd /opt/srv-control
   ```
2. **Создание и заполнение `.env`:**
   ```bash
   cp .env.example .env
   nano .env
   ```
3. **Запуск контейнера:**
   ```bash
   docker compose up -d
   ```
   Панель будет доступна на порту `5002` (логин по умолчанию `admin` / пароль `admin123`).

### Вариант 2. Нативный запуск (через Virtualenv)

1. Установите зависимости и подготовьте окружение:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Запустите Flask-сервер:
   ```bash
   python3 app.py
   ```
