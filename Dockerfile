FROM python:3.10-slim

# Настройка переменных окружения Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Установка необходимых системных пакетов для компиляции криптографии
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    ssl-cert \
    && rm -rf /var/lib/apt/lists/*

# Копирование и установка зависимостей Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Копирование всех файлов проекта
COPY . .

# Создание директории для базы данных SQLite
RUN mkdir -p instance

EXPOSE 5002

# Запуск приложения в продакшн-режиме через gunicorn
CMD ["gunicorn", "--workers", "3", "--bind", "0.0.0.0:5002", "app:app"]
