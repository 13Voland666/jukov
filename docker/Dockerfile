# Используем официальный образ Python
FROM python:3.9-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файл requirements.txt и устанавливаем зависимости
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Копируем все содержимое в рабочую директорию
COPY . .

# Устанавливаем переменные окружения
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Открываем порт для доступа
EXPOSE 5000

# Команда для запуска приложения
CMD ["flask", "run"]
