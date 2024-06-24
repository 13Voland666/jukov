# Использование образа python:3.9-slim как базового
FROM python:3.9-slim

# Установка рабочей директории в контейнере
WORKDIR /app

# Копирование файла requirements.txt в рабочую директорию
COPY requirements.txt requirements.txt

# Установка зависимостей
RUN pip install --no-cache-dir -r requirements.txt

# Копирование всего содержимого текущей директории в рабочую директорию контейнера
COPY . .

# Установка переменной окружения для предотвращения буферизации вывода Python (полезно для логирования)
ENV PYTHONUNBUFFERED=1

# Команда для запуска приложения
CMD ["flask", "run", "--host=0.0.0.0"]
