# Учебное веб-приложение «Магазин». Зависимостей, кроме Python, нет,
# поэтому образ собирается без обращения к индексу пакетов.
FROM python:3.12-slim

WORKDIR /app
COPY app.py /app/app.py
COPY static /app/static

# Журнал событий пишется в /app/logs — этот каталог монтируется наружу
# через docker-compose, чтобы правила можно было применять на хосте.
ENV EVENTS_LOG=/app/logs/events.jsonl
ENV APP_PORT=8080
EXPOSE 8080

CMD ["python3", "app.py"]
