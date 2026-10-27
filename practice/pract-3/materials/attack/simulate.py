#!/usr/bin/env python3
"""Сценарий активности для учебного приложения «Магазин».

Скрипт обращается к приложению по HTTP и воспроизводит:
  * легитимную активность — обычные входы, просмотр своих заказов, один «забытый пароль»;
  * действия нарушителя — подбор пароля, распыление паролей, перебор чужих заказов,
    отключение второго фактора.

Все обращения приложение само записывает в журнал событий (app/logs/events.jsonl),
к которому затем применяются правила обнаружения.

Запуск (приложение должно быть запущено):
  python3 simulate.py                 # адрес по умолчанию http://localhost:8080
  python3 simulate.py --url http://localhost:8080

Зависимостей, кроме стандартной библиотеки Python 3.10+, нет.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request

# Адреса, с которых якобы приходят запросы (передаются приложению заголовком X-Forwarded-For).
IP_OFFICE = "10.0.0.15"        # легитимные пользователи из офиса
IP_ATTACKER = "203.0.113.77"   # нарушитель
IP_SPRAY = "198.51.100.23"     # распыление паролей

# Известные нарушителю (из утечки) учётные записи для распыления.
# Не пересекаются с anna и boris, чтобы распыление не смешивалось с подбором и «забытым паролем».
MANY_LOGINS = ["clara", "dmitry", "elena", "frank", "galina", "igor",
               "julia", "kirill", "larisa", "maxim", "nina", "oleg"]


class Client:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        # Обходим системный прокси: обращения идут напрямую к приложению.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def req(self, method: str, path: str, ip: str, body: dict | None = None,
            user: str | None = None) -> int:
        headers = {"X-Forwarded-For": ip, "Content-Type": "application/json"}
        if user:
            headers["X-User"] = user
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            return self.opener.open(r, timeout=5).status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception as e:  # noqa: BLE001
            print(f"  ошибка связи с приложением: {e}")
            raise SystemExit(1)

    def login(self, user: str, password: str, ip: str) -> int:
        return self.req("POST", "/login", ip, {"username": user, "password": password})


def legitimate(c: Client) -> None:
    print("1. Легитимная активность")
    c.login("anna", "sunflower7", IP_OFFICE)
    c.req("GET", "/orders/1001", IP_OFFICE, user="anna")
    c.req("GET", "/orders/1002", IP_OFFICE, user="anna")
    c.login("manager", "Mg!7xQ2p", IP_OFFICE)
    c.req("GET", "/orders/1004", IP_OFFICE, user="manager")
    # «Забытый пароль»: три неудачи, затем успех — легитимный источник ложного срабатывания.
    c.login("boris", "winter2025", IP_OFFICE)
    c.login("boris", "winter20262", IP_OFFICE)
    c.login("boris", "Winter2026", IP_OFFICE)
    c.login("boris", "winter2026", IP_OFFICE)
    print("   готово")


def brute_force(c: Client) -> None:
    print("2. Подбор пароля к учётной записи anna (адрес нарушителя)")
    for pwd in ["123456", "qwerty", "password", "anna2026", "sunshine",
                "letmein", "iloveyou", "sunflower7"]:   # последний — верный
        c.login("anna", pwd, IP_ATTACKER)
    print("   7 неудач и 1 успех")


def password_spraying(c: Client) -> None:
    print("3. Распыление пароля 123456 по многим учётным записям (один адрес)")
    for login in MANY_LOGINS:
        c.login(login, "123456", IP_SPRAY)
    print(f"   {len(MANY_LOGINS)} неудачных входов с одного адреса")


def idor(c: Client) -> None:
    print("4. Перебор чужих заказов под учётной записью anna")
    for oid in range(1001, 1010):
        c.req("GET", f"/orders/{oid}", IP_ATTACKER, user="anna")
    print("   перебор заказов 1001–1009")


def mfa_disable(c: Client) -> None:
    print("5. Отключение второго фактора у учётной записи anna")
    c.req("POST", "/mfa/disable", IP_ATTACKER, {"target": "anna"}, user="anna")
    print("   второй фактор отключён без заявки")


def main() -> None:
    ap = argparse.ArgumentParser(description="Сценарий активности для учебного приложения")
    ap.add_argument("--url", default="http://localhost:8080")
    args = ap.parse_args()

    c = Client(args.url)
    # Проверяем, что приложение отвечает.
    try:
        c.req("GET", "/health", IP_OFFICE)
    except SystemExit:
        print(f"Приложение по адресу {args.url} недоступно. Запущен ли контейнер?")
        raise

    print(f"Приложение: {args.url}\n")
    legitimate(c)
    brute_force(c)
    password_spraying(c)
    idor(c)
    mfa_disable(c)
    print("\nГотово. События записаны в журнал приложения (app/logs/events.jsonl).")


if __name__ == "__main__":
    main()
