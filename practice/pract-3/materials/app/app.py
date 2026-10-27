#!/usr/bin/env python3
"""Учебное веб-приложение «Магазин» с намеренными уязвимостями.

Назначение: показать, как действия пользователей и нарушителя попадают в журнал
событий безопасности, и дать материал для правил обнаружения (практическое занятие 3).

Приложение намеренно содержит слабые места:
  * нет блокировки учётной записи после серии неудачных входов (возможен подбор пароля);
  * доступ к чужому заказу не проверяется полностью — отказ происходит, но его легко перебрать
    (небезопасная прямая ссылка на объект, IDOR);
  * отключить второй фактор можно без повторной проверки пароля.

Каждое значимое действие записывается в журнал событий безопасности в формате JSON
(одна запись на строку) по схеме, рассмотренной в лекции 3. Путь к журналу задаётся
переменной окружения EVENTS_LOG (по умолчанию logs/events.jsonl).

Зависимостей, кроме стандартной библиотеки Python 3.10+, нет.
Запуск:  python3 app.py           (слушает 0.0.0.0:8080)
"""

from __future__ import annotations

import json
import mimetypes
import os
import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("APP_HOST", "0.0.0.0")
PORT = int(os.environ.get("APP_PORT", "8080"))
LOG_PATH = Path(os.environ.get("EVENTS_LOG", "logs/events.jsonl"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
SERVICE = "shop-app"
HOSTNAME = os.environ.get("HOSTNAME", "app-01")

# Учётные записи приложения: логин -> (пароль, роль, включён ли второй фактор).
USERS = {
    "anna":    {"password": "sunflower7", "role": "customer", "mfa": True,  "owns": [1001, 1002]},
    "boris":   {"password": "winter2026",  "role": "customer", "mfa": False, "owns": [1003]},
    "manager": {"password": "Mg!7xQ2p",    "role": "manager",  "mfa": True,  "owns": []},
    "admin":   {"password": "Adm1n!pass",  "role": "admin",    "mfa": True,  "owns": []},
}
INITIAL_MFA = {login: data["mfa"] for login, data in USERS.items()}

# Заказы: номер -> владелец. Используются для демонстрации доступа к чужим данным.
ORDERS = {1001: "anna", 1002: "anna", 1003: "boris", 1004: "manager", 1005: "admin"}


def now() -> str:
    """Текущее время в UTC по ISO 8601 с миллисекундами."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{datetime.now(timezone.utc).microsecond // 1000:03d}+00:00"


def log_event(event_type: str, outcome: str, *, actor: str | None, source_ip: str,
              severity: str = "low", target: dict | None = None, context: dict | None = None) -> None:
    """Записывает одно событие безопасности в журнал (JSON, одна строка)."""
    record = {
        "timestamp": now(),
        "event_type": event_type,
        "outcome": outcome,
        "actor": {"type": "user", "id": actor} if actor else {"type": "anonymous", "id": "-"},
        "source_ip": source_ip,
        "service": SERVICE,
        "host": HOSTNAME,
        "severity": severity,
        "target": target,
        "context": context or {},
        "event_id": uuid.uuid4().hex[:12],
    }
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_events() -> list[dict]:
    """Reads the current lab journal, tolerating a missing or partial last line."""
    if not LOG_PATH.exists():
        return []
    events = []
    with LOG_PATH.open(encoding="utf-8") as f:
        for line in f:
            try:
                if line.strip():
                    events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def lab_state() -> dict:
    """Returns compact telemetry for the browser without replacing Sigma analysis."""
    events = read_events()
    failed_by_actor: Counter[str] = Counter()
    actors_by_source: defaultdict[str, set[str]] = defaultdict(set)
    denied_by_actor: Counter[str] = Counter()
    mfa_without_ticket = 0

    for event in events:
        actor = str(event.get("actor", {}).get("id", "-"))
        source = str(event.get("source_ip", "-"))
        if event.get("event_type") == "auth.login" and event.get("outcome") == "failure":
            failed_by_actor[actor] += 1
            actors_by_source[source].add(actor)
        elif event.get("event_type") == "authz.access" and event.get("outcome") == "failure":
            denied_by_actor[actor] += 1
        elif event.get("event_type") == "auth.mfa.disable" and event.get("outcome") == "success":
            if not event.get("context", {}).get("ticket_id"):
                mfa_without_ticket += 1

    spray_sources = [ip for ip, actors in actors_by_source.items() if len(actors) >= 8]

    # The browser quest is intentionally ordered. An event counts toward a mission only
    # after the previous mission has been completed. This keeps the UI, methodology and
    # correlation rules aligned and prevents a later action from completing a step early.
    stage = 0
    quest_anna_failures = 0
    quest_spray: defaultdict[str, set[str]] = defaultdict(set)
    quest_denials = 0
    for event in events:
        actor = str(event.get("actor", {}).get("id", "-"))
        source = str(event.get("source_ip", "-"))
        event_type = event.get("event_type")
        outcome = event.get("outcome")

        if stage == 0:
            if event_type == "auth.login" and outcome == "failure" and actor == "anna":
                quest_anna_failures += 1
            elif (event_type == "auth.login" and outcome == "success" and actor == "anna"
                  and quest_anna_failures >= 5):
                stage = 1
            continue

        if stage == 1:
            if event_type == "auth.login" and outcome == "failure" and actor != "anna":
                quest_spray[source].add(actor)
                if len(quest_spray[source]) >= 8:
                    stage = 2
            continue

        if stage == 2:
            if event_type == "authz.access" and outcome == "failure" and actor == "anna":
                quest_denials += 1
                if quest_denials >= 5:
                    stage = 3
            continue

        if stage == 3:
            if (event_type == "auth.mfa.disable" and outcome == "success"
                    and not event.get("context", {}).get("ticket_id")):
                stage = 4

    quest_spray_count = max((len(actors) for actors in quest_spray.values()), default=0)
    return {
        "total": len(events),
        "login_failures": sum(failed_by_actor.values()),
        "access_denials": sum(denied_by_actor.values()),
        "mfa_disabled": mfa_without_ticket,
        "missions": {
            "bruteforce": stage >= 1,
            "spraying": stage >= 2,
            "idor": stage >= 3,
            "mfa": stage >= 4,
        },
        "stage": stage,
        "progress": {
            "bruteforce_failures": min(quest_anna_failures, 5),
            "spraying_accounts": min(quest_spray_count, 8),
            "idor_denials": min(quest_denials, 5),
        },
        "highlights": {
            "anna_failures": failed_by_actor.get("anna", 0),
            "spray_source": spray_sources[0] if spray_sources else None,
            "anna_denials": denied_by_actor.get("anna", 0),
        },
        "recent": events[-18:][::-1],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "ShopApp/1.0"

    # ------------------------------------------------------------------ служебное
    def _client_ip(self) -> str:
        # Учитываем доверенный заголовок, который выставляет обратный прокси.
        fwd = self.headers.get("X-Forwarded-For")
        return fwd.split(",")[0].strip() if fwd else self.client_address[0]

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        if not path.is_file():
            self._send(404, {"error": "not found"})
            return
        body = path.read_bytes()
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8" if content_type.startswith("text/") else content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {k: v[0] for k, v in parse_qs(raw).items()}

    def log_message(self, *args) -> None:  # заглушаем журнал HTTP-сервера в stderr
        return

    # ------------------------------------------------------------------ маршруты
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        ip = self._client_ip()
        if path == "/":
            self._send_file(STATIC_DIR / "index.html")
            return
        if path == "/static/app.js":
            self._send_file(STATIC_DIR / "app.js")
            return
        if path == "/static/style.css":
            self._send_file(STATIC_DIR / "style.css")
            return
        if path == "/health":
            self._send(200, {"service": SERVICE, "status": "ok",
                             "routes": ["POST /login", "GET /orders/<id>",
                                        "POST /mfa/disable", "GET /api/lab-state"]})
            return
        if path == "/api/lab-state":
            self._send(200, lab_state())
            return
        m = re.fullmatch(r"/orders/(\d+)", path)
        if m:
            self._orders(int(m.group(1)), ip)
            return
        if path == "/admin/users":
            self._admin_users(ip)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        ip = self._client_ip()
        if path == "/login":
            self._login(ip)
        elif path == "/mfa/disable":
            self._mfa_disable(ip)
        elif path == "/lab/reset":
            self._lab_reset()
        else:
            self._send(404, {"error": "not found"})

    # ------------------------------------------------------------------ логика
    def _login(self, ip: str) -> None:
        data = self._body()
        login = str(data.get("username", ""))
        password = str(data.get("password", ""))
        user = USERS.get(login)
        # УЯЗВИМОСТЬ: нет блокировки учётной записи после серии неудачных попыток.
        if user and user["password"] == password:
            log_event("auth.login", "success", actor=login, source_ip=ip, severity="low",
                      context={"method": "password", "mfa": user["mfa"]})
            self._send(200, {"result": "ok", "user": login, "role": user["role"]})
        else:
            reason = "bad_password" if user else "unknown_user"
            log_event("auth.login", "failure", actor=login or None, source_ip=ip, severity="low",
                      context={"method": "password", "reason": reason})
            self._send(401, {"result": "fail", "reason": reason})

    def _orders(self, order_id: int, ip: str) -> None:
        # Текущего пользователя определяем по заголовку X-User (упрощение для стенда).
        login = self.headers.get("X-User", "")
        user = USERS.get(login)
        if not user:
            log_event("authz.access", "failure", actor=login or None, source_ip=ip, severity="low",
                      target={"type": "order", "id": str(order_id)},
                      context={"reason": "not_authenticated", "path": f"/orders/{order_id}"})
            self._send(401, {"result": "fail", "reason": "not_authenticated"})
            return
        owner = ORDERS.get(order_id)
        # УЯЗВИМОСТЬ (IDOR): проверка владельца есть, но номера заказов легко перебираются.
        if owner == login or user["role"] in ("manager", "admin"):
            log_event("data.read", "success", actor=login, source_ip=ip, severity="low",
                      target={"type": "order", "id": str(order_id)},
                      context={"path": f"/orders/{order_id}"})
            self._send(200, {"order": order_id, "owner": owner, "items": ["книга", "кружка"]})
        else:
            log_event("authz.access", "failure", actor=login, source_ip=ip, severity="low",
                      target={"type": "order", "id": str(order_id)},
                      context={"reason": "not_owner", "path": f"/orders/{order_id}"})
            self._send(403, {"result": "fail", "reason": "not_owner"})

    def _admin_users(self, ip: str) -> None:
        login = self.headers.get("X-User", "")
        user = USERS.get(login)
        if user and user["role"] == "admin":
            log_event("authz.access", "success", actor=login, source_ip=ip, severity="medium",
                      target={"type": "admin_function", "id": "/admin/users"},
                      context={"path": "/admin/users"})
            self._send(200, {"users": list(USERS.keys())})
        else:
            log_event("authz.access", "failure", actor=login or None, source_ip=ip, severity="medium",
                      target={"type": "admin_function", "id": "/admin/users"},
                      context={"reason": "not_admin", "path": "/admin/users"})
            self._send(403, {"result": "fail", "reason": "not_admin"})

    def _mfa_disable(self, ip: str) -> None:
        data = self._body()
        login = self.headers.get("X-User", "")
        target_login = str(data.get("target", login))
        user = USERS.get(login)
        target = USERS.get(target_login)
        if not user or not target:
            self._send(401, {"result": "fail", "reason": "not_authenticated"})
            return
        # УЯЗВИМОСТЬ: отключение второго фактора без повторной проверки пароля.
        target["mfa"] = False
        ticket = data.get("ticket_id")
        log_event("auth.mfa.disable", "success", actor=login, source_ip=ip, severity="high",
                  target={"type": "user", "id": target_login},
                  context={"factor": "totp", "ticket_id": ticket} if ticket else {"factor": "totp"})
        self._send(200, {"result": "ok", "target": target_login, "mfa": False})

    def _lab_reset(self) -> None:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        LOG_PATH.write_text("", encoding="utf-8")
        for login, enabled in INITIAL_MFA.items():
            USERS[login]["mfa"] = enabled
        self._send(200, {"result": "ok", "message": "Лаборатория сброшена", "state": lab_state()})


def main() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Учебное приложение «Магазин» слушает http://{HOST}:{PORT}")
    print(f"Журнал событий: {LOG_PATH.resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено")


if __name__ == "__main__":
    main()
