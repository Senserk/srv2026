#!/usr/bin/env python3
"""Программа проверки правил обнаружения в формате Sigma на журнале учебного приложения.

Практическое занятие 3 курса «Методы и принципы проектирования современных защищённых систем».

Поддерживаемое подмножество Sigma 2:
  * правила по событиям: наборы условий в разделе detection, поле condition
    (and, or, not, скобки, «1 of …», «all of …»), модификаторы
    contains, startswith, endswith, all, exists, re, cidr, gt, gte, lt, lte;
  * правила корреляции: event_count, value_count, temporal, temporal_ordered
    с полями rules, group-by, timespan, condition, generate.

Запуск:
  python3 detect.py --events ../app/logs/events.jsonl --rules rules

Зависимостей, кроме стандартной библиотеки Python 3.10+, нет.
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path


# =========================================================================== разбор YAML
# Встроенный разбор подмножества YAML, достаточного для правил Sigma, — чтобы программа
# работала без установки сторонних библиотек. Поддерживаются: несколько документов через
# «---», комментарии «#», вложенность по отступам, блочные и поточные (flow) словари и списки.

def _parse_scalar(text: str):
    t = text.strip()
    if t == "" or t in ("~", "null", "Null", "NULL"):
        return None
    if len(t) >= 2 and t[0] in "\"'" and t[-1] == t[0]:
        return t[1:-1]
    if t.startswith("{"):
        return _parse_flow_map(t)
    if t.startswith("["):
        return _parse_flow_seq(t)
    if t in ("true", "True", "yes"):
        return True
    if t in ("false", "False", "no"):
        return False
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d+", t):
        return float(t)
    return t


def _split_top(text: str) -> list[str]:
    """Разбивает содержимое flow-коллекции по запятым верхнего уровня."""
    parts, depth, cur, quote = [], 0, "", None
    for ch in text:
        if quote:
            cur += ch
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            cur += ch
        elif ch in "{[":
            depth += 1
            cur += ch
        elif ch in "}]":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def _parse_flow_map(text: str) -> dict:
    inner = text.strip()[1:-1]
    result = {}
    for part in _split_top(inner):
        if ":" in part:
            k, v = part.split(":", 1)
            result[k.strip()] = _parse_scalar(v)
    return result


def _parse_flow_seq(text: str) -> list:
    inner = text.strip()[1:-1]
    return [_parse_scalar(p) for p in _split_top(inner)]


def _strip_comment(line: str) -> str:
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def _parse_block(lines: list[tuple[int, str]], idx: int, indent: int):
    """Разбирает блок (словарь или список) на уровне отступа indent. Возвращает (значение, idx)."""
    if idx < len(lines) and lines[idx][1].startswith("- "):
        seq = []
        while idx < len(lines) and lines[idx][0] == indent and lines[idx][1].startswith("- "):
            seq.append(_parse_scalar(lines[idx][1][2:]))
            idx += 1
        return seq, idx
    mapping = {}
    while idx < len(lines) and lines[idx][0] == indent and not lines[idx][1].startswith("- "):
        key, _, rest = lines[idx][1].partition(":")
        key, rest = key.strip(), rest.strip()
        idx += 1
        if rest:
            mapping[key] = _parse_scalar(rest)
        elif idx < len(lines) and lines[idx][0] > indent:
            mapping[key], idx = _parse_block(lines, idx, lines[idx][0])
        else:
            mapping[key] = None
    return mapping, idx


def load_yaml_documents(text: str) -> list[dict]:
    """Разбирает текст в список документов YAML (подмножество для правил Sigma)."""
    docs, buf = [], []
    for raw in text.splitlines() + ["---"]:
        if raw.strip() == "---":
            lines = []
            for ln in buf:
                body = _strip_comment(ln).rstrip()
                if body.strip():
                    lines.append((len(body) - len(body.lstrip(" ")), body.strip()))
            if lines:
                value, _ = _parse_block(lines, 0, lines[0][0])
                if value:
                    docs.append(value)
            buf = []
        else:
            buf.append(raw)
    return docs


# =========================================================================== данные

@dataclass
class Signal:
    """Срабатывание правила: одно событие (правило по событию) или группа событий (корреляция)."""
    rule: str                     # имя или идентификатор правила
    first: datetime               # время первого события
    last: datetime                # время последнего события
    events: list[dict]            # события, на которых основано срабатывание
    group: dict = field(default_factory=dict)   # значения полей группировки


def load_events(path: str) -> list[dict]:
    """Читает журнал JSON Lines и добавляет к каждой записи разобранное время в поле _t."""
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                ev = json.loads(line)
                ev["_t"] = datetime.fromisoformat(ev["timestamp"])
                events.append(ev)
    events.sort(key=lambda e: e["_t"])
    return events


def get_field(event: dict, name: str):
    """Значение поля; вложенные поля задаются через точку: actor.id, context.rows."""
    if name in event:
        return event[name]
    value = event
    for part in name.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def parse_timespan(text: str) -> timedelta:
    m = re.fullmatch(r"(\d+)([smhd])", str(text).strip())
    if not m:
        raise ValueError(f"Некорректное значение timespan: {text!r}")
    n, unit = int(m.group(1)), m.group(2)
    return {"s": timedelta(seconds=n), "m": timedelta(minutes=n),
            "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]


# =========================================================================== правила по событиям

def _scalar_match(actual, expected, mods: list[str]) -> bool:
    if "exists" in mods:
        return (actual is not None) == bool(expected)
    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False
    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[
            next(m for m in mods if m in ("gt", "gte", "lt", "lte"))]
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    if "re" in mods:
        return re.search(str(expected), str(actual)) is not None
    if isinstance(actual, (list, dict)):
        actual = json.dumps(actual, ensure_ascii=False)
    a, e = str(actual).lower(), str(expected).lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    return a == e


def match_field(event: dict, key: str, expected) -> bool:
    name, *mods = key.split("|")
    actual = get_field(event, name)
    values = expected if isinstance(expected, list) else [expected]
    if "all" in mods:
        return all(_scalar_match(actual, v, mods) for v in values)
    return any(_scalar_match(actual, v, mods) for v in values)


def match_selection(event: dict, selection) -> bool:
    """Набор условий: словарь — условия по «И», список словарей — по «ИЛИ», список строк — ключевые слова."""
    if isinstance(selection, dict):
        return all(match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(x, dict) for x in selection):
            return any(match_selection(event, x) for x in selection)
        text = json.dumps(event, ensure_ascii=False, default=str).lower()
        return any(str(x).lower() in text for x in selection)
    raise ValueError(f"Неподдерживаемый вид набора условий: {selection!r}")


class Condition:
    """Разбор поля condition: or < and < not < «1 of / all of» < скобки."""

    TOKEN = re.compile(r"\s*(\(|\)|1 of|all of|and\b|or\b|not\b|[\w*]+)")

    def __init__(self, text: str, names: list[str]):
        self.tokens = [t for t in self.TOKEN.findall(text) if t.strip()]
        self.names = names
        self.pos = 0
        self.tree = self._expr()
        if self.pos != len(self.tokens):
            raise ValueError(f"Не удалось разобрать условие: {text!r}")

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self):
        self.pos += 1
        return self.tokens[self.pos - 1]

    def _expr(self):
        node = self._term()
        while self._peek() == "or":
            self._take()
            node = ("or", node, self._term())
        return node

    def _term(self):
        node = self._factor()
        while self._peek() == "and":
            self._take()
            node = ("and", node, self._factor())
        return node

    def _factor(self):
        tok = self._take()
        if tok == "not":
            return ("not", self._factor())
        if tok == "(":
            node = self._expr()
            if self._take() != ")":
                raise ValueError("Не закрыта скобка в условии")
            return node
        if tok in ("1 of", "all of"):
            pattern = self._take()
            if pattern == "them":
                group = [n for n in self.names if not n.startswith("_")]
            else:
                group = [n for n in self.names if fnmatch.fnmatchcase(n, pattern)]
            return ("any" if tok == "1 of" else "all", group)
        if tok not in self.names:
            raise ValueError(f"В условии упомянут неизвестный набор: {tok}")
        return ("id", tok)

    def evaluate(self, hits: dict[str, bool], node=None) -> bool:
        node = node or self.tree
        op = node[0]
        if op == "id":
            return hits[node[1]]
        if op == "not":
            return not self.evaluate(hits, node[1])
        if op == "and":
            return self.evaluate(hits, node[1]) and self.evaluate(hits, node[2])
        if op == "or":
            return self.evaluate(hits, node[1]) or self.evaluate(hits, node[2])
        if op == "any":
            return any(hits[n] for n in node[1])
        return all(hits[n] for n in node[1])


def run_detection_rule(rule: dict, events: list[dict]) -> list[Signal]:
    detection = dict(rule["detection"])
    condition = detection.pop("condition")
    conditions = condition if isinstance(condition, list) else [condition]
    names = list(detection)
    parsed = [Condition(c, names) for c in conditions]
    key = rule.get("name") or rule["id"]
    signals = []
    for ev in events:
        hits = {n: match_selection(ev, detection[n]) for n in names}
        if any(c.evaluate(hits) for c in parsed):
            signals.append(Signal(key, ev["_t"], ev["_t"], [ev]))
    return signals


# =========================================================================== корреляция

def group_key(signal: Signal, fields: list[str]) -> tuple:
    """Значения полей группировки: берутся из группы срабатывания или из его первого события."""
    return tuple(signal.group.get(f, get_field(signal.events[0], f)) for f in fields)


def condition_met(value: int, cond: dict) -> bool:
    ops = {"gt": value.__gt__, "gte": value.__ge__, "lt": value.__lt__,
           "lte": value.__le__, "eq": value.__eq__, "neq": value.__ne__}
    return all(ops[k](v) for k, v in cond.items() if k in ops)


def merge_events(*lists: list[dict]) -> list[dict]:
    seen, out = set(), []
    for lst in lists:
        for ev in lst:
            if ev["event_id"] not in seen:
                seen.add(ev["event_id"])
                out.append(ev)
    out.sort(key=lambda e: e["_t"])
    return out


def correlate_count(signals: list[Signal], corr: dict, key: str) -> list[Signal]:
    """Корреляции event_count и value_count со СКОЛЬЗЯЩИМ окном.

    Для каждой группы (значений полей group-by) хранится окно — срабатывания базового правила
    за последние timespan. При поступлении нового срабатывания окно сдвигается, вычисляется
    величина (число событий для event_count, число различных значений поля condition.field
    для value_count) и проверяется условие (gte, gt, ...).

    Пока условие выполняется, все новые события добавляются к одному и тому же сигналу
    («вспышка»), чтобы одна атака не порождала сигнал на каждое событие. Новый сигнал по той же
    группе открывается, если с конца предыдущего прошло больше timespan.
    """
    ### BEGIN SOLUTION
    span = parse_timespan(corr["timespan"])
    fields = corr.get("group-by", [])
    cond = dict(corr["condition"])
    value_field = cond.pop("field", None)
    windows: dict[tuple, deque] = defaultdict(deque)
    open_alert: dict[tuple, Signal] = {}
    result: list[Signal] = []
    for s in sorted(signals, key=lambda x: x.last):
        g = group_key(s, fields)
        win = windows[g]
        win.append(s)
        while s.last - win[0].last > span:
            win.popleft()
        if corr["type"] == "event_count":
            value = sum(len(x.events) for x in win)
        else:
            value = len({json.dumps(v, default=str) for x in win for ev in x.events
                         if (v := get_field(ev, value_field)) is not None})
        if not condition_met(value, cond):
            continue
        cur = open_alert.get(g)
        if cur is not None and s.last - cur.last <= span:
            cur.events = merge_events(cur.events, s.events)
            cur.last = s.last
        else:
            cur = Signal(key, win[0].first, s.last, merge_events(*(x.events for x in win)),
                         dict(zip(fields, g)))
            open_alert[g] = cur
            result.append(cur)
    return result
    ### END SOLUTION


def correlate_temporal(signals_by_rule: list[list[Signal]], corr: dict, key: str,
                       ordered: bool) -> list[Signal]:
    """Корреляции temporal и temporal_ordered.

    signals_by_rule[i] — срабатывания i-го правила из списка rules. Сигнал формируется, когда
    для одной группы (group-by) срабатывания всех правил укладываются в timespan, а для
    temporal_ordered — ещё и следуют в порядке, указанном в rules.
    После формирования сигнала состояние группы сбрасывается.
    """
    span = parse_timespan(corr["timespan"])
    fields = corr.get("group-by", [])
    n = len(signals_by_rule)
    stream = sorted(((s.last, i, s) for i, lst in enumerate(signals_by_rule) for s in lst),
                    key=lambda x: (x[0], x[1]))
    result: list[Signal] = []
    if ordered:
        # progress[g][k] — самая поздняя цепочка, в которой выполнены шаги 0..k
        progress: dict[tuple, list] = defaultdict(lambda: [None] * n)
        for _, i, s in stream:
            g = group_key(s, fields)
            p = progress[g]
            if i == 0:
                p[0] = (s.first, s.events)
            elif p[i - 1] is not None and s.last - p[i - 1][0] <= span:
                p[i] = (p[i - 1][0], merge_events(p[i - 1][1], s.events))
            else:
                continue
            if i == n - 1 and p[i] is not None:
                start, evs = p[i]
                result.append(Signal(key, start, s.last, evs, dict(zip(fields, g))))
                progress[g] = [None] * n
    else:
        latest: dict[tuple, list] = defaultdict(lambda: [None] * n)
        for _, i, s in stream:
            g = group_key(s, fields)
            lat = latest[g]
            lat[i] = s
            if all(x is not None for x in lat):
                first = min(x.first for x in lat)
                if s.last - first <= span:
                    result.append(Signal(key, first, s.last, merge_events(*(x.events for x in lat)),
                                         dict(zip(fields, g))))
                    latest[g] = [None] * n
    return result


# =========================================================================== загрузка и выполнение правил

def load_rules(rules_dir: str) -> dict[str, dict]:
    """Все документы YAML из каталога правил; ключ — name (если задан) и id."""
    rules: dict[str, dict] = {}
    paths = sorted(Path(rules_dir).glob("*.yml")) + sorted(Path(rules_dir).glob("*.yaml"))
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for doc in load_yaml_documents(f.read()):
                if not doc:
                    continue
                if "detection" not in doc and "correlation" not in doc:
                    raise ValueError(f"{path.name}: документ без detection и correlation")
                doc["_file"] = path.name
                for k in filter(None, (doc.get("name"), doc.get("id"))):
                    if k in rules and rules[k] is not doc:
                        raise ValueError(f"{path.name}: повторяющееся имя или id правила: {k}")
                    rules[k] = doc
    return rules


def run_rules(rules: dict[str, dict], events: list[dict]) -> list[tuple[dict, Signal]]:
    cache: dict[int, list[Signal]] = {}

    def run(rule: dict) -> list[Signal]:
        if id(rule) in cache:
            return cache[id(rule)]
        key = rule.get("name") or rule["id"]
        if "detection" in rule:
            out = run_detection_rule(rule, events)
        else:
            corr = rule["correlation"]
            refs = []
            for r in corr["rules"]:
                if r not in rules:
                    raise ValueError(f"{rule['_file']}: ссылка на неизвестное правило {r}")
                refs.append(run(rules[r]))
            if corr["type"] in ("event_count", "value_count"):
                out = correlate_count([s for lst in refs for s in lst], corr, key)
            elif corr["type"] in ("temporal", "temporal_ordered"):
                out = correlate_temporal(refs, corr, key, ordered=corr["type"] == "temporal_ordered")
            else:
                raise ValueError(f"{rule['_file']}: тип корреляции {corr['type']} не поддерживается")
        cache[id(rule)] = out
        return out

    unique = list({id(r): r for r in rules.values()}.values())
    # Правила, на которые ссылается корреляция, сами сигналов не выдают (если не задано generate: true).
    suppressed = set()
    for r in unique:
        corr = r.get("correlation")
        if corr and not corr.get("generate", False):
            suppressed.update(id(rules[x]) for x in corr["rules"] if x in rules)
    results = []
    for r in unique:
        signals = run(r)
        if id(r) not in suppressed:
            results.extend((r, s) for s in signals)
    results.sort(key=lambda x: x[1].first)
    return results


def write_alerts(results: list[tuple[dict, Signal]], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for n, (rule, s) in enumerate(results, 1):
            alert = {
                "alert_id": f"A{n:05d}",
                "rule_id": rule["id"],
                "rule_name": rule.get("name"),
                "title": rule.get("title"),
                "level": rule.get("level"),
                "first_time": s.first.isoformat(timespec="milliseconds"),
                "last_time": s.last.isoformat(timespec="milliseconds"),
                "group": s.group,
                "event_count": len(s.events),
                "event_ids": [e["event_id"] for e in s.events],
            }
            f.write(json.dumps(alert, ensure_ascii=False, default=str) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Проверка правил Sigma на журнале TraceShop")
    ap.add_argument("--events", default="../app/logs/events.jsonl")
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--out", default="alerts.jsonl")
    args = ap.parse_args()

    events = load_events(args.events)
    rules = load_rules(args.rules)
    results = run_rules(rules, events)
    write_alerts(results, args.out)

    per_rule: dict[str, int] = defaultdict(int)
    for rule, _ in results:
        per_rule[f"{rule.get('title')} ({rule['_file']})"] += 1
    print(f"Событий: {len(events)}; правил: {len({id(r) for r in rules.values()})}; сигналов: {len(results)}")
    for title, cnt in sorted(per_rule.items(), key=lambda x: -x[1]):
        print(f"  {cnt:6d}  {title}")
    print(f"Сигналы записаны в {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
