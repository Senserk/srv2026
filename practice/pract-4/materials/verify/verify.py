#!/usr/bin/env python3
"""Проверка результатов практического занятия 4 без внешних зависимостей."""

from __future__ import annotations

import csv
import sys
from datetime import datetime
from pathlib import Path

REQUIRED = {
    "quality-summary.csv", "quarantine.csv", "objects.csv", "train.csv",
    "validation.csv", "test.csv", "feature-audit.csv", "metrics.csv", "dataset-card.md",
}
OBJECT_COLUMNS = {
    "object_id", "window_start", "source_id", "attempt_count", "failure_count",
    "success_count", "failure_rate", "unique_accounts", "night_activity",
    "label", "is_attack", "scenario_id", "split",
}


def fail(message: str) -> None:
    print(f"✗ {message}")
    raise SystemExit(1)


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def day(value: str) -> int:
    return (datetime.fromisoformat(value) - datetime.fromisoformat("2026-07-01T00:00:00+00:00")).days + 1


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "output"
    missing = sorted(name for name in REQUIRED if not (output / name).is_file())
    if missing:
        fail("не хватает файлов: " + ", ".join(missing))

    quality = {row["check"]: int(float(row["value"])) for row in rows(output / "quality-summary.csv")}
    expected_quality = {"records": 7991, "missing_source": 6, "invalid_outcome": 4,
                        "duplicates": 8, "noncanonical_type": 13, "non_utc": 24, "gap_hours": 3}
    if quality != expected_quality:
        fail("профиль качества не совпадает с исходным журналом")
    if len(rows(output / "quarantine.csv")) != 10:
        fail("в карантине должно быть 10 записей")

    objects = rows(output / "objects.csv")
    if not objects or set(objects[0]) != OBJECT_COLUMNS:
        fail("неверная схема objects.csv")
    if any("@" in value for row in objects for value in row.values()):
        fail("обнаружены непсевдонимизированные идентификаторы")

    audit = {row["feature"]: row["decision"].strip().lower() for row in rows(output / "feature-audit.csv")}
    for feature in ("future_success_10m", "incident_confirmed", "scenario_id"):
        if audit.get(feature) != "исключить":
            fail(f"признак {feature} не исключён как источник утечки")
    for feature in ("attempt_count", "failure_rate", "unique_accounts", "night_activity"):
        if audit.get(feature) != "оставить":
            fail(f"допустимый признак {feature} отсутствует в итоговом наборе")

    bounds = {"train.csv": (1, 34, "train"), "validation.csv": (36, 45, "validation"),
              "test.csv": (47, 56, "test")}
    scenarios: dict[str, set[str]] = {}
    for name, (start, end, split) in bounds.items():
        sample = rows(output / name)
        if not sample or set(sample[0]) != OBJECT_COLUMNS:
            fail(f"неверная схема {name}")
        if any(row["split"] != split or not start <= day(row["window_start"]) <= end for row in sample):
            fail(f"нарушены временные границы {name}")
        scenarios[name] = {row["scenario_id"] for row in sample if row["scenario_id"]}
        if not scenarios[name]:
            fail(f"в {name} отсутствуют атакующие объекты")
    names = list(scenarios)
    if any(scenarios[names[i]] & scenarios[names[j]] for i in range(len(names)) for j in range(i + 1, len(names))):
        fail("один сценарий атаки оказался в нескольких выборках")

    metrics = rows(output / "metrics.csv")
    if len(metrics) != 2 or {row["experiment"] for row in metrics} != {
        "случайное разбиение + утечка", "временное разбиение без утечки"
    }:
        fail("metrics.csv должен содержать два контрольных эксперимента")
    wrong = next(row for row in metrics if row["experiment"].startswith("случайное"))
    correct = next(row for row in metrics if row["experiment"].startswith("временное"))
    if float(wrong["f1"]) < float(correct["f1"]):
        fail("результаты не демонстрируют влияние утечки на оценку")

    print("✓ профиль качества рассчитан")
    print("✓ дефектные записи изолированы, идентификаторы псевдонимизированы")
    print("✓ признаки с утечкой исключены")
    print("✓ временные выборки и зазоры сформированы корректно")
    print("✓ два эксперимента сохранены и сопоставимы")
    print("Результат принят.")


if __name__ == "__main__":
    main()
