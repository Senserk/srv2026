#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path("/work")
WORKSPACE = ROOT / "repository"
REPORTS = ROOT / "reports"


def fail(message: str) -> None:
    print(f"[BLOCK] {message}")
    raise SystemExit(1)


required = [
    REPORTS / "sast.txt",
    REPORTS / "dast-asan.txt",
    REPORTS / "gitleaks.json",
    REPORTS / "sbom.cdx.json",
    REPORTS / "grype.json",
    REPORTS / "trivy.json",
]
for path in required:
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"нет отчёта {path.name}")

sast = (REPORTS / "sast.txt").read_text(errors="replace")
if "error:" in sast:
    fail("SAST: исходный код не компилируется")
if "Attempt to free released memory" in sast:
    fail("SAST по-прежнему обнаруживает двойное освобождение")

dast = (REPORTS / "dast-asan.txt").read_text(errors="replace")
if "AddressSanitizer" in dast or "LeakSanitizer" in dast:
    fail("DAST: AddressSanitizer обнаружил ошибку при выполнении")

gitleaks = json.loads((REPORTS / "gitleaks.json").read_text())
if gitleaks:
    fail(f"Gitleaks обнаружил секреты: {len(gitleaks)}")

sbom = json.loads((REPORTS / "sbom.cdx.json").read_text())
components = sbom.get("components", [])
if len(components) < 5:
    fail("SBOM не содержит ожидаемого состава образа")

dockerfile = (WORKSPACE / "Dockerfile").read_text()
compose = (WORKSPACE / "compose.yaml").read_text()
for marker in ["AS build", "USER user", "--no-install-recommends"]:
    if marker not in dockerfile:
        fail(f"Dockerfile не содержит {marker}")
for marker in ["read_only: true", "cap_drop:", "no-new-privileges:true"]:
    if marker not in compose:
        fail(f"Compose-конфигурация не содержит {marker}")

tracked = subprocess.run(
    ["git", "-C", str(WORKSPACE), "log", "--all", "-S", "TRAINING_TOKEN_", "--oneline"],
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
if tracked:
    fail("секрет сохранился в истории Git")

print("[PASS] Security Gate: релиз-кандидат принят")
print(f"[INFO] компонентов в SBOM: {len(components)}")
sys.exit(0)
