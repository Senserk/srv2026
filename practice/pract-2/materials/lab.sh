#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

case "${1:-}" in
  start)
    docker compose up -d --build
    echo "Стенд готов. Вход: ./lab.sh shell"
    ;;
  shell)
    docker compose exec lab bash
    ;;
  reset)
    docker compose exec lab practice-reset
    ;;
  status)
    docker compose ps
    docker compose exec lab bash -lc \
      'clang --version | head -1; gitleaks version; syft version; grype version; trivy --version | head -1'
    ;;
  stop)
    docker compose down
    ;;
  *)
    echo "Использование: ./lab.sh {start|shell|reset|status|stop}"
    exit 2
    ;;
esac
