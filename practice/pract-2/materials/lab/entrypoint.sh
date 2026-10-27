#!/usr/bin/env bash
set -euo pipefail

if [[ ! -d /work/repository/.git ]]; then
  practice-reset --quiet
fi

exec "$@"
