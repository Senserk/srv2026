# Учебный стенд Security Gate

Требования: Docker с Compose plugin, Bash, около 4 ГБ свободного места.

Соберите единый образ на Ubuntu и войдите в него:

```bash
./lab.sh start
./lab.sh shell
```

Внутри контейнера уже доступны `/work/repository`, `/work/reports`,
`/work/playbook.sh` и `/work/report.md`. Студенты заполняют playbook командой
`nano /work/playbook.sh`. Состояние хранится в именованном Docker volume.
Сброс с хоста: `./lab.sh reset`.

Версии учебных инструментов зафиксированы в `lab/Dockerfile`:

- Gitleaks 8.24.2;
- Syft 1.18.1;
- Grype 0.84.0;
- Trivy 0.58.1;
- Clang 18 и остальные системные средства из Ubuntu 24.04.

Количество обнаруженных CVE зависит от состояния базы Grype. Контрольные
результаты, не зависящие от обновления базы: один double free, два секрета,
два HIGH finding в исходном Dockerfile и финальный `[PASS]`.

Все действия занятия после входа выполняются непосредственно в одном
контейнере. Docker socket подключён только для сборки и анализа учебного
release-образа; такой доступ допустим для локального стенда, но не должен
выдаваться обычному production-контейнеру.

## Разметка результатов SAST через OpenRouter

Скрипт `sarif-triage` (в образе, исходник `tools/sarif_triage.py`) отправляет
каждую находку из `sast.sarif` с трассой и фрагментом кода языковой модели через
OpenRouter и записывает вердикт обратно в SARIF: `properties.llmTriage`
(`true_positive`, `false_positive` или `needs_review`, уверенность, объяснение,
исправление). Для `false_positive` добавляется `suppressions[]` со статусом
`underReview`. Исходные поля отчёта не меняются.

Ключ передаётся только переменной окружения, в файлы и образ он не попадает:

```bash
sarif-triage --dry-run /work/reports/sast.sarif --source-root /work/repository
export OPENROUTER_API_KEY=...            # ваш ключ
sarif-triage /work/reports/sast.sarif --source-root /work/repository
# результат: /work/reports/sast.triaged.sarif
```

Параметры: `--model` (по умолчанию `anthropic/claude-3.5-haiku`, также
`OPENROUTER_MODEL`), `-o` (выходной файл), `--timeout`. Режим `--dry-run` не
требует ключа и сети: он печатает запросы, которые будут отправлены.
