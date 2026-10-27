# Release candidate 2.0

Учебное приложение на C для аудита перед выпуском. Не используйте содержащиеся
здесь значения за пределами локального стенда.

Сборка:

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build
```
