# 🤖 Автоматическая сборка через GitHub Actions

## Что это?

GitHub Actions автоматически собирает приложение для **Windows, macOS и Linux** при каждом push или создании тега.

**Не нужен Mac!** GitHub предоставляет виртуальные машины со всеми ОС.

---

## 🚀 Как использовать

### Вариант 1: Автоматическая сборка при push

```bash
# Просто делаешь push
git add .
git commit -m "Update application"
git push origin dev
```

**GitHub Actions автоматически:**
1. Соберет для Windows, Mac, Linux
2. Сохранит артефакты на 30 дней

**Где скачать:**
- GitHub → Repository → Actions → Build Desktop Apps
- Выбери последний workflow run
- Скачай артефакты:
  - `windows-build` - Windows файлы
  - `macos-build` - macOS файлы  
  - `linux-build` - Linux файлы

---

### Вариант 2: Создать Release (рекомендуется)

```bash
# Создать тег версии
git tag v1.0.0
git push origin v1.0.0
```

**GitHub Actions автоматически:**
1. Соберет для всех платформ
2. Создаст **Draft Release** с прикрепленными файлами
3. Сгенерирует Release Notes

**Где найти:**
- GitHub → Repository → Releases
- Edit draft release
- Publish release

**Файлы в Release:**
```
✅ SentryVault Setup 1.0.0.exe (Windows Installer)
✅ SentryVault 1.0.0.exe (Windows Portable)
✅ SentryVault-1.0.0.dmg (macOS)
✅ SentryVault-1.0.0-mac.zip (macOS Archive)
✅ SentryVault-1.0.0.AppImage (Linux)
✅ sentryvault_1.0.0_amd64.deb (Linux Debian)
✅ SentryVault-1.0.0.tar.gz (Linux Archive)
```

---

## ⏱️ Время сборки

| Платформа | Время | Runner |
|-----------|-------|--------|
| Windows | ~5 мин | windows-latest |
| macOS | ~7 мин | macos-latest |
| Linux | ~4 мин | ubuntu-latest |
| **Всего** | **~7 мин** | (параллельно) |

---

## 🔧 Настройка (уже сделано)

Файл `.github/workflows/build-desktop.yml` уже настроен.

### Триггеры (когда запускается):

```yaml
on:
  push:
    branches: [ main, dev ]        # При push в main/dev
  tags:
    - 'v*'                         # При создании тега v1.0.0
  pull_request:
    branches: [ main ]             # При PR в main
  workflow_dispatch:               # Ручной запуск
```

### Jobs:

1. **build-windows** - Собирает `.exe` файлы
2. **build-macos** - Собирает `.dmg` и `.zip`
3. **build-linux** - Собирает `.AppImage` и `.deb`
4. **create-release** - Создает Release (только для тегов)

---

## 📊 Мониторинг

### Просмотр прогресса:

1. GitHub → Repository → Actions
2. Выбери workflow run
3. Смотри логи каждого job

### Статусы:

- 🟡 **Queued** - В очереди
- 🔵 **In progress** - Собирается
- ✅ **Success** - Успешно
- ❌ **Failed** - Ошибка

---

## 🐛 Решение проблем

### Ошибка: "npm ci failed"

**Причина:** Нет `package-lock.json` или устаревшие зависимости

**Решение:**
```bash
cd cliente2
npm install
git add package-lock.json
git commit -m "Update dependencies"
git push
```

### Ошибка: "Build failed"

**Причина:** Ошибка компиляции Angular или Electron

**Решение:**
```bash
# Проверь локально
cd cliente2
npm run build:prod
npm run build:win
```

### Workflow не запускается

**Причина:** Workflow файл в неправильном месте

**Проверь:**
- Файл должен быть в `.github/workflows/build-desktop.yml`
- Расширение должно быть `.yml` или `.yaml`

---

## 💰 Лимиты GitHub Actions

### Free tier (public репозиторий):
- ✅ **Unlimited** минуты для public репозиториев
- ✅ 2000 минут/месяц для private репозиториев
- ✅ 500 MB хранилище артефактов

### Ваш случай (public):
- **Полностью бесплатно!**
- Неограниченные сборки
- Артефакты хранятся 30 дней

---

## 🎯 Рекомендации

### Для разработки:
```bash
# Локально тестируй Windows
npm run build:win

# Проверяй Mac/Linux через Actions
git push origin dev
```

### Для релиза:
```bash
# 1. Обнови версию
# в cliente2/package.json: "version": "1.0.1"

# 2. Коммит
git add .
git commit -m "Release v1.0.1"

# 3. Создай тег
git tag v1.0.1
git push origin v1.0.1

# 4. GitHub Actions создаст Draft Release
# 5. Отредактируй и опубликуй
```

### Для тестирования:
```bash
# Ручной запуск workflow
GitHub → Actions → Build Desktop Apps → Run workflow
```

---

## 📝 Пример workflow

```
Push v1.0.0 tag
  ↓
GitHub Actions starts
  ├─ 🪟 Windows Job (5 мин)
  │   ├─ npm ci
  │   ├─ npm run build:prod
  │   └─ npm run build:win
  │       → Setup.exe, Portable.exe
  │
  ├─ 🍎 macOS Job (7 мин)
  │   ├─ npm ci
  │   ├─ npm run build:prod
  │   └─ npm run build:mac
  │       → .dmg, .zip
  │
  └─ 🐧 Linux Job (4 мин)
      ├─ npm ci
      ├─ npm run build:prod
      └─ npm run build:linux
          → .AppImage, .deb, .tar.gz
  ↓
Create Draft Release
  ├─ Attach all artifacts
  └─ Generate release notes
  ↓
✅ Ready to publish!
```

---

## ✅ Преимущества

| Локальная сборка | GitHub Actions |
|------------------|----------------|
| ❌ Нужен Mac для macOS | ✅ Mac виртуалка бесплатно |
| ❌ Нужен Linux для Linux | ✅ Linux виртуалка бесплатно |
| ⏱️ 2-3 минуты локально | ⏱️ 7 минут все платформы |
| 💾 Занимает место | 💾 Хранится в cloud |
| 🔧 Ручная работа | 🤖 Автоматизация |

---

## 🚀 Быстрые команды

```bash
# Автоматическая сборка при push
git push origin dev

# Создать Release
git tag v1.0.0
git push origin v1.0.0

# Ручной запуск (через UI)
GitHub → Actions → Run workflow
```

---

**Вывод:** GitHub Actions - идеальное решение для сборки на всех платформах без необходимости иметь Mac или Linux! 🎉
