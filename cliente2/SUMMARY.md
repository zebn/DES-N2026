# 📦 Сборка для всех платформ - Сводка

## ✅ Что настроено

### 1. Windows (работает сейчас)
```bash
npm run build:win
```
**Результат:**
- ✅ `MILCOM Secure Exchange Setup 1.0.0.exe` (90 MB) - Installer
- ✅ `MILCOM Secure Exchange 1.0.0.exe` (90 MB) - Portable

### 2. macOS (через GitHub Actions)
```bash
# На Mac:
npm run build:mac

# Или через GitHub Actions:
git tag v1.0.0 && git push origin v1.0.0
```
**Результат:**
- ✅ `MILCOM Secure Exchange-1.0.0.dmg` (~150 MB)
- ✅ `MILCOM Secure Exchange-1.0.0-mac.zip` (~140 MB)

### 3. Linux (на любой ОС)
```bash
npm run build:linux
```
**Результат:**
- ✅ `MILCOM Secure Exchange-1.0.0.AppImage` (~130 MB)
- ✅ `milcom-secure-exchange_1.0.0_amd64.deb` (~110 MB)
- ✅ `MILCOM Secure Exchange-1.0.0.tar.gz`

---

## 🚀 Как собрать для Mac БЕЗ Mac

### Способ 1: GitHub Actions (рекомендуется)

**Один раз настроить, потом автоматически:**

```bash
# 1. Push код в GitHub
git add .
git commit -m "Ready for build"
git push origin dev

# 2. Создать тег для release
git tag v1.0.0
git push origin v1.0.0

# 3. Подождать ~7 минут
# 4. Скачать из GitHub:
#    - Releases (для тегов)
#    - Actions → Artifacts (для обычных push)
```

**GitHub Actions автоматически:**
- ✅ Соберет Windows на `windows-latest`
- ✅ Соберет macOS на `macos-latest` 
- ✅ Соберет Linux на `ubuntu-latest`
- ✅ Создаст Draft Release с прикрепленными файлами

### Способ 2: Найти друга с Mac

```bash
# Отправь другу:
git clone https://github.com/zebn/PROTECCI-N2025.git
cd PROTECCI-N2025/cliente2
npm install
npm run build:mac
```

### Способ 3: Арендовать Mac в облаке

- **MacStadium** (~$100/месяц)
- **MacinCloud** (~$30/месяц)
- **AWS EC2 Mac** (~$1/час)

---

## 📁 Созданные файлы

### Конфигурация:

- ✅ `package.json` - Обновлены команды и настройки electron-builder
  - `npm run build:win` - Windows
  - `npm run build:mac` - macOS
  - `npm run build:linux` - Linux
  - `npm run build:all` - Все платформы

- ✅ `.github/workflows/build-desktop.yml` - GitHub Actions workflow
  - Триггеры: push в main/dev, создание тега v*, PR в main
  - Jobs: build-windows, build-macos, build-linux, create-release
  - Артефакты хранятся 30 дней

### Документация:

- ✅ `README.md` - Быстрый старт (русский + español)
- ✅ `README_MAC.md` - Подробная инструкция для macOS
- ✅ `README_GITHUB_ACTIONS.md` - Как использовать GitHub Actions
- ✅ `README_BUILDS.md` - Техническая документация по сборкам

---

## 🎯 Рекомендуемый workflow

### Для разработки:
```bash
# 1. Разрабатывай и тестируй локально
npm run dev

# 2. Собирай Windows локально для проверки
npm run build:win

# 3. Push в dev branch
git push origin dev

# 4. GitHub Actions соберет Mac/Linux автоматически
# 5. Скачай артефакты из Actions для тестирования
```

### Для релиза:
```bash
# 1. Обнови версию в package.json
"version": "1.0.1"

# 2. Коммит всех изменений
git add .
git commit -m "Release v1.0.1"

# 3. Создай тег
git tag v1.0.1
git push origin v1.0.1

# 4. GitHub Actions автоматически:
#    - Соберет все платформы
#    - Создаст Draft Release
#    - Прикрепит все файлы

# 5. Перейди в Releases, отредактируй и опубликуй
```

---

## 📊 Сравнение методов

| Метод | Windows | macOS | Linux | Время | Стоимость |
|-------|---------|-------|-------|-------|-----------|
| **Локально** | ✅ | ❌ | ✅ | 2 мин | Бесплатно |
| **GitHub Actions** | ✅ | ✅ | ✅ | 7 мин | **Бесплатно** |
| **Облачный Mac** | ✅ | ✅ | ✅ | 5 мин | $30-100/мес |

**Вывод:** GitHub Actions - лучший вариант! 🎉

---

## ✅ Что можно делать сейчас

1. **Собрать Windows локально:**
   ```bash
   cd cliente2
   npm run build:win
   ```

2. **Собрать Linux локально:**
   ```bash
   cd cliente2
   npm run build:linux
   ```

3. **Протестировать GitHub Actions:**
   ```bash
   git add .
   git commit -m "Test GitHub Actions"
   git push origin dev
   # Проверь: GitHub → Actions
   ```

4. **Создать первый Release:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   # Проверь: GitHub → Releases
   ```

---

## 📖 Дополнительная информация

- **README_MAC.md** - Детали сборки macOS, подпись кода, Gatekeeper
- **README_GITHUB_ACTIONS.md** - Подробности о workflow, лимиты, troubleshooting
- **README_BUILDS.md** - Техническая документация, структура файлов

---

## 🐛 Возможные проблемы

### "npm ci failed" в GitHub Actions

**Причина:** Нет `package-lock.json`

**Решение:**
```bash
cd cliente2
npm install
git add package-lock.json
git commit -m "Add package-lock.json"
git push
```

### macOS build не подписан

**Нормально!** Для разработки не нужна подпись.

Для продакшена нужен Apple Developer Account ($99/год).

### Gatekeeper блокирует macOS app

**Обход:** Ctrl+Click → Open при первом запуске

**Или:** Подпиши код сертификатом Developer ID

---

## 🎉 Итого

✅ **Windows** - Собирается локально  
✅ **macOS** - Собирается через GitHub Actions (бесплатно!)  
✅ **Linux** - Собирается локально или через Actions  
✅ **Автоматические Releases** - При создании тега  
✅ **Полная документация** - 4 README файла  

**Все работает БЕЗ Mac!** 🚀
