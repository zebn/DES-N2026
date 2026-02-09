# 🍎 Сборка для macOS

## ⚠️ Важно

**Собрать .dmg для Mac можно только на компьютере Mac!**

Windows не может создавать macOS приложения из-за ограничений Apple.

---

## 🚀 Два способа сборки

### 1️⃣ Автоматическая сборка (рекомендуется)

**GitHub Actions** автоматически собирает для всех платформ при каждом push.

#### Как использовать:

1. **Push код в GitHub:**
   ```bash
   git add .
   git commit -m "Update app"
   git push origin dev
   ```

2. **Перейти в GitHub:**
   - Репозиторий → Actions → Build Desktop Apps
   - Дождаться завершения (~10 минут)

3. **Скачать артефакты:**
   - Windows: `windows-build`
   - macOS: `macos-build`
   - Linux: `linux-build`

#### Создать Release:

```bash
# Создать тег версии
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions автоматически:
- Соберет для Windows, Mac, Linux
- Создаст Draft Release
- Прикрепит все файлы

---

### 2️⃣ Ручная сборка на Mac

Если у тебя есть доступ к Mac:

```bash
# 1. Клонировать репозиторий
git clone https://github.com/zebn/PROTECCI-N2025.git
cd PROTECCI-N2025/cliente2

# 2. Установить зависимости
npm install

# 3. Собрать для macOS
npm run build:mac
```

**Результат:**
- `release/MILCOM Secure Exchange-1.0.0.dmg` (~150 MB)
- `release/MILCOM Secure Exchange-1.0.0-mac.zip` (~140 MB)

---

## 📦 Что будет в macOS build

| Файл | Размер | Описание |
|------|--------|----------|
| `MILCOM Secure Exchange.dmg` | ~150 MB | Установщик с drag-and-drop |
| `MILCOM Secure Exchange-mac.zip` | ~140 MB | Архив приложения |

### Установка на Mac:

1. Открыть `.dmg` файл
2. Перетащить `MILCOM Secure Exchange.app` в `/Applications`
3. Первый запуск: Ctrl+Click → Open (обход Gatekeeper)

---

## 🔐 Подпись кода (для распространения)

Для официальной публикации в App Store или без предупреждений Gatekeeper:

### Требуется:

1. **Apple Developer Account** ($99/год)
2. **Developer ID Application Certificate**

### Настройка:

```bash
# 1. Получить сертификат от Apple
# 2. Добавить в Keychain Access

# 3. Собрать с подписью
export CSC_LINK=/path/to/certificate.p12
export CSC_KEY_PASSWORD=your_password
npm run build:mac
```

### Для GitHub Actions:

```yaml
# Добавить secrets в GitHub:
# Settings → Secrets → Actions

CSC_LINK: <base64 encoded .p12>
CSC_KEY_PASSWORD: <password>
```

Затем обновить `.github/workflows/build-desktop.yml`:

```yaml
- name: Build Electron macOS
  working-directory: ./cliente2
  run: npm run build:mac
  env:
    CSC_LINK: ${{ secrets.CSC_LINK }}
    CSC_KEY_PASSWORD: ${{ secrets.CSC_KEY_PASSWORD }}
```

---

## 🐧 Сборка для Linux (на любой ОС)

Linux можно собрать даже на Windows/Mac:

```bash
npm run build:linux
```

**Результат:**
- `MILCOM Secure Exchange-1.0.0.AppImage` - Universal (работает везде)
- `milcom-secure-exchange_1.0.0_amd64.deb` - Для Ubuntu/Debian
- `MILCOM Secure Exchange-1.0.0.tar.gz` - Архив

---

## 🎯 Текущие возможности

### ✅ Работает сейчас:

| Платформа | Где собирать | Команда |
|-----------|--------------|---------|
| Windows | Windows | `npm run build:win` |
| Linux | Любая ОС | `npm run build:linux` |
| **macOS** | **Только Mac** | `npm run build:mac` |
| Все | GitHub Actions | `git push` |

### 📊 GitHub Actions (автоматически):

```
Push → GitHub Actions
  ├─ Windows Runner → .exe файлы
  ├─ macOS Runner → .dmg + .zip
  └─ Linux Runner → .AppImage + .deb
```

**Преимущества:**
- ✅ Не нужен Mac для сборки
- ✅ Все платформы одновременно
- ✅ Чистое окружение
- ✅ Автоматический Release

---

## 🔧 Конфигурация electron-builder

Файл `package.json`:

```json
{
  "build": {
    "mac": {
      "target": ["dmg", "zip"],
      "icon": "src/favicon.ico",
      "category": "public.app-category.productivity",
      "hardenedRuntime": true,
      "gatekeeperAssess": false
    }
  }
}
```

**Опции:**
- `dmg` - Красивый установщик с перетаскиванием
- `zip` - Простой архив приложения
- `hardenedRuntime` - Защита для macOS 10.14+
- `gatekeeperAssess: false` - Не требовать подписи (для разработки)

---

## 📝 Инструкции для команды

### Если есть Mac:

```bash
# Клонировать и собрать
git clone <repo>
cd PROTECCI-N2025/cliente2
npm install
npm run build:mac
```

### Если нет Mac:

**Используй GitHub Actions:**

```bash
# Просто push код
git add .
git commit -m "Build for Mac"
git push origin dev

# Через 10 минут скачай из Actions → Artifacts
```

---

## 🚀 Быстрые команды

```bash
# Windows (на Windows)
npm run build:win

# macOS (только на Mac)
npm run build:mac

# Linux (на любой ОС)
npm run build:linux

# Все платформы (GitHub Actions)
git tag v1.0.0
git push origin v1.0.0
```

---

## 📊 Сравнение размеров

| Платформа | Размер | Причина |
|-----------|--------|---------|
| Windows .exe | ~90 MB | Chromium + NSIS compression |
| macOS .dmg | ~150 MB | Chromium + Mac frameworks |
| Linux .AppImage | ~130 MB | Chromium + все зависимости |
| Linux .deb | ~110 MB | Chromium + Debian packaging |

---

## ❓ FAQ

### Q: Почему macOS build больше?
**A:** Включает дополнительные Apple frameworks и не использует агрессивное сжатие

### Q: Можно ли на Windows собрать для Mac?
**A:** Нет, только через GitHub Actions или на реальном Mac

### Q: Нужен ли Mac для тестирования?
**A:** Да, macOS приложения запускаются только на Mac

### Q: Что такое "Hardened Runtime"?
**A:** Дополнительная защита macOS, требуется для подписи кода

### Q: Gatekeeper блокирует приложение?
**A:** Ctrl+Click → Open при первом запуске, или подпиши код сертификатом

---

## 🎯 Рекомендации

1. **Для разработки:**
   - Тестируй на Windows: `npm run build:win`
   - Проверяй на Mac через виртуалку или GitHub Actions

2. **Для релиза:**
   - Используй GitHub Actions для всех платформ
   - Создавай Git tag → автоматический Release

3. **Для App Store:**
   - Нужен Apple Developer Account
   - Подписывай код сертификатом
   - Используй `mas` target в electron-builder

---

**Вывод:** Используй GitHub Actions для автоматической сборки на всех платформах без необходимости иметь Mac! 🚀

**Файл:** `.github/workflows/build-desktop.yml` уже настроен и готов к использованию.
