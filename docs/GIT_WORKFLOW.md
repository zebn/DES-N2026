# Flujo de Trabajo Git — DES-N2026

## Estructura de ramas

```
master (producción — solo releases estables)
│
└── develop (integración — aquí se juntan las features terminadas)
    │
    ├── feature/secrets-crud         ← RF01: CRUD de secretos
    ├── feature/rbac-roles           ← RF05: Sistema de roles RBAC
    ├── feature/groups-sharing       ← RF06: Grupos y compartición
    ├── feature/session-management   ← RF02: Gestión de sesiones
    ├── feature/audit-logging        ← RF08: Auditoría y logging
    │
    ├── feature/<nombre>             ← Nuevas funcionalidades
    ├── fix/<nombre>                 ← Corrección de bugs
    └── refactor/<nombre>            ← Refactorizaciones
```

---

## Reglas fundamentales

### 1. Nunca hacer commit directo a `master` ni a `develop`
- **`master`** = código estable, listo para entregar/desplegar
- **`develop`** = rama de integración donde se prueban las features juntas
- Todo el trabajo se hace en ramas `feature/`, `fix/`, o `refactor/`

### 2. Convención de nombres de rama
| Tipo | Formato | Ejemplo |
|------|---------|---------|
| Feature nueva | `feature/<nombre-descriptivo>` | `feature/secrets-crud` |
| Bug fix | `fix/<nombre-del-bug>` | `fix/login-token-expiry` |
| Refactorización | `refactor/<que-se-mejora>` | `refactor/crypto-service` |
| Hotfix (urgente en prod) | `hotfix/<descripcion>` | `hotfix/security-patch` |

### 3. Convención de mensajes de commit
Usar formato **Conventional Commits**:

```
<tipo>(<alcance>): <descripción corta>

[cuerpo opcional — qué y por qué]
```

**Tipos permitidos:**
| Tipo | Cuándo usarlo |
|------|--------------|
| `feat` | Nueva funcionalidad |
| `fix` | Corrección de bug |
| `refactor` | Cambio de código sin cambiar funcionalidad |
| `docs` | Cambios en documentación |
| `test` | Añadir o modificar tests |
| `chore` | Tareas de mantenimiento (deps, config) |
| `style` | Formato, espacios, sin cambio lógico |

**Ejemplos:**
```bash
git commit -m "feat(secrets): añadir modelo Secret con cifrado E2E"
git commit -m "fix(auth): corregir expiración de refresh token"
git commit -m "refactor(models): migrar clearance_level a sistema RBAC"
git commit -m "docs(prd): actualizar diagrama de arquitectura"
git commit -m "test(secrets): añadir tests unitarios para CRUD"
```

---

## Flujo de trabajo diario

### Empezar a trabajar en una feature

```bash
# 1. Asegurarse de estar en develop actualizado
git checkout develop
git pull origin develop

# 2. Crear rama de feature (o cambiar a una existente)
git checkout -b feature/mi-nueva-feature

# 3. Trabajar, hacer commits frecuentes y descriptivos
git add .
git commit -m "feat(secrets): crear modelo y migración de tabla secrets"

# 4. Subir la rama al remoto regularmente
git push origin feature/mi-nueva-feature
```

### Integrar feature terminada en develop

```bash
# 1. Actualizar develop
git checkout develop
git pull origin develop

# 2. Volver a la feature y hacer rebase (mantiene historial limpio)
git checkout feature/mi-feature
git rebase develop

# 3. Resolver conflictos si los hay, luego:
git rebase --continue

# 4. Opción A: Merge via Pull Request en GitHub (RECOMENDADO)
#    → Crear PR en GitHub: feature/mi-feature → develop
#    → Revisar cambios, aprobar y hacer merge

# 5. Opción B: Merge local (si trabajas solo)
git checkout develop
git merge --no-ff feature/mi-feature
git push origin develop

# 6. Eliminar la rama si ya no se necesita
git branch -d feature/mi-feature
git push origin --delete feature/mi-feature
```

### Crear un release (pasar a master)

```bash
# Solo cuando develop está estable y probado
git checkout master
git pull origin master
git merge --no-ff develop
git tag -a v1.0.0 -m "Release v1.0.0: MVP con gestión de secretos"
git push origin master --tags
```

---

## Flujo visual

```
feature/secrets-crud ──●──●──●──┐
                                │ PR / merge
feature/rbac-roles ──●──●──┐    │
                           │    ▼
develop ──────────────●────●────●────●────┐
                                          │ release
master ───────────────────────────────────●── v1.0.0
```

---

## Buenas prácticas

1. **Commits pequeños y frecuentes** — Un commit = un cambio lógico
2. **No mezclar features en una rama** — Cada rama = una sola responsabilidad
3. **Pull antes de push** — Siempre `git pull --rebase` antes de subir
4. **No subir archivos sensibles** — `.env`, claves privadas, certificados
5. **Revisar antes de commit** — Usar `git diff` y `git status` antes de cada commit
6. **Rebase > Merge para features** — Mantiene el historial lineal y limpio
7. **Tags para releases** — Marcar cada versión estable con `git tag`
8. **Borrar ramas merged** — Mantener el repo limpio de ramas obsoletas

---

## Comandos útiles de referencia

```bash
# Ver estado actual
git status
git log --oneline --graph --all

# Ver ramas
git branch -a

# Guardar cambios temporalmente (sin commit)
git stash
git stash pop

# Deshacer último commit (manteniendo cambios)
git reset --soft HEAD~1

# Ver diferencias antes de commit
git diff
git diff --staged

# Cambiar entre ramas rápidamente
git checkout -

# Ver quién modificó cada línea
git blame <archivo>
```

---

## Orden de desarrollo sugerido

Basado en las dependencias del PRD:

| Prioridad | Feature | Rama | Dependencias |
|-----------|---------|------|-------------|
| 1 | Refactorizar modelos (Secret, RBAC) | `feature/secrets-crud` + `feature/rbac-roles` | Ninguna |
| 2 | Gestión de sesiones | `feature/session-management` | Modelos base |
| 3 | Grupos y compartición | `feature/groups-sharing` | RBAC, modelos |
| 4 | Auditoría y logging | `feature/audit-logging` | Modelos base |
| 5 | Frontend Angular | `feature/frontend-*` | APIs backend |
