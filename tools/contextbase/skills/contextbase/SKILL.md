---
name: contextbase
description: Sistema universal y minimalista de memoria persistente técnica, bitácora y lista de tareas para agentes de código (Antigravity, Claude Code, Cursor, OpenCode, Kilo, Kimi Code, etc.).
---

# ContextBase: Memoria Técnica Persistente y Bitácora Universal

ContextBase garantiza la continuidad técnica, contexto persistente y trazabilidad entre sesiones de trabajo para agentes de código y desarrolladores.

## Directiva de Inicialización ("Instala esto...")
Cuando el usuario indique "instala esto", "inicializa memoria" o se trabaje en un proyecto sin bitácora técnica:

1. Ejecutar en terminal:
   ```bash
   contextbase init
   ```
   *(O simplemente `contextbase` - detecta automáticamente si `contextbase/` falta y lo crea).*

2. Esto ejecutará secuencialmente:
   - Creación de `contextbase/`
   - Generación de `contextbase/fundamentos.md` con objetivos, arquitectura y reglas.
   - Creación de `contextbase/changelog.md` con historial metódico ("Cambios realizados" y "Cambios por hacer").
   - Creación de `contextbase/tasklist.md` con formato visual `[x]` y `[ ]`.
   - Escaneo retroactivo y volcado de datos reales del proyecto.
   - Inyección de directivas en `AGENTS.md`, `CLAUDE.md`, `.cursorrules` y `.windsurfrules`.

> **Garantía de Auto-Creación:** Si ejecutas cualquier comando (`status`, `task add`, `log`, etc.) en un proyecto que aún no tiene `contextbase/`, la herramienta lo inicializará automáticamente antes de procesar la orden.

---

## Regla Crítica de Actualización (Obligatoria para Agentes)
> **Directiva Fundamental:** Toda futura corrección, mejora, alteración o nueva implementación en el código debe incluir SIEMPRE, como paso final y obligatorio, la actualización de los registros dentro de la carpeta `contextbase/`:
>
> 1. `contextbase/changelog.md`: Registrar la entrada bajo `## Cambios Realizados` y actualizar `## Cambios por Hacer`.
> 2. `contextbase/tasklist.md`: Marcar con `[x]` las tareas completadas y registrar con `[ ]` las pendientes.
> 3. `contextbase/fundamentos.md`: Actualizar si se modificó la arquitectura o dependencias.
> 4. Idioma: Toda la documentación debe mantenerse estrictamente en **español**.

---

## Comandos CLI de Soporte Rápido
- `contextbase status`: Ver estado visual de memoria, tareas completadas vs pendientes.
- `contextbase task add "<tarea>"`: Agregar una tarea pendiente a `tasklist.md`.
- `contextbase task done "<tarea>"`: Marcar tarea como completada en `tasklist.md`.
- `contextbase log "<mensaje>"`: Registrar un cambio en `changelog.md`.
- `contextbase pack`: Empaquetar el repositorio estilo Repomix para análisis en contexto.
- `contextbase dump`: Volcar todo el contenido de contextbase para alimentar el prompt.
