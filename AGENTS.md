# AGENTS.md — AURIS.net

Instrucciones para agentes de código que trabajen en este repositorio.

## Proyecto

AURIS.net es un framework modular de auditoría de seguridad inalámbrica (802.11)
para routers y CPEs domésticos. Python 3.10+, Linux (Kali/Parrot/Debian/Ubuntu),
100% offline en campo. La autorización por Reglas de Compromiso (RoE) es
obligatoria y no se negocia.

## Comandos

```bash
# Tests (nunca requieren hardware ni red)
PYTHONPATH=src pytest tests/ -v

# CLI
python3 auris.py doctor
python3 auris.py hal
python3 auris.py run-all --dry-run

# Memoria técnica persistente (Node >= 18, sin npm)
bash scripts/contextbase.sh status
bash scripts/contextbase.sh log "mensaje del cambio"
bash scripts/contextbase.sh task add "tarea pendiente"
```

## Reglas

1. Todo cambio de código termina actualizando `contextbase/` (ver bloque inferior).
2. No agregar dependencias nuevas sin justificarlo en `contextbase/fundamentos.md`.
3. Los tests deben correr sin hardware WiFi real ni conexión a internet.
4. Nada de telemetría, red o escritura fuera del repositorio en tiempo de test.
5. Documentación y bitácora en español; código e identificadores en inglés.

<!-- CONTEXTBASE:START -->
## Memoria Persistente y Bitácora del Proyecto (contextbase)
Este proyecto utiliza un sistema de memoria técnica persistente en la carpeta `contextbase/`.

### Regla Crítica de Actualización (Obligatoria para Agentes de Código):
Toda futura corrección, mejora, alteración o nueva implementación en el código debe incluir **SIEMPRE**, como paso final y obligatorio, la actualización de los registros dentro de la carpeta `contextbase/`:
1. **`contextbase/changelog.md`**: Documentar metódicamente el cambio en `## Cambios Realizados` con fecha y actualizar `## Cambios por Hacer`.
2. **`contextbase/tasklist.md`**: Marcar con `[x]` las tareas completadas y registrar con `[ ]` cualquier nueva tarea o requerimiento pendiente.
3. **`contextbase/fundamentos.md`**: Actualizar si hubo modificaciones en arquitectura, dependencias, scripts o reglas operativas.
4. **Idioma**: Toda salida, bitácora y documentación debe mantenerse estrictamente en **español**.
<!-- CONTEXTBASE:END -->
