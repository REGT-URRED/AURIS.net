import fs from 'node:fs';
import path from 'node:path';

/**
 * Genera el contenido de contextbase/fundamentos.md
 */
export function generateFundamentos(analysis) {
  const { metadata, directories, languages } = analysis;
  const projectName = metadata.name || 'Proyecto';
  const projectDesc = metadata.description || 'Sistema y repositorio de desarrollo de software.';
  
  // Resumen de lenguajes
  const topLangs = Object.entries(languages)
    .sort((a, b) => b[1] - a[1])
    .map(([lang, count]) => `${lang} (${count} archivos)`)
    .slice(0, 5)
    .join(', ') || 'Políglota / General';

  // Resumen de scripts
  const scriptsList = Object.entries(metadata.scripts || {})
    .map(([cmd, script]) => `- \`npm run ${cmd}\`: \`${script}\``)
    .join('\n') || '- No se detectaron scripts automáticos en package.json.';

  // Directorios clave
  const topDirs = directories
    .filter(d => !d.includes('/'))
    .slice(0, 10)
    .map(d => `├── ${d}/`)
    .join('\n') || 'Raíz del repositorio.';

  // Frameworks y dependencias clave
  const frameworksStr = metadata.frameworks.length > 0
    ? metadata.frameworks.join(', ')
    : 'Librerías estándar / Vanilla';

  const depsSample = metadata.dependencies.slice(0, 15).join(', ') || 'Sin dependencias externas registradas.';

  return `# Fundamentos del Proyecto: ${projectName}

## 1. Objetivo Principal
${projectDesc}

Este documento establece las bases arquitectónicas, directivas operativas y contexto técnico esencial para mantener la coherencia y calidad a través de múltiples sesiones de trabajo y entre diversos agentes de código o desarrolladores.

---

## 2. Reglas de Desarrollo y Buenas Prácticas
1. **Regla Crítica de Actualización (Obligatoria):**
   - Toda corrección, mejora, alteración o nueva implementación en el código debe concluir **siempre y de manera obligatoria** con la actualización de los registros dentro de \`contextbase/\` (\`changelog.md\`, \`tasklist.md\` y este documento si hay cambios estructurales).
2. **Minimalismo y Simplicidad:**
   - Evitar complejidad accidental, dependencias innecesarias o abstracciones prematuras.
   - Preferir soluciones limpias, mantenibles y de ejecución directa.
3. **Calidad de Código y Estilo:**
   - Mantener consistencia en el estilo, tipado y convenciones del proyecto.
   - No dejar código muerto ni archivos huérfanos.
4. **Idioma de Documentación:**
   - Todas las notas técnicas, bitácoras y registros en \`contextbase/\` deben mantenerse estrictamente en **español**.

---

## 3. Arquitectura y Contexto Técnico General
- **Nombre:** \`${projectName}\`
- **Versión:** \`${metadata.version}\`
- **Tipo de Ecosistema:** ${metadata.type}
- **Tecnologías y Frameworks Clave:** ${frameworksStr}
- **Lenguajes Dominantes:** ${topLangs}
- **Dependencias Principales:** ${depsSample}

### Comandos de Ejecución y Scripts Disponibles:
${scriptsList}

---

## 4. Mapa de Estructura de Directorios Clave
\`\`\`
${projectName}/
├── contextbase/               # Memoria técnica persistente y bitácora
${topDirs}
\`\`\`

---
*Generado automáticamente por ContextBase CLI el ${new Date().toLocaleDateString('es-ES')}.*
`;
}

/**
 * Genera el contenido de contextbase/changelog.md
 */
export function generateChangelog(analysis) {
  const { gitHistory, todos } = analysis;

  let historySection = '';
  if (gitHistory && gitHistory.length > 0) {
    historySection = gitHistory
      .map(entry => `- [${entry.split(' | ')[0]}] ${entry.split(' | ')[1] || entry}`)
      .join('\n');
  } else {
    historySection = `- [${new Date().toISOString().split('T')[0]}] Inicialización del proyecto y configuración del sistema de memoria técnica contextbase.`;
  }

  let todosSection = '';
  if (todos && todos.length > 0) {
    todosSection = todos
      .map(t => `- [${t.type}] \`${t.file}:${t.line}\`: ${t.text}`)
      .join('\n');
  } else {
    todosSection = `- Consolidar pruebas de funcionamiento y despliegue inicial.\n- Documentar guías de uso y endpoints principales.`;
  }

  return `# Bitácora Histórica del Proyecto (Changelog)

Registro metódico del progreso técnico, decisiones de arquitectura y evolución del sistema.

---

## Cambios Realizados

${historySection}
- [${new Date().toISOString().split('T')[0]}] Implementación del sistema de memoria persistente \`contextbase/\` para agentes de código y desarrolladores.

---

## Cambios por Hacer

${todosSection}

---
*Nota: Registrar siempre cada nueva tarea completada en "Cambios Realizados" y actualizar los ítems pendientes en "Cambios por Hacer".*
`;
}

/**
 * Genera el contenido de contextbase/tasklist.md
 */
export function generateTasklist(analysis) {
  const { todos, metadata } = analysis;

  const completedDefault = [
    `- [x] Creación de carpeta de memoria persistente \`contextbase/\``,
    `- [x] Generación de documento estructurado \`fundamentos.md\``,
    `- [x] Creación de bitácora histórica \`changelog.md\``,
    `- [x] Configuración de lista de tareas visual de alto contraste \`tasklist.md\``,
    `- [x] Inyección de directivas y reglas críticas para agentes de código (\`AGENTS.md\`, \`CLAUDE.md\`, \`.cursorrules\`)`,
    `- [x] Escaneo y análisis retroactivo de los archivos del proyecto (\`${metadata.name}\`)`
  ];

  let pendingTasks = [];
  if (todos && todos.length > 0) {
    pendingTasks = todos.map(t => `- [ ] Resolver ${t.type} en \`${t.file}:${t.line}\`: ${t.text}`);
  } else {
    pendingTasks = [
      `- [ ] Validar cobertura de pruebas funcionales y unitarias`,
      `- [ ] Revisar optimizaciones de rendimiento y seguridad`,
      `- [ ] Preparar empaquetado o despliegue a producción`
    ];
  }

  return `# Lista de Tareas Visual (Tasklist)

Seguimiento del estado de tareas con alto contraste visual.

---

## Tareas Completadas

${completedDefault.join('\n')}

---

## Tareas Pendientes / En Progreso

${pendingTasks.join('\n')}

---
*Regla: Marcar con \`[x]\` las tareas completadas y agregar con \`[ ]\` cualquier nuevo requerimiento técnico.*
`;
}

/**
 * Escribe todos los archivos en contextbase/
 */
export function writeContextBase(projectDir, analysis, options = {}) {
  const contextDir = path.join(projectDir, 'contextbase');

  if (!fs.existsSync(contextDir)) {
    fs.mkdirSync(contextDir, { recursive: true });
  }

  const fundamentosPath = path.join(contextDir, 'fundamentos.md');
  const changelogPath = path.join(contextDir, 'changelog.md');
  const tasklistPath = path.join(contextDir, 'tasklist.md');

  const filesWritten = [];

  // Si no forzar overwrite, respetar si ya existían para no borrar notas manuales previas
  if (!fs.existsSync(fundamentosPath) || options.force) {
    fs.writeFileSync(fundamentosPath, generateFundamentos(analysis), 'utf8');
    filesWritten.push('contextbase/fundamentos.md');
  }

  if (!fs.existsSync(changelogPath) || options.force) {
    fs.writeFileSync(changelogPath, generateChangelog(analysis), 'utf8');
    filesWritten.push('contextbase/changelog.md');
  }

  if (!fs.existsSync(tasklistPath) || options.force) {
    fs.writeFileSync(tasklistPath, generateTasklist(analysis), 'utf8');
    filesWritten.push('contextbase/tasklist.md');
  }

  return {
    contextDir,
    filesWritten
  };
}
