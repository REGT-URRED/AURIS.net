import fs from 'node:fs';
import path from 'node:path';

export const CONTEXTBASE_RULE_BLOCK = `<!-- CONTEXTBASE:START -->
## Memoria Persistente y Bitácora del Proyecto (contextbase)
Este proyecto utiliza un sistema de memoria técnica persistente en la carpeta \`contextbase/\`.

### Regla Crítica de Actualización (Obligatoria para Agentes de Código):
Toda futura corrección, mejora, alteración o nueva implementación en el código debe incluir **SIEMPRE**, como paso final y obligatorio, la actualización de los registros dentro de la carpeta \`contextbase/\`:
1. **\`contextbase/changelog.md\`**: Documentar metódicamente el cambio en \`## Cambios Realizados\` con fecha y actualizar \`## Cambios por Hacer\`.
2. **\`contextbase/tasklist.md\`**: Marcar con \`[x]\` las tareas completadas y registrar con \`[ ]\` cualquier nueva tarea o requerimiento pendiente.
3. **\`contextbase/fundamentos.md\`**: Actualizar si hubo modificaciones en arquitectura, dependencias, scripts o reglas operativas.
4. **Idioma**: Toda salida, bitácora y documentación debe mantenerse estrictamente en **español**.
<!-- CONTEXTBASE:END -->`;

/**
 * Inyecta o actualiza el bloque de reglas de contextbase en un archivo
 */
function injectRuleInFile(filePath) {
  let content = '';
  if (fs.existsSync(filePath)) {
    content = fs.readFileSync(filePath, 'utf8');
  }

  const startTag = '<!-- CONTEXTBASE:START -->';
  const endTag = '<!-- CONTEXTBASE:END -->';

  let updatedContent;
  if (content.includes(startTag) && content.includes(endTag)) {
    // Reemplazar bloque existente
    const regex = new RegExp(`${startTag}[\\s\\S]*?${endTag}`, 'g');
    updatedContent = content.replace(regex, CONTEXTBASE_RULE_BLOCK);
  } else if (content.trim().length > 0) {
    // Agregar al final
    updatedContent = `${content.trim()}\n\n${CONTEXTBASE_RULE_BLOCK}\n`;
  } else {
    // Archivo nuevo
    updatedContent = `${CONTEXTBASE_RULE_BLOCK}\n`;
  }

  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, updatedContent, 'utf8');
  return true;
}

/**
 * Inyecta las directivas de ContextBase en todos los agentes comunes
 */
export function injectAgentRules(projectDir) {
  const targetFiles = [
    path.join(projectDir, 'AGENTS.md'),
    path.join(projectDir, 'CLAUDE.md'),
    path.join(projectDir, '.cursorrules'),
    path.join(projectDir, '.windsurfrules')
  ];

  // Si existe .gemini o .agents, también agregarlo allí
  const geminiRules = path.join(projectDir, '.gemini', 'rules', 'contextbase.md');
  const agentRules = path.join(projectDir, '.agents', 'rules', 'contextbase.md');

  if (fs.existsSync(path.join(projectDir, '.gemini'))) {
    targetFiles.push(geminiRules);
  }
  if (fs.existsSync(path.join(projectDir, '.agents'))) {
    targetFiles.push(agentRules);
  }

  const injected = [];
  for (const file of targetFiles) {
    try {
      injectRuleInFile(file);
      injected.push(path.relative(projectDir, file).replace(/\\/g, '/'));
    } catch {
      // Ignorar fallos individuales de permisos
    }
  }

  return injected;
}
