import fs from 'node:fs';
import path from 'node:path';
import { analyzeProject, packRepository } from './scanner.js';
import { writeContextBase } from './generator.js';
import { injectAgentRules } from './rules.js';
import { installSkill } from './installer.js';

// Estilos ANSI sin dependencias
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  magenta: '\x1b[35m',
  blue: '\x1b[34m',
  gray: '\x1b[90m'
};

function banner() {
  console.log(`\n${c.cyan}${c.bold}╔════════════════════════════════════════════════════════════════╗`);
  console.log(`║                   CONTEXTBASE (v1.0.0)                         ║`);
  console.log(`║   Memoria Técnica Persistente Minimalista para Agentes de IA   ║`);
  console.log(`╚════════════════════════════════════════════════════════════════╝${c.reset}\n`);
}

function showHelp() {
  banner();
  console.log(`${c.bold}USO:${c.reset}`);
  console.log(`  ${c.green}contextbase${c.reset} [comando] [opciones]\n`);
  console.log(`${c.bold}COMANDOS PRINCIPALES:${c.reset}`);
  console.log(`  ${c.cyan}init${c.reset}                  Inicializa contextbase en el proyecto actual.`);
  console.log(`                        Ejecuta escaneo profundo, crea fundamentos.md, changelog.md,`);
  console.log(`                        tasklist.md e inyecta reglas universales para agentes.`);
  console.log(`  ${c.cyan}status${c.reset} | ${c.cyan}check${c.reset}        Muestra el estado visual de la memoria y tareas.`);
  console.log(`  ${c.cyan}pack${c.reset} [archivo]        Empaqueta el código fuente estilo Repomix en un solo archivo.`);
  console.log(`  ${c.cyan}dump${c.reset}                  Vuelca el contenido completo de contextbase en pantalla.`);
  console.log(`  ${c.cyan}install-skill${c.reset}         Instala la Skill de ContextBase en el directorio global.`);
  console.log(`  ${c.cyan}log${c.reset} <mensaje>         Registra un nuevo cambio en contextbase/changelog.md.`);
  console.log(`  ${c.cyan}task add${c.reset} <descripción> Añade una nueva tarea pendiente [ ] a tasklist.md.`);
  console.log(`  ${c.cyan}task done${c.reset} <texto>      Marca una tarea como completada [x] en tasklist.md.`);
  console.log(`  ${c.cyan}task list${c.reset}             Lista todas las tareas actuales.\n`);
  console.log(`${c.bold}OPCIONES DE INIT:${c.reset}`);
  console.log(`  ${c.yellow}--force${c.reset}               Sobrescribe archivos existentes en contextbase/.`);
  console.log(`  ${c.yellow}--pack${c.reset}                Genera también contextbase-pack.txt durante la inicialización.\n`);
  console.log(`${c.bold}EJEMPLOS:${c.reset}`);
  console.log(`  contextbase init`);
  console.log(`  contextbase status`);
  console.log(`  contextbase log "Refactorización de módulo de autenticación"`);
  console.log(`  contextbase task add "Implementar tests unitarios para scanner"`);
  console.log(`  contextbase task done "scanner"`);
  console.log(`  contextbase pack\n`);
}

/**
 * Comando: contextbase init
 */
export async function runInit(targetDir = process.cwd(), options = {}) {
  banner();
  console.log(`${c.bold}Iniciando implementación secuencial de ContextBase en:${c.reset} ${c.dim}${targetDir}${c.reset}\n`);

  // Paso 1: Creación de directorio
  console.log(`${c.cyan}[1/5] Creación de Directorio:${c.reset} Verificando carpeta 'contextbase/'...`);
  const contextDir = path.join(targetDir, 'contextbase');
  if (!fs.existsSync(contextDir)) {
    fs.mkdirSync(contextDir, { recursive: true });
    console.log(`      ${c.green}✓ Carpeta creada exitosamente:${c.reset} ${contextDir}`);
  } else {
    console.log(`      ${c.gray}✓ Carpeta existente detectada.${c.reset}`);
  }

  // Paso 2: Análisis y escaneo profundo (estilo Repomix)
  console.log(`\n${c.cyan}[2/5] Análisis y Escaneo Profundo:${c.reset} Leyendo archivos, dependencias y commits...`);
  const analysis = analyzeProject(targetDir);
  console.log(`      ${c.green}✓ Proyecto detectado:${c.reset} ${analysis.metadata.name} (${analysis.metadata.type})`);
  console.log(`      ${c.green}✓ Archivos analizados:${c.reset} ${analysis.files.length} archivos relevantes`);
  if (analysis.todos.length > 0) {
    console.log(`      ${c.yellow}✓ TODOs/Pendientes detectados:${c.reset} ${analysis.todos.length} ítems en código`);
  }
  if (analysis.gitHistory.length > 0) {
    console.log(`      ${c.green}✓ Historial Git:${c.reset} ${analysis.gitHistory.length} commits recientes registrados`);
  }

  // Paso 3: Generación de documentos
  console.log(`\n${c.cyan}[3/5] Generación y Poblado de Documentos:${c.reset}`);
  const result = writeContextBase(targetDir, analysis, { force: options.force });
  for (const f of result.filesWritten) {
    console.log(`      ${c.green}✓ Generado:${c.reset} ${f}`);
  }
  if (result.filesWritten.length === 0) {
    console.log(`      ${c.gray}(Archivos previos conservados. Usa --force si deseas regenerarlos)${c.reset}`);
  }

  // Paso 4: Inyección de reglas para agentes de código
  console.log(`\n${c.cyan}[4/5] Inyección de Directivas para Agentes de Código:${c.reset}`);
  const rulesUpdated = injectAgentRules(targetDir);
  for (const r of rulesUpdated) {
    console.log(`      ${c.green}✓ Regla de actualización obligatoria inyectada en:${c.reset} ${r}`);
  }

  // Paso 5: Instalación global de la skill para agentes
  console.log(`\n${c.cyan}[5/5] Disponibilidad Universal de Skill:${c.reset}`);
  try {
    const installed = installSkill('global');
    for (const inst of installed) {
      console.log(`      ${c.green}✓ Skill disponible globalmente en:${c.reset} ${inst}`);
    }
  } catch (e) {
    console.log(`      ${c.gray}Nota: No se pudo instalar la skill global (${e.message})${c.reset}`);
  }

  // Empaquetado opcional
  if (options.pack) {
    console.log(`\n${c.magenta}[Repomix] Generando empaquetado del repositorio...${c.reset}`);
    const packContent = packRepository(targetDir);
    const packFile = path.join(targetDir, 'contextbase-pack.txt');
    fs.writeFileSync(packFile, packContent, 'utf8');
    console.log(`      ${c.green}✓ Repositorio empaquetado en:${c.reset} contextbase-pack.txt`);
  }

  console.log(`\n${c.green}${c.bold}✨ ¡ContextBase inicializado y completamente funcional!${c.reset}`);
  console.log(`${c.dim}Cualquier agente de código ahora actualizará contextbase/ de forma obligatoria tras cada cambio.${c.reset}\n`);
}

/**
 * Comando: contextbase status
 */
export function runStatus(targetDir = process.cwd()) {
  banner();
  const contextDir = path.join(targetDir, 'contextbase');

  if (!fs.existsSync(contextDir)) {
    console.log(`${c.yellow}⚠️ No se encontró la carpeta 'contextbase/' en este directorio.${c.reset}`);
    console.log(`   Ejecuta ${c.green}contextbase init${c.reset} para inicializar la memoria persistente.\n`);
    return;
  }

  const fundamentosPath = path.join(contextDir, 'fundamentos.md');
  const changelogPath = path.join(contextDir, 'changelog.md');
  const tasklistPath = path.join(contextDir, 'tasklist.md');

  console.log(`${c.bold}ESTADO DE LA MEMORIA TÉCNICA (${targetDir}):${c.reset}\n`);

  // Archivos presentes
  const files = [
    { name: 'fundamentos.md', path: fundamentosPath },
    { name: 'changelog.md', path: changelogPath },
    { name: 'tasklist.md', path: tasklistPath }
  ];

  for (const f of files) {
    if (fs.existsSync(f.path)) {
      const stat = fs.statSync(f.path);
      const mod = stat.mtime.toLocaleDateString('es-ES') + ' ' + stat.mtime.toLocaleTimeString('es-ES');
      console.log(`  ${c.green}●${c.reset} ${c.bold}${f.name}${c.reset} ${c.gray}(Modificado: ${mod}, ${stat.size} bytes)${c.reset}`);
    } else {
      console.log(`  ${c.red}○${c.reset} ${c.bold}${f.name}${c.reset} ${c.red}(Faltante)${c.reset}`);
    }
  }

  // Tareas
  if (fs.existsSync(tasklistPath)) {
    const content = fs.readFileSync(tasklistPath, 'utf8');
    const doneCount = (content.match(/\[x\]/gi) || []).length;
    const pendingCount = (content.match(/\[ \]/g) || []).length;
    const total = doneCount + pendingCount;
    const pct = total > 0 ? Math.round((doneCount / total) * 100) : 0;

    console.log(`\n${c.bold}PROGRESO DE TAREAS:${c.reset}`);
    console.log(`  ${c.green}✓ Completadas:${c.reset} ${doneCount}`);
    console.log(`  ${c.yellow}⏳ Pendientes:${c.reset}  ${pendingCount}`);
    console.log(`  ${c.cyan}📊 Total:${c.reset}       ${total} (${pct}% completado)`);
  }

  console.log('\n');
}

/**
 * Comando: contextbase task
 */
export function runTask(action, taskText, targetDir = process.cwd()) {
  const tasklistPath = path.join(targetDir, 'contextbase', 'tasklist.md');
  if (!fs.existsSync(tasklistPath)) {
    console.log(`${c.red}Error: No existe contextbase/tasklist.md. Ejecuta 'contextbase init' primero.${c.reset}`);
    return;
  }

  let content = fs.readFileSync(tasklistPath, 'utf8');

  if (action === 'add') {
    if (!taskText) {
      console.log(`${c.yellow}Uso: contextbase task add "<descripción de la tarea>"${c.reset}`);
      return;
    }
    const targetHeader = '## Tareas Pendientes / En Progreso';
    const newTask = `- [ ] ${taskText.trim()}`;
    if (content.includes(targetHeader)) {
      content = content.replace(targetHeader, `${targetHeader}\n${newTask}`);
    } else {
      content += `\n${targetHeader}\n${newTask}\n`;
    }
    fs.writeFileSync(tasklistPath, content, 'utf8');
    console.log(`${c.green}✓ Tarea agregada con éxito:${c.reset} ${taskText}`);
  } else if (action === 'done') {
    if (!taskText) {
      console.log(`${c.yellow}Uso: contextbase task done "<texto o parte de la tarea>"${c.reset}`);
      return;
    }
    let completedLine = null;
    const remainingLines = [];
    const lines = content.split('\n');
    const query = taskText.toLowerCase().trim();

    for (const line of lines) {
      if (!completedLine && line.includes('[ ]') && line.toLowerCase().includes(query)) {
        completedLine = line.replace('[ ]', '[x]');
        console.log(`${c.green}✓ Tarea completada:${c.reset} ${completedLine.replace('- [x]', '').trim()}`);
      } else {
        remainingLines.push(line);
      }
    }

    if (completedLine) {
      let newContent = remainingLines.join('\n');
      const compHeader = '## Tareas Completadas';
      if (newContent.includes(compHeader)) {
        newContent = newContent.replace(compHeader, `${compHeader}\n${completedLine}`);
      } else {
        newContent = `${compHeader}\n${completedLine}\n\n${newContent}`;
      }
      fs.writeFileSync(tasklistPath, newContent, 'utf8');
    } else {
      console.log(`${c.yellow}No se encontró ninguna tarea pendiente que coincida con:${c.reset} "${taskText}"`);
    }
  } else if (action === 'list') {
    const lines = content.split('\n');
    console.log(`\n${c.bold}LISTA DE TAREAS:${c.reset}\n`);
    for (const line of lines) {
      if (line.includes('[x]')) {
        console.log(`  ${c.green}${line}${c.reset}`);
      } else if (line.includes('[ ]')) {
        console.log(`  ${c.yellow}${line}${c.reset}`);
      } else if (line.startsWith('## ')) {
        console.log(`\n${c.bold}${c.cyan}${line}${c.reset}`);
      }
    }
    console.log('\n');
  }
}

/**
 * Comando: contextbase log
 */
export function runLog(logMessage, targetDir = process.cwd()) {
  if (!logMessage) {
    console.log(`${c.yellow}Uso: contextbase log "<mensaje del cambio realizado>"${c.reset}`);
    return;
  }

  const changelogPath = path.join(targetDir, 'contextbase', 'changelog.md');
  if (!fs.existsSync(changelogPath)) {
    console.log(`${c.red}Error: No existe contextbase/changelog.md. Ejecuta 'contextbase init' primero.${c.reset}`);
    return;
  }

  let content = fs.readFileSync(changelogPath, 'utf8');
  const targetHeader = '## Cambios Realizados';
  const dateStr = new Date().toISOString().split('T')[0];
  const newEntry = `- [${dateStr}] ${logMessage.trim()}`;

  if (content.includes(targetHeader)) {
    content = content.replace(targetHeader, `${targetHeader}\n${newEntry}`);
  } else {
    content = `## Cambios Realizados\n${newEntry}\n\n${content}`;
  }

  fs.writeFileSync(changelogPath, content, 'utf8');
  console.log(`${c.green}✓ Cambio registrado en contextbase/changelog.md:${c.reset} ${newEntry}`);
}

/**
 * Comando: contextbase dump
 */
export function runDump(targetDir = process.cwd()) {
  const contextDir = path.join(targetDir, 'contextbase');
  if (!fs.existsSync(contextDir)) {
    console.log(`${c.red}Error: No se encontró la carpeta contextbase/.${c.reset}`);
    return;
  }

  const files = ['fundamentos.md', 'changelog.md', 'tasklist.md'];
  for (const file of files) {
    const full = path.join(contextDir, file);
    if (fs.existsSync(full)) {
      console.log(`\n${c.cyan}${c.bold}=== ${file.toUpperCase()} ===${c.reset}\n`);
      console.log(fs.readFileSync(full, 'utf8'));
    }
  }
}

/**
 * Comando: contextbase pack
 */
export function runPack(outputFile, targetDir = process.cwd()) {
  banner();
  console.log(`${c.magenta}[Repomix Engine] Empaquetando código fuente...${c.reset}`);
  const result = packRepository(targetDir);
  const outPath = outputFile || path.join(targetDir, 'contextbase-pack.txt');
  fs.writeFileSync(outPath, result, 'utf8');
  console.log(`${c.green}✓ Repositorio empaquetado exitosamente en:${c.reset} ${outPath}\n`);
}

/**
 * Garantiza que contextbase/ exista y contenga todos los archivos requeridos.
 * Si no existe o le falta algún archivo, lo inicializa automáticamente.
 */
export async function ensureContextBase(targetDir = process.cwd(), silent = false) {
  const contextDir = path.join(targetDir, 'contextbase');
  const fundamentos = path.join(contextDir, 'fundamentos.md');
  const changelog = path.join(contextDir, 'changelog.md');
  const tasklist = path.join(contextDir, 'tasklist.md');

  const isMissing = !fs.existsSync(contextDir) ||
                    !fs.existsSync(fundamentos) ||
                    !fs.existsSync(changelog) ||
                    !fs.existsSync(tasklist);

  if (isMissing) {
    if (!silent) {
      console.log(`${c.yellow}⚡ 'contextbase/' no existe o está incompleto en este proyecto. Inicializando automáticamente...${c.reset}`);
    }
    await runInit(targetDir, { force: false });
    return true;
  }
  return false;
}

/**
 * CLI Router Principal
 */
export async function cli(args = process.argv.slice(2)) {
  if (args.length === 0) {
    const contextDir = path.join(process.cwd(), 'contextbase');
    if (!fs.existsSync(contextDir)) {
      await runInit(process.cwd());
    } else {
      await ensureContextBase(process.cwd(), true);
      runStatus(process.cwd());
    }
    return;
  }

  const command = args[0];

  if (command === '--help' || command === '-h' || command === 'help') {
    showHelp();
    return;
  }

  if (command === '--version' || command === '-v' || command === 'version') {
    console.log('1.0.0');
    return;
  }

  if (command === 'init') {
    const force = args.includes('--force');
    const pack = args.includes('--pack');
    await runInit(process.cwd(), { force, pack });
    return;
  }

  if (command === 'ensure') {
    await ensureContextBase(process.cwd());
    return;
  }

  if (command === 'status' || command === 'check') {
    await ensureContextBase(process.cwd());
    runStatus(process.cwd());
    return;
  }

  if (command === 'pack') {
    const out = args[1];
    runPack(out, process.cwd());
    return;
  }

  if (command === 'dump') {
    await ensureContextBase(process.cwd());
    runDump(process.cwd());
    return;
  }

  if (command === 'install-skill') {
    const installed = installSkill('global');
    console.log(`${c.green}✓ Skill instalada en:${c.reset}\n${installed.join('\n')}`);
    return;
  }

  if (command === 'log') {
    await ensureContextBase(process.cwd());
    const msg = args.slice(1).join(' ');
    runLog(msg, process.cwd());
    return;
  }

  if (command === 'task') {
    await ensureContextBase(process.cwd());
    const subAction = args[1] || 'list';
    const text = args.slice(2).join(' ');
    runTask(subAction, text, process.cwd());
    return;
  }

  // Si no se reconoce el comando pero no empieza con guion, intentar init o mostrar ayuda
  console.log(`${c.red}Comando no reconocido: ${command}${c.reset}\n`);
  showHelp();
}
