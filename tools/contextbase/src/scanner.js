import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const DEFAULT_IGNORES = [
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.turbo',
  'coverage',
  '.venv',
  'venv',
  '__pycache__',
  '.idea',
  '.vscode',
  '.changeset',
  '.cache',
  'pnpm-lock.yaml',
  'package-lock.json',
  'yarn.lock',
  'Cargo.lock',
  'poetry.lock',
  'Gemfile.lock',
  'composer.lock'
];

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp', '.tiff',
  '.pdf', '.zip', '.tar', '.gz', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.iso',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.wav', '.mov', '.avi', '.flv',
  '.pyc', '.class', '.o', '.obj'
]);

const LANGUAGE_EXTENSIONS = {
  '.js': 'JavaScript',
  '.jsx': 'JavaScript (React)',
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript (React)',
  '.py': 'Python',
  '.go': 'Go',
  '.rs': 'Rust',
  '.java': 'Java',
  '.c': 'C',
  '.cpp': 'C++',
  '.cs': 'C#',
  '.php': 'PHP',
  '.rb': 'Ruby',
  '.swift': 'Swift',
  '.kt': 'Kotlin',
  '.html': 'HTML',
  '.css': 'CSS',
  '.scss': 'SCSS',
  '.sass': 'Sass',
  '.vue': 'Vue',
  '.svelte': 'Svelte',
  '.sh': 'Shell',
  '.bash': 'Bash',
  '.ps1': 'PowerShell',
  '.json': 'JSON',
  '.yaml': 'YAML',
  '.yml': 'YAML',
  '.md': 'Markdown',
  '.sql': 'SQL'
};

/**
 * Carga patrones de exclusión de .gitignore si existe
 */
function loadGitignorePatterns(projectDir) {
  const gitignorePath = path.join(projectDir, '.gitignore');
  const patterns = [...DEFAULT_IGNORES];
  if (fs.existsSync(gitignorePath)) {
    try {
      const content = fs.readFileSync(gitignorePath, 'utf8');
      const lines = content.split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'))
        .map(l => l.replace(/^\//, '').replace(/\/$/, ''));
      patterns.push(...lines);
    } catch {
      // Ignorar fallos de lectura
    }
  }
  return Array.from(new Set(patterns));
}

/**
 * Determina si una ruta debe ser ignorada
 */
function shouldIgnore(relativeFilePath, ignorePatterns) {
  const normalized = relativeFilePath.replace(/\\/g, '/');
  const parts = normalized.split('/');

  for (const part of parts) {
    if (ignorePatterns.includes(part)) return true;
  }

  for (const pattern of ignorePatterns) {
    if (normalized === pattern || normalized.startsWith(pattern + '/')) {
      return true;
    }
  }

  const ext = path.extname(relativeFilePath).toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) return true;

  return false;
}

/**
 * Escanea recursivamente el árbol de archivos
 */
export function scanFiles(projectDir, maxFiles = 1000) {
  const ignorePatterns = loadGitignorePatterns(projectDir);
  const fileList = [];
  const dirList = [];

  function walk(currentDir, relativeBase = '') {
    if (fileList.length >= maxFiles) return;

    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const relativePath = path.join(relativeBase, entry.name);
      if (shouldIgnore(relativePath, ignorePatterns)) {
        continue;
      }

      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        dirList.push(relativePath.replace(/\\/g, '/'));
        walk(fullPath, relativePath);
      } else if (entry.isFile()) {
        fileList.push({
          name: entry.name,
          relativePath: relativePath.replace(/\\/g, '/'),
          fullPath,
          ext: path.extname(entry.name).toLowerCase()
        });
      }
    }
  }

  walk(projectDir);
  return { files: fileList, directories: dirList };
}

/**
 * Extrae metadatos del proyecto (package.json, pyproject, cargo, etc.)
 */
export function extractProjectMetadata(projectDir) {
  const meta = {
    name: path.basename(path.resolve(projectDir)),
    description: '',
    version: '0.1.0',
    type: 'Generic',
    scripts: {},
    dependencies: [],
    devDependencies: [],
    frameworks: [],
    entryPoints: []
  };

  // Node.js package.json
  const pkgPath = path.join(projectDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      meta.name = pkg.name || meta.name;
      meta.description = pkg.description || meta.description;
      meta.version = pkg.version || meta.version;
      meta.type = 'Node.js / JavaScript / TypeScript';
      meta.scripts = pkg.scripts || {};
      meta.dependencies = Object.keys(pkg.dependencies || {});
      meta.devDependencies = Object.keys(pkg.devDependencies || {});

      // Detección de frameworks populares
      const allDeps = [...meta.dependencies, ...meta.devDependencies];
      if (allDeps.includes('next')) meta.frameworks.push('Next.js');
      if (allDeps.includes('react')) meta.frameworks.push('React');
      if (allDeps.includes('vue')) meta.frameworks.push('Vue.js');
      if (allDeps.includes('express')) meta.frameworks.push('Express');
      if (allDeps.includes('fastify')) meta.frameworks.push('Fastify');
      if (allDeps.includes('nest') || allDeps.some(d => d.includes('@nestjs'))) meta.frameworks.push('NestJS');
      if (allDeps.includes('vite')) meta.frameworks.push('Vite');
      if (allDeps.includes('tailwindcss')) meta.frameworks.push('TailwindCSS');
    } catch {
      // Ignorar error de parsing
    }
  }

  // Python
  const pyprojectPath = path.join(projectDir, 'pyproject.toml');
  const reqsPath = path.join(projectDir, 'requirements.txt');
  if (fs.existsSync(pyprojectPath) || fs.existsSync(reqsPath)) {
    meta.type = meta.type === 'Generic' ? 'Python' : `${meta.type} + Python`;
    if (fs.existsSync(reqsPath)) {
      try {
        const lines = fs.readFileSync(reqsPath, 'utf8').split('\n');
        for (const line of lines) {
          const dep = line.trim().split(/[=><~]/)[0].trim();
          if (dep && !dep.startsWith('#')) {
            meta.dependencies.push(dep);
            if (['fastapi', 'flask', 'django'].includes(dep.toLowerCase())) {
              meta.frameworks.push(dep);
            }
          }
        }
      } catch {}
    }
  }

  // Rust
  const cargoPath = path.join(projectDir, 'Cargo.toml');
  if (fs.existsSync(cargoPath)) {
    meta.type = meta.type === 'Generic' ? 'Rust' : `${meta.type} + Rust`;
  }

  // Go
  const goModPath = path.join(projectDir, 'go.mod');
  if (fs.existsSync(goModPath)) {
    meta.type = meta.type === 'Generic' ? 'Go' : `${meta.type} + Go`;
  }

  // README summary
  const readmePath = path.join(projectDir, 'README.md');
  if (fs.existsSync(readmePath) && !meta.description) {
    try {
      const readme = fs.readFileSync(readmePath, 'utf8');
      const lines = readme.split('\n').map(l => l.trim()).filter(Boolean);
      for (const line of lines) {
        if (!line.startsWith('#') && line.length > 20) {
          meta.description = line;
          break;
        }
      }
    } catch {}
  }

  return meta;
}

/**
 * Extrae historial de commits de git si está disponible
 */
export function extractGitHistory(projectDir, limit = 10) {
  try {
    const output = execSync(`git log -n ${limit} --pretty=format:"%ad | %s" --date=short`, {
      cwd: projectDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000
    });
    return output.split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Escanea tareas pendientes en código (TODO, FIXME, HACK, BUG)
 */
export function extractCodeTodos(files, maxTodos = 25) {
  const todos = [];
  const todoRegex = /\b(TODO|FIXME|HACK|BUG):\s*(.+)$/i;

  for (const file of files) {
    if (todos.length >= maxTodos) break;
    // Solo escanear archivos de código/texto relevantes (< 300KB)
    try {
      const stat = fs.statSync(file.fullPath);
      if (stat.size > 300 * 1024) continue;

      const content = fs.readFileSync(file.fullPath, 'utf8');
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(todoRegex);
        if (match) {
          todos.push({
            type: match[1].toUpperCase(),
            text: match[2].trim(),
            file: file.relativePath,
            line: i + 1
          });
          if (todos.length >= maxTodos) break;
        }
      }
    } catch {
      // Ignorar errores de lectura
    }
  }

  return todos;
}

/**
 * Motor Repomix integrado: empaqueta el repositorio completo o genera un resumen
 */
export function packRepository(projectDir, options = {}) {
  const maxFileSize = options.maxFileSize || 200 * 1024; // 200KB por archivo
  const { files } = scanFiles(projectDir, options.maxFiles || 500);

  let output = `# REPOMIX REPOSITORY PACK (ContextBase Engine)\n`;
  output += `> Generado: ${new Date().toISOString()}\n`;
  output += `> Directorio: ${projectDir}\n`;
  output += `> Total de archivos empaquetados: ${files.length}\n\n`;

  output += `## Estructura de Archivos:\n\`\`\`\n`;
  for (const file of files) {
    output += `${file.relativePath}\n`;
  }
  output += `\`\`\`\n\n`;

  output += `## Contenido del Código:\n\n`;

  for (const file of files) {
    try {
      const stat = fs.statSync(file.fullPath);
      if (stat.size > maxFileSize) {
        output += `### ${file.relativePath} (Omitido: archivo demasiado grande > ${Math.round(maxFileSize / 1024)}KB)\n\n`;
        continue;
      }
      const content = fs.readFileSync(file.fullPath, 'utf8');
      const ext = path.extname(file.name).replace('.', '');
      output += `### File: ${file.relativePath}\n`;
      output += `\`\`\`${ext}\n${content}\n\`\`\`\n\n`;
    } catch (e) {
      output += `### File: ${file.relativePath} (Error al leer: ${e.message})\n\n`;
    }
  }

  return output;
}

/**
 * Análisis integral del proyecto
 */
export function analyzeProject(projectDir) {
  const { files, directories } = scanFiles(projectDir);
  const metadata = extractProjectMetadata(projectDir);
  const gitHistory = extractGitHistory(projectDir);
  const todos = extractCodeTodos(files);

  // Detección de lenguajes
  const langCount = {};
  for (const file of files) {
    const lang = LANGUAGE_EXTENSIONS[file.ext];
    if (lang) {
      langCount[lang] = (langCount[lang] || 0) + 1;
    }
  }

  return {
    metadata,
    files,
    directories,
    gitHistory,
    todos,
    languages: langCount
  };
}
