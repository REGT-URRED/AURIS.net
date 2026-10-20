import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Instala la Skill de ContextBase en las ubicaciones globales de agentes
 */
export function installSkill(target = 'global') {
  const sourceSkillPath = path.resolve(__dirname, '..', 'skills', 'contextbase', 'SKILL.md');
  if (!fs.existsSync(sourceSkillPath)) {
    throw new Error(`Archivo fuente de la skill no encontrado en: ${sourceSkillPath}`);
  }

  const skillContent = fs.readFileSync(sourceSkillPath, 'utf8');
  const installedPaths = [];

  if (target === 'global' || target === 'all') {
    // 1. Antigravity / Gemini CLI Global
    const geminiGlobal = path.join(os.homedir(), '.gemini', 'config', 'skills', 'contextbase');
    try {
      fs.mkdirSync(geminiGlobal, { recursive: true });
      fs.writeFileSync(path.join(geminiGlobal, 'SKILL.md'), skillContent, 'utf8');
      installedPaths.push(path.join(geminiGlobal, 'SKILL.md'));
    } catch (e) {
      // Ignorar si hay restricción de permisos
    }

    // 2. Claude Code global si existe ~/.claude
    const claudeGlobal = path.join(os.homedir(), '.claude', 'skills', 'contextbase');
    if (fs.existsSync(path.join(os.homedir(), '.claude'))) {
      try {
        fs.mkdirSync(claudeGlobal, { recursive: true });
        fs.writeFileSync(path.join(claudeGlobal, 'SKILL.md'), skillContent, 'utf8');
        installedPaths.push(path.join(claudeGlobal, 'SKILL.md'));
      } catch {}
    }

    // 3. OpenCode global si existe ~/.config/opencode (Linux/macOS)
    const opencodeRoot = path.join(os.homedir(), '.config', 'opencode');
    if (fs.existsSync(opencodeRoot)) {
      const opencodeGlobal = path.join(opencodeRoot, 'skills', 'contextbase');
      try {
        fs.mkdirSync(opencodeGlobal, { recursive: true });
        fs.writeFileSync(path.join(opencodeGlobal, 'SKILL.md'), skillContent, 'utf8');
        installedPaths.push(path.join(opencodeGlobal, 'SKILL.md'));
      } catch {}
    }
  }

  if (target === 'workspace' || target === 'all') {
    // Local workspace .agents/skills/contextbase
    const workspacePath = path.join(process.cwd(), '.agents', 'skills', 'contextbase');
    try {
      fs.mkdirSync(workspacePath, { recursive: true });
      fs.writeFileSync(path.join(workspacePath, 'SKILL.md'), skillContent, 'utf8');
      installedPaths.push(path.join(workspacePath, 'SKILL.md'));
    } catch {}
  }

  return installedPaths;
}
