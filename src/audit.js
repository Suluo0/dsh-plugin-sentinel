/**
 * Audit orchestrator: walks a package (directory, tarball, or in-memory
 * virtual files), runs every analyzer, evaluates combo rules, and produces
 * the canonical report value.
 */

import { createRequire } from 'node:module'
import path from 'node:path'
import { readFile, readdir } from 'node:fs/promises'
import os from 'node:os'

import { CODE_RULES, LITERAL_RULES, COMBO_RULES, MANIFEST_RULES, scoreFindings, SEVERITY_ORDER } from './rules.js'
import { stripSource, extractModules } from './scanner.js'
import { analyzePatch } from './patch.js'
import { parseTar } from './tarball.js'

const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts'])
const SKIP_DIRS = new Set(['node_modules', '.git', '.DS_Store', '.hg', '.svn'])

const DEFAULTS = {
  maxFileKb: 256,
  maxFiles: 2000,
}

/** @typedef {{ rule: string, severity: string, title: string, file: string, line: number, evidence: string, explanation?: string, mitigation?: string }} Finding */

const clip = (s, n = 160) => (s.length > n ? s.slice(0, n - 1) + '…' : s)

/**
 * Audit a virtual file set (path → text). The core pipeline every entry
 * point (directory / tarball / profile) funnels into.
 * @param {{ path: string, text: string }[]} files
 * @param {{ target: string, kind: 'directory' | 'tarball' | 'profile-bundle' | 'virtual', maxFileKb?: number }} meta
 * @returns {object} canonical report value
 */
export function auditVirtualFiles(files, meta) {
  const opts = { ...DEFAULTS, ...meta }
  /** @type {Finding[]} */
  const findings = []
  let codeFiles = 0
  let totalBytes = 0
  let skipped = 0

  const rootPkg = pickRoot(files, 'package.json')
  const patchFile = pickPatch(files, rootPkg)

  // ---- manifest ----------------------------------------------------------
  let manifest = null
  if (!rootPkg) {
    findings.push(mkFinding('PKG-NO-MANIFEST', 'high', 'No package.json found', meta.target, 0, 'Not an npm package layout; cannot verify what you would install.'))
  } else {
    try {
      manifest = JSON.parse(rootPkg.text)
    } catch (err) {
      findings.push(mkFinding('PKG-UNPARSEABLE', 'high', 'package.json is not valid JSON', rootPkg.path, 0, String(err).slice(0, 120)))
    }
    if (manifest) {
      for (const rule of MANIFEST_RULES) {
        const evidence = rule.check(manifest)
        if (evidence) findings.push(mkFinding(rule.id, rule.severity, rule.title, rootPkg.path, 0, evidence))
      }
      // cross-check: does the patch file referenced by dsh.bundle exist?
      const declared = manifest?.dsh?.bundle?.patch
      if (declared && typeof declared === 'string') {
        const resolved = normalizeIn(declared, files)
        if (!resolved) findings.push(mkFinding('PKG-PATCH-MISSING', 'medium', 'dsh.bundle.patch points to a file that is not shipped', rootPkg.path, 0, declared))
      }
    }
  }

  // ---- patch layer ---------------------------------------------------------
  if (patchFile) {
    for (const f of analyzePatch(patchFile.text, patchFile.path)) {
      findings.push(mkFinding(f.rule, f.severity, f.title, patchFile.path, f.line ?? 0, f.evidence, f.explanation))
    }
  }

  // ---- code scan -----------------------------------------------------------
  for (const file of files) {
    const ext = path.posix.extname(file.path)
    totalBytes += file.text.length
    if (!CODE_EXT.has(ext)) continue
    if (file.text.length > opts.maxFileKb * 1024) {
      skipped++
      findings.push(mkFinding('AUDIT-FILE-SKIPPED', 'info', `File exceeds scan cap (${opts.maxFileKb} KB)`, file.path, 0, 'scanned as unreviewable'))
      continue
    }
    if (file.text.includes('\0')) { skipped++; continue }
    codeFiles++

    const stripped = stripSource(file.text)
    const mods = extractModules(stripped)
    if (mods.dynamicRequires > 0) {
      findings.push(mkFinding('JS-DYNAMIC-REQUIRE', 'low', `${mods.dynamicRequires} dynamic require call(s)`, file.path, 0, 'module resolved only at runtime'))
    }

    for (const { n, code, raw } of stripped.lines) {
      for (const rule of CODE_RULES) {
        const subject = rule.on === 'raw' ? raw : code
        if (rule.pattern.test(subject)) {
          findings.push(mkFinding(rule.id, rule.severity, rule.title, file.path, n, clip(subject.trim()), rule.explanation, rule.mitigation))
        }
      }
    }
    // multi-line imports (`import {\n x\n} from 'mod'`) only match when joined
    const joinedRaw = stripped.lines.map((l) => l.raw).join('\n')
    for (const rule of CODE_RULES) {
      if (rule.on !== 'raw') continue
      const perLineHit = stripped.lines.some((l) => rule.pattern.test(l.raw))
      if (perLineHit) continue
      if (rule.pattern.test(joinedRaw)) {
        const anchor = stripped.lines.find((l) => /(?:from\s*['"]|require\s*\(\s*['"]|import\s*['"]|import\s*\()/.test(l.raw))
        findings.push(mkFinding(rule.id, rule.severity, rule.title, file.path, anchor?.n ?? 0, clip(joinedRaw.replace(/\s+/g, ' ')), rule.explanation, rule.mitigation))
      }
    }
    for (const lit of stripped.literals) {
      for (const rule of LITERAL_RULES) {
        if (lit.kind === 'regex') continue
        if (rule.test(lit.text)) {
          findings.push(mkFinding(rule.id, rule.severity, rule.title, file.path, lit.line, clip(lit.text), rule.explanation ?? '', rule.mitigation ?? ''))
        }
      }
    }
  }

  // ---- tarball structural hazards (symlinks / traversal) --------------------
  if (meta.kind === 'tarball' && meta.entries) {
    for (const e of meta.entries) {
      if (e.kind === 'symlink') {
        findings.push(mkFinding('TAR-SYMLINK', 'high', `Archive contains a symlink: ${e.name} → ${e.linkname ?? '?'}`, e.name, 0, 'symlinks in plugin packages can redirect writes outside the install dir'))
      }
      if (e.name.split('/').includes('..')) {
        findings.push(mkFinding('TAR-PATH-TRAVERSAL', 'critical', `Archive entry escapes its directory: ${e.name}`, e.name, 0, 'a path with .. can write outside the extraction target'))
      }
    }
    for (const w of meta.warnings ?? []) {
      findings.push(mkFinding('TAR-WARNING', 'low', 'Archive anomaly', '(archive)', 0, w))
    }
  }

  // ---- combos ---------------------------------------------------------------
  const fired = new Set(findings.map((f) => f.rule))
  for (const combo of COMBO_RULES) {
    const satisfied = combo.requires.every((alt) => alt.split('|').some((r) => fired.has(r)))
    if (satisfied) {
      findings.push(mkFinding(combo.id, combo.severity, combo.title, '(combined capabilities)', 0, combo.requires.join(' + '), combo.explanation))
    }
  }

  // ---- score -----------------------------------------------------------------
  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line)
  const { score, bySeverity, verdict } = scoreFindings(findings)
  const summary = buildSummary(verdict, bySeverity, findings)

  return {
    target: meta.target,
    kind: meta.kind,
    verdict,
    score,
    summary,
    bySeverity,
    stats: { files: files.length, codeFiles, bytes: totalBytes, skipped },
    findings,
  }
}

function mkFinding(rule, severity, title, file, line, evidence, explanation, mitigation) {
  return { rule, severity, title, file, line, evidence: String(evidence ?? ''), explanation: explanation ?? '', mitigation: mitigation ?? '' }
}

function pickRoot(files, name) {
  const candidates = files.filter((f) => f.path === name || f.path.endsWith('/' + name))
  if (candidates.length === 0) return null
  // shallowest path wins (npm tarballs root everything under package/)
  return candidates.sort((a, b) => a.path.length - b.path.length)[0]
}

function pickPatch(files, rootPkg) {
  const declared = (() => {
    try { return rootPkg ? JSON.parse(rootPkg.text)?.dsh?.bundle?.patch : null } catch { return null }
  })()
  const byName = (n) => files.find((f) => f.path === n || f.path.endsWith('/' + n)) ?? null
  if (typeof declared === 'string') {
    const hit = files.find((f) => normalizePath(f.path) === normalizePath(joinVirtual(dirnameVirtual('/' + f.path), declared)))
    if (hit) return hit
  }
  return byName('cordis.patch.yml') ?? files.find((f) => /cordis.*\.ya?ml$|\.patch\.ya?ml$/.test(f.path)) ?? null
}

const normalizePath = (p) => p.replace(/^\.\//, '').replace(/\/+/g, '/')
const dirnameVirtual = (p) => p.slice(0, p.lastIndexOf('/'))
const joinVirtual = (dir, rel) => (rel.startsWith('/') ? rel : `${dir}/${rel}`)
const normalizeIn = (declared, files) =>
  files.some((f) => {
    const dir = dirnameVirtual('/' + f.path)
    return normalizePath(f.path) === normalizePath(declared) || normalizePath(f.path) === normalizePath(joinVirtual(dir, declared)).slice(1)
  })

function buildSummary(verdict, bySeverity, findings) {
  const parts = SEVERITY_ORDER.filter((s) => bySeverity[s] > 0).map((s) => `${bySeverity[s]} ${s}`)
  if (parts.length === 0) return '未发现任何风险特征（仅代表静态可见面，不含运行时行为）。'
  const head = verdict === 'block' ? '建议拒绝安装' : verdict === 'review' ? '安装前需人工审查' : '存在低风险特征'
  return `${head}：${parts.join('、')}。首要问题：${findings[0].title}。`
}

// ---------------------------------------------------------------------------
// Entry point: directory
// ---------------------------------------------------------------------------

/**
 * @param {string} dir absolute or cwd-relative directory
 * @param {{ maxFileKb?: number }} [options]
 */
export async function auditDirectory(dir, options = {}) {
  /** @type {{ path: string, text: string }[]} */
  const files = []
  const root = path.resolve(dir)
  await walk(root, '', files, options, 0)
  return auditVirtualFiles(files, { target: root, kind: 'directory', ...options })
}

async function walk(root, rel, files, options, depth) {
  if (depth > 12) return
  const abs = path.join(root, rel)
  const dirents = await readdir(abs, { withFileTypes: true })
  for (const d of dirents) {
    if (SKIP_DIRS.has(d.name)) continue
    const relPath = rel ? `${rel}/${d.name}` : d.name
    const absPath = path.join(abs, d.name)
    if (d.isDirectory()) {
      await walk(root, relPath, files, options, depth + 1)
    } else if (d.isFile()) {
      if (files.length >= (options.maxFiles ?? DEFAULTS.maxFiles)) return
      const buf = await readFile(absPath)
      if (buf.includes(0)) continue // binary
      files.push({ path: relPath, text: buf.toString('utf8') })
    }
  }
}

// ---------------------------------------------------------------------------
// Entry point: tarball (in-memory)
// ---------------------------------------------------------------------------

/**
 * @param {Uint8Array} bytes
 * @param {string} targetName
 * @param {{ maxFileKb?: number }} [options]
 */
export function auditTarballBytes(bytes, targetName, options = {}) {
  const { entries, warnings } = parseTar(bytes)
  // strip the common leading directory (npm packs use "package/")
  const files = entries
    .filter((e) => e.kind === 'file')
    .map((e) => ({ path: e.name.replace(/^package\//, ''), text: new TextDecoder('utf-8').decode(e.data) }))
  if (files.length === 0) {
    return {
      target: targetName,
      kind: 'tarball',
      verdict: 'review',
      score: 0,
      summary: '压缩包内没有可审计的文本文件（可能是二进制包或空包）。',
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      stats: { files: 0, codeFiles: 0, bytes: 0, skipped: 0 },
      findings: [mkFinding('TAR-NO-TEXT', 'medium', 'Archive contains no auditable text files', '(archive)', 0, 'nothing to review statically')],
    }
  }
  return auditVirtualFiles(files, { target: targetName, kind: 'tarball', entries, warnings, ...options })
}

// ---------------------------------------------------------------------------
// Entry point: installed profile
// ---------------------------------------------------------------------------

/**
 * Audit every out-of-tree bundle installed in a profile.
 * @param {string} profileDir absolute path to $DSH_HOME/profiles/<name>
 */
export async function auditProfile(profileDir, options = {}) {
  const profilePath = path.resolve(profileDir)
  const manifestPath = path.join(profilePath, 'package.json')
  /** @type {{ name: string, verdict: string, score: number, summary: string, report?: object, error?: string }[]} */
  const bundles = []
  let manifest = null
  try {
    manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  } catch (err) {
    return {
      profile: profilePath,
      overallVerdict: 'error',
      summary: `无法读取 profile manifest：${String(err).slice(0, 120)}`,
      bundles,
    }
  }

  const list = Array.isArray(manifest?.dsh?.profile?.bundles) ? manifest.dsh.profile.bundles : []
  const require = createRequire(manifestPath)

  for (const name of list) {
    if (typeof name !== 'string') continue
    if (name.startsWith('@deepseek-ai/') || name === '@deepseek-ai/dsh-base') {
      bundles.push({ name, verdict: 'trusted', score: 0, summary: '官方内置 bundle，随 dsh 安装分发，跳过（源代码即官方仓库）。' })
      continue
    }
    try {
      const pkgJsonPath = require.resolve(`${name}/package.json`)
      const bundleDir = path.dirname(pkgJsonPath)
      const report = await auditDirectory(bundleDir, options)
      bundles.push({ name, verdict: report.verdict, score: report.score, summary: report.summary, report })
    } catch (err) {
      bundles.push({ name, verdict: 'error', score: 0, summary: `无法解析该 bundle：${String(err).slice(0, 120)}` })
    }
  }

  const worst = bundles.reduce((acc, b) => {
    const rank = { block: 4, error: 3, review: 2, pass: 1, trusted: 0 }
    return Math.max(acc, rank[b.verdict] ?? 0)
  }, 0)
  const overallVerdict = ['pass', 'review', 'error', 'review', 'block'][worst] ?? 'pass'
  const flagged = bundles.filter((b) => b.verdict === 'block' || b.verdict === 'review')
  const summary = flagged.length === 0
    ? `profile 内 ${bundles.length} 个 bundle 均未发现问题。`
    : `${flagged.length}/${bundles.length} 个 bundle 需要处理：${flagged.map((b) => `${b.name}(${b.verdict})`).join('、')}。`

  return { profile: profilePath, overallVerdict, summary, bundles }
}

/**
 * Resolve the DSH home directory the same way the harness does:
 * `$DSH_HOME`, else `~/.dsh`.
 */
export function resolveDshHome() {
  return process.env.DSH_HOME ? path.resolve(process.env.DSH_HOME) : path.join(os.homedir(), '.dsh')
}
