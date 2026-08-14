/**
 * cordis.patch.yml analyzer.
 *
 * The patch semantics (verified against vendor/include/src/index.ts in the
 * deepseek-harness repo) are:
 *
 *   - insert: [rows]      add plugin rows
 *   - id: <target>        target an existing row; sibling keys override its
 *                         fields — config, inject, and critically
 *                         disabled: true, which silently switches a row off
 *   - name: <value>       optional guard: must match the target row's name
 *
 * `!!js` expressions inside config values execute at plugin-load time in the
 * row's own fiber context, which makes them arbitrary host-side code.
 *
 * We do NOT bring in a YAML dependency: patch files are a small, documented
 * subset, so a tolerant line-based structural parser is enough — and for the
 * `!!js` check we scan raw text after stripping comments, so it works even if
 * structural parsing degrades.
 */

import { PROTECTED_ROW_KEYWORDS } from './rules.js'

/**
 * @typedef {object} PatchFinding
 * @property {string} rule
 * @property {string} severity
 * @property {string} title
 * @property {string} evidence
 * @property {string} [explanation]
 * @property {number} line
 */

const PROTECTED_RE = new RegExp(`(?:${PROTECTED_ROW_KEYWORDS.join('|')})`, 'i')

/** Strip YAML comments (full-line and naive inline ` #`) from raw text. */
function stripYamlComments(text) {
  return text
    .split('\n')
    .map((l) => {
      const t = l.trimStart()
      if (t.startsWith('#')) return ''
      const q1 = l.indexOf("'")
      const q2 = l.indexOf('"')
      const hash = l.indexOf(' #')
      if (hash >= 0 && (q1 < 0 || hash < q1) && (q2 < 0 || hash < q2)) return l.slice(0, hash)
      return l
    })
    .join('\n')
}

/** Unquote a scalar the way YAML would. */
function scalar(value) {
  const v = value.trim()
  if (v === '' || v === '~' || v === 'null') return null
  if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith('"') && v.endsWith('"'))) {
    return v.slice(1, -1)
  }
  if (v === 'true') return true
  if (v === 'false') return false
  const num = Number(v)
  return Number.isFinite(num) && /^[-+]?\d/.test(v) ? num : v
}

/**
 * Parse the patch subset into ops. Returns `{ ops, parseError }` — parseError
 * is a string when the file does not look like a patch list at all.
 * @param {string} raw
 */
export function parsePatchOps(raw) {
  const lines = stripYamlComments(raw).split('\n')
  /** @type {{kind:'insert', line:number, rows:{id?:string,name?:string}[]}[] | {kind:'override', line:number, id?:string, name?:string, disabled?:boolean, hasConfig?:boolean}[]} */
  const ops = []
  let parseError = null
  let sawTopLevelItem = false

  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    if (line.trim() === '') { i++; continue }

    // top-level list item must start with "- " at column 0
    if (!/^-\s/.test(line) && !sawTopLevelItem) {
      if (line.startsWith(' ') || line.startsWith('\t')) { i++; continue }
      parseError = `unexpected non-list content at line ${i + 1}: ${line.trim().slice(0, 60)}`
      break
    }
    if (!/^-\s/.test(line)) { i++; continue }
    sawTopLevelItem = true

    const itemLine = i + 1
    // keys of this item live at a deeper indent than the dash column
    const keyIndent = line.indexOf('-') + 2
    /** @type {Record<string, unknown>} */
    const item = {}
    // first key may sit on the dash line itself: "- id: foo"
    const inline = line.replace(/^-\s*/, '')
    if (inline.trim() !== '') {
      const m = inline.match(/^([A-Za-z_][\w-]*)(?:\s*:\s*(.*))?$/)
      if (m) item[m[1]] = m[2] === undefined ? null : scalar(m[2])
    }
    i++
    // collect sibling keys (and shallow nested blocks) for this item
    while (i < lines.length) {
      const l = lines[i]
      if (l.trim() === '') { i++; continue }
      const ind = l.length - l.trimStart().length
      if (ind < keyIndent) break
      const m = l.trim().match(/^([A-Za-z_][\w-]*)\s*:\s*(.*)$/)
      if (m) {
        if (m[2] === '') {
          // block value (nested map / list) — record presence only
          item[m[1]] = { __block: true }
          i++
          // skip the block
          while (i < lines.length && (lines[i].trim() === '' || lines[i].length - lines[i].trimStart().length >= ind + 2)) i++
        } else {
          item[m[1]] = scalar(m[2])
          i++
        }
      } else if (l.trim().startsWith('- ') && ind >= keyIndent) {
        if ('insert' in item) break // these are the insert rows — handled below
        i++ // tolerate stray list content
      } else {
        i++
      }
    }

    if ('insert' in item) {
      // count inserted rows: subsequent "- " lines deeper than the item keys
      const rows = []
      while (i < lines.length) {
        const l = lines[i]
        if (l.trim() === '') { i++; continue }
        const ind = l.length - l.trimStart().length
        if (ind < keyIndent || !l.trim().startsWith('- ')) break
        const row = {}
        const first = l.trim().replace(/^-\s*/, '')
        const fm = first.match(/^([A-Za-z_][\w-]*)\s*:\s*(.*)$/)
        if (fm) row[fm[1]] = fm[2] === '' ? { __block: true } : scalar(fm[2])
        i++
        const rowIndent = ind + 2
        while (i < lines.length) {
          const rl = lines[i]
          if (rl.trim() === '') { i++; continue }
          const rind = rl.length - rl.trimStart().length
          if (rind < rowIndent) break
          const rm = rl.trim().match(/^([A-Za-z_][\w-]*)\s*:\s*(.*)$/)
          if (rm) {
            row[rm[1]] = rm[2] === '' ? { __block: true } : scalar(rm[2])
            if (rm[2] === '') {
              i++
              while (i < lines.length && (lines[i].trim() === '' || lines[i].length - lines[i].trimStart().length >= rind + 2)) i++
            } else i++
          } else i++
        }
        rows.push(row)
      }
      ops.push({ kind: 'insert', line: itemLine, rows })
    } else {
      ops.push({
        kind: 'override',
        line: itemLine,
        id: typeof item.id === 'string' ? item.id : undefined,
        name: typeof item.name === 'string' ? item.name : undefined,
        disabled: item.disabled === true,
        hasConfig: 'config' in item,
      })
    }
  }

  if (!sawTopLevelItem && !parseError) parseError = 'no patch entries found'
  return { ops, parseError }
}

/**
 * Analyze a cordis.patch.yml.
 * @param {string} raw
 * @param {string} file
 * @returns {PatchFinding[]}
 */
export function analyzePatch(raw, file) {
  /** @type {PatchFinding[]} */
  const findings = []

  // 1) `!!js` executes at load time — scan comment-stripped raw text with lines
  const stripped = stripYamlComments(raw)
  stripped.split('\n').forEach((l, idx) => {
    if (l.includes('!!js')) {
      findings.push({
        rule: 'PATCH-JS-EXPR',
        severity: 'critical',
        title: 'Executes JS at plugin-load time (!!js config expression)',
        evidence: l.trim().slice(0, 160),
        explanation:
          'A !!js expression in a patch row runs on the HOST when the config tree is composed — before any permission gate, outside every agent sandbox.',
        line: idx + 1,
      })
    }
  })

  // 2) structural analysis
  const { ops, parseError } = parsePatchOps(raw)
  if (parseError) {
    findings.push({
      rule: 'PATCH-UNPARSEABLE',
      severity: 'medium',
      title: 'Patch file could not be parsed structurally',
      evidence: parseError,
      explanation: 'An unusual patch shape deserves a manual read before install.',
      line: 1,
    })
    return findings
  }

  for (const op of ops) {
    if (op.kind === 'override') {
      const target = `${op.id ?? ''}${op.name ? ' ' + op.name : ''}`
      if (op.disabled && PROTECTED_RE.test(target)) {
        findings.push({
          rule: 'PATCH-DISABLE-PROTECTED',
          severity: 'critical',
          title: `Disables a security-relevant row: ${op.id}`,
          evidence: `id: ${op.id}${op.name ? `, name: ${op.name}` : ''}, disabled: true`,
          explanation:
            'Later layers silently switch off earlier rows. Disabling a sandbox/approval/guard row removes protections for every other plugin with no visible error.',
          line: op.line,
        })
      } else if (op.disabled && op.id) {
        findings.push({
          rule: 'PATCH-DISABLE-ROW',
          severity: 'low',
          title: `Disables row: ${op.id}`,
          evidence: `id: ${op.id}, disabled: true`,
          line: op.line,
        })
      }
      if (op.hasConfig && op.id && PROTECTED_RE.test(`${op.id}${op.name ?? ''}`)) {
        findings.push({
          rule: 'PATCH-RECONFIG-PROTECTED',
          severity: 'high',
          title: `Reconfigures a security-relevant row: ${op.id}`,
          evidence: `id: ${op.id} with a config override`,
          explanation: 'A config override replaces the row’s entire config. A sandbox or approval row "reconfigured" this way can be quietly weakened.',
          line: op.line,
        })
      }
    } else {
      for (const row of op.rows) {
        const rowText = `${row.id ?? ''} ${typeof row.name === 'string' ? row.name : ''}`
        if (PROTECTED_RE.test(rowText)) {
          findings.push({
            rule: 'PATCH-INSERT-PROTECTED-NAME',
            severity: 'high',
            title: `Inserts a row named like a security component: ${row.id ?? row.name}`,
            evidence: rowText.trim().slice(0, 160),
            explanation:
              'New rows shadowing security-sounding ids (sandbox/guard/approval) either replace protection or masquerade as it. Verify what this row actually mounts.',
            line: op.line,
          })
        }
      }
    }
  }
  return findings
}
