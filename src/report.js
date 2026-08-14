/**
 * Canonical report schema (JSON Schema subset supported by the dsh tools
 * registry: type/oneOf/properties/required/items/enum/const + annotations)
 * and the model-facing Markdown renderer.
 */

export const FINDING_SCHEMA = {
  type: 'object',
  properties: {
    severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'], description: '风险等级' },
    rule: { type: 'string', description: '规则 ID' },
    title: { type: 'string', description: '发现摘要' },
    file: { type: 'string', description: '相关文件（相对包根）' },
    line: { type: 'number', description: '行号，0 表示不适用' },
    evidence: { type: 'string', description: '代码/配置证据摘录' },
    explanation: { type: 'string', description: '为什么这是风险' },
    mitigation: { type: 'string', description: '缓解建议' },
  },
  required: ['severity', 'rule', 'title', 'file', 'line', 'evidence'],
  additionalProperties: false,
}

export const AUDIT_REPORT_SCHEMA = {
  type: 'object',
  properties: {
    target: { type: 'string', description: '被审计对象' },
    kind: { type: 'string', enum: ['directory', 'tarball', 'profile-bundle', 'virtual'] },
    verdict: { type: 'string', enum: ['pass', 'review', 'block'], description: 'pass=通过 / review=需人工审查 / block=建议拒绝' },
    score: { type: 'number', description: '风险分（critical=10/high=5/medium=2/low=1）' },
    summary: { type: 'string', description: '一句话结论' },
    bySeverity: {
      type: 'object',
      properties: {
        critical: { type: 'number' }, high: { type: 'number' }, medium: { type: 'number' }, low: { type: 'number' }, info: { type: 'number' },
      },
      required: ['critical', 'high', 'medium', 'low', 'info'],
    },
    stats: {
      type: 'object',
      properties: {
        files: { type: 'number' }, codeFiles: { type: 'number' }, bytes: { type: 'number' }, skipped: { type: 'number' },
      },
      required: ['files', 'codeFiles', 'bytes', 'skipped'],
    },
    findings: { type: 'array', items: FINDING_SCHEMA, description: '按严重度排序的全部发现' },
  },
  required: ['target', 'kind', 'verdict', 'score', 'summary', 'findings'],
}

export const PROFILE_REPORT_SCHEMA = {
  type: 'object',
  properties: {
    profile: { type: 'string' },
    overallVerdict: { type: 'string', enum: ['pass', 'review', 'error', 'block'] },
    summary: { type: 'string' },
    bundles: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          verdict: { type: 'string', enum: ['pass', 'review', 'block', 'trusted', 'error'] },
          score: { type: 'number' },
          summary: { type: 'string' },
          report: AUDIT_REPORT_SCHEMA,
        },
        required: ['name', 'verdict', 'score', 'summary'],
      },
    },
  },
  required: ['profile', 'overallVerdict', 'summary', 'bundles'],
}

const BANNER = {
  block: '🚫 **建议拒绝安装（block）**',
  review: '⚠️ **安装前需人工审查（review）**',
  pass: '✅ **静态审计通过（pass）**',
  trusted: '✅ 官方内置，跳过',
  error: '❓ 无法解析',
}

const SEVERITY_ICON = {
  critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪',
}

/**
 * Render a single audit report as model-facing Markdown.
 * @param {object} value canonical report
 */
export function renderAuditReport(value) {
  const out = []
  out.push(`## 🔒 Sentinel 审计报告 — ${value.target ?? '(unknown)'}`)
  out.push('')
  out.push(BANNER[value.verdict] ?? value.verdict)
  out.push(`风险分 **${value.score}** ｜ ${describeCounts(value.bySeverity)} ｜ 扫描 ${value.stats?.codeFiles ?? 0} 个代码文件 / ${value.stats?.files ?? 0} 个文件`)
  out.push('')
  out.push(`> ${value.summary}`)
  out.push('')
  if (!value.findings || value.findings.length === 0) {
    out.push('未发现任何静态可见的风险特征。')
    return out.join('\n')
  }
  out.push('| 级别 | 规则 | 位置 | 发现 |')
  out.push('|---|---|---|---|')
  for (const f of value.findings) {
    const loc = `${f.file}${f.line ? ':' + f.line : ''}`
    out.push(`| ${SEVERITY_ICON[f.severity] ?? ''} ${f.severity} | \`${f.rule}\` | ${loc} | ${escapeCell(f.title)} |`)
  }
  out.push('')
  for (const f of value.findings) {
    if (f.severity === 'info') continue
    out.push(`### ${SEVERITY_ICON[f.severity] ?? ''} ${f.rule} — ${f.title}`)
    out.push(`- 位置：\`${f.file}${f.line ? ':' + f.line : ''}\``)
    if (f.evidence) out.push(`- 证据：\`${f.evidence}\``)
    if (f.explanation) out.push(`- 说明：${f.explanation}`)
    if (f.mitigation) out.push(`- 建议：${f.mitigation}`)
    out.push('')
  }
  return out.join('\n')
}

/**
 * Render a profile audit (multiple bundles) as model-facing Markdown.
 * @param {object} value canonical profile report
 */
export function renderProfileReport(value) {
  const out = []
  out.push(`## 🔒 Sentinel Profile 巡检 — ${value.profile}`)
  out.push('')
  out.push(BANNER[value.overallVerdict] ?? value.overallVerdict)
  out.push('')
  out.push(`> ${value.summary}`)
  out.push('')
  out.push('| Bundle | 结论 | 风险分 | 摘要 |')
  out.push('|---|---|---|---|')
  for (const b of value.bundles) {
    out.push(`| ${b.name} | ${b.verdict} | ${b.score} | ${escapeCell(b.summary)} |`)
  }
  const flagged = value.bundles.filter((b) => (b.verdict === 'block' || b.verdict === 'review') && b.report)
  for (const b of flagged) {
    out.push('')
    out.push(renderAuditReport(b.report))
  }
  return out.join('\n')
}

const escapeCell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ').slice(0, 120)

function describeCounts(bySeverity) {
  if (!bySeverity) return ''
  return ['critical', 'high', 'medium', 'low', 'info']
    .filter((k) => bySeverity[k] > 0)
    .map((k) => `${bySeverity[k]} ${k}`)
    .join(' / ') || '无发现'
}
