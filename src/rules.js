/**
 * Rule table for the static audit engine.
 *
 * Every rule matches against *stripped* source (comments and string contents
 * removed) unless `target: 'literal'`, in which case it matches against
 * collected string literals only. This separation is what keeps quoted or
 * commented-out dangerous APIs from producing false positives.
 */

/** @typedef {'critical'|'high'|'medium'|'low'|'info'} Severity */

export const SEVERITY_WEIGHT = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 1,
  info: 0,
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

/**
 * @typedef {object} CodeRule
 * @property {string} id
 * @property {Severity} severity
 * @property {string} title
 * @property {RegExp} pattern           — matched against stripped code lines
 * @property {'code'|'raw'} [on='code'] — 'raw' rules run on the projection that
 *                                         keeps string bodies (import specifiers)
 * @property {string} explanation
 * @property {string} mitigation
 */

/** Rules evaluated per stripped source line. */
export const CODE_RULES = [
  {
    id: 'JS-EXEC-CHILD-PROCESS',
    severity: 'critical',
    title: 'Spawns operating-system processes',
    // `child_process.` 前缀或裸调用才算命中；`foo.exec(`（如 RegExp.prototype.exec）不再误判
    pattern: /\bchild_process\s*\.\s*(?:execSync|spawnSync|execFileSync|execFile|exec|spawn)\s*\(|(?<![.\w$])(?:execSync|spawnSync|execFileSync|execFile|exec|spawn)\s*\(/,
    explanation:
      'The plugin can run arbitrary shell commands. A malicious plugin executes anything on your machine with your user permissions, outside every agent sandbox.',
    mitigation: 'Read every command construction site; reject string-concatenated commands.',
  },
  {
    id: 'JS-EXEC-EVAL',
    severity: 'critical',
    title: 'Dynamic code execution (eval / new Function)',
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(|\brequire\s*\(\s*['"]node:vm['"]\s*\)|\brunIn(?:New)?Context\s*\(|\brunInThisContext\s*\(/,
    explanation:
      'Dynamically evaluated code defeats static review: what you read in the package is not necessarily what runs.',
    mitigation: 'Only acceptable for a documented, input-independent bootstrap; otherwise remove.',
  },
  {
    id: 'JS-IMPORT-CHILD-PROCESS',
    severity: 'high',
    title: 'Imports child_process',
    on: 'raw',
    pattern: /\b(?:import\s+[^;]*?from\s+|require\s*\(\s*|import\s*\(\s*)['"][^'"]*(?:node:)?child_process[^'"]*['"]/,
    explanation: 'Grants the plugin the ability to launch processes even if no call site is visible (dynamic dispatch may hide it).',
    mitigation: 'Confirm every spawned command is user-visible and input-independent.',
  },
  {
    id: 'JS-IMPORT-VM',
    severity: 'high',
    title: 'Imports the vm module',
    on: 'raw',
    pattern: /\b(?:import\s+[^;]*?from\s+|require\s*\(\s*|import\s*\(\s*)['"][^'"]*(?:node:)?vm[^'"]*['"]/,
    explanation: 'The vm module executes strings as code inside this process; vm contexts are not a security boundary.',
    mitigation: 'Remove unless the package documents why scripted evaluation is required.',
  },
  {
    id: 'JS-IMPORT-NET',
    severity: 'medium',
    title: 'Network egress capability',
    on: 'raw',
    pattern: /\b(?:import\s+[^;'"]*?from\s+|require\s*\(\s*|import\s*\(\s*)['"][^'"]*(?:node:)?(?:https?|net|tls|dgram|undici|axios|node-fetch|cross-fetch|got|superagent|request|websocket|ws|puppeteer|playwright)[^'"]*['"]/,
    explanation:
      'The plugin can talk to the outside world. Legitimate for web-search tools, but combined with secret reads (see EXFIL combos) it is the classic exfiltration shape.',
    mitigation: 'Check every destination host; unexplained non-registry domains are disqualifying.',
  },
  {
    id: 'JS-NET-CALL',
    severity: 'medium',
    title: 'Outbound request call',
    pattern: /\bfetch\s*\(|\b(?:https?|net|tls)\s*\.\s*(?:request|get|connect)\s*\(|\bnew\s+WebSocket\s*\(|\bXMLHttpRequest\b/,
    explanation: 'A concrete outbound request site. Where does the data go?',
    mitigation: 'Verify the destination and everything included in the request body.',
  },
  {
    id: 'JS-READ-ENV',
    severity: 'medium',
    title: 'Reads environment variables',
    pattern: /\bprocess\s*\.\s*env\b/,
    explanation:
      'Environment variables carry API keys for every provider configured in DSH. Reading them is legitimate for a model adapter, suspicious anywhere else.',
    mitigation: 'Only provider plugins should need this; whitelist the exact variable names read.',
  },
  {
    id: 'JS-FS-WRITE',
    severity: 'medium',
    title: 'Filesystem writes / process control',
    pattern: /\bfs\s*\.\s*(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|rename|renameSync|truncate|truncateSync)\s*\(|\bprocess\s*\.\s*(?:exit|kill)\s*\(/,
    explanation: 'The plugin modifies files or kills processes. Within the workspace this is normal; outside it, it is destructive capability.',
    mitigation: 'Confirm writes stay inside the workspace and target paths cannot be attacker-controlled.',
  },
  {
    id: 'JS-HOMEDIR',
    severity: 'low',
    title: 'Resolves the user home directory',
    pattern: /\bos\s*\.\s*homedir\s*\(|\bUSERPROFILE\b/,
    explanation: 'Reach beyond the workspace usually aims at dotfiles (credentials, shell history, other tools’ config).',
    mitigation: 'Explain why the plugin needs paths outside its own package.',
  },
]

/**
 * Rules evaluated against collected string literals (contents only).
 * @typedef {object} LiteralRule
 * @property {string} id
 * @property {Severity} severity
 * @property {string} title
 * @property {(text: string) => boolean} test
 */
export const LITERAL_RULES = [
  {
    id: 'STR-SENSITIVE-PATH',
    severity: 'high',
    title: 'References a sensitive path',
    test: (t) => /(?:^|[/~\s:='"(,])\.?(?:ssh|aws|gnupg|gpg|kube|docker|config\/gcloud)[/'\s]|id_rsa|id_ed25519|(?:^|[/\s~:'"(=,])\.env\b|credentials\.(?:json|yaml)|keychain|\.netrc|\.dsh\/\.credentials|\.dsh\/profiles\/[^/]*\/package\.json/i.test(t),
    // (…) paths worth stealing: ssh keys, cloud creds, DSH profile manifests with linked plugins
  },
  {
    id: 'STR-EXTERNAL-URL',
    severity: 'info',
    title: 'Contains a URL',
    test: (t) => /(?:^|["'`\s(])https?:\/\/[^\s"'`]+|(?:^|["'`\s(])wss?:\/\/[^\s"'`]+/i.test(t),
  },
  {
    id: 'STR-LONG-OPAQUE',
    severity: 'medium',
    title: 'Long opaque literal (possible encoded payload)',
    test: (t) => t.length >= 96 && /^[A-Za-z0-9+/=\s]+$/.test(t.replace(/\\n/g, '')),
  },
]

/**
 * Cross-feature combos: capabilities that are individually explainable but
 * damning together. Evaluated after per-file scanning.
 * @typedef {object} ComboRule
 * @property {string} id
 * @property {Severity} severity
 * @property {string} title
 * @property {string[]} requires — rule ids that must ALL have fired
 * @property {string} explanation
 */
export const COMBO_RULES = [
  {
    id: 'COMBO-EXFIL-SECRETS',
    severity: 'critical',
    title: 'Secret read + network egress (exfiltration shape)',
    requires: ['JS-READ-ENV|STR-SENSITIVE-PATH', 'JS-IMPORT-NET|JS-NET-CALL'],
    explanation:
      'The plugin can read credentials (env vars or key files) AND send data out. This pair is the standard shape of a credential stealer, regardless of intent.',
  },
  {
    id: 'COMBO-DECODE-EXEC',
    severity: 'critical',
    title: 'Encoded payload + dynamic execution',
    requires: ['STR-LONG-OPAQUE', 'JS-EXEC-EVAL|JS-IMPORT-VM'],
    explanation:
      'A long encoded blob is decoded and executed at runtime. Static review cannot see what this code does; treat as malicious until proven otherwise.',
  },
  {
    id: 'COMBO-SHELL-EXFIL',
    severity: 'critical',
    title: 'Process spawn + network egress',
    requires: ['JS-EXEC-CHILD-PROCESS|JS-IMPORT-CHILD-PROCESS', 'JS-IMPORT-NET|JS-NET-CALL'],
    explanation:
      'Shell access plus outbound networking lets a plugin run a curl/wget one-liner that no JS-level review will ever catch.',
  },
]

/**
 * package.json manifest rules. Each receives the parsed manifest.
 * @typedef {object} ManifestRule
 * @property {string} id
 * @property {Severity} severity
 * @property {string} title
 * @property {(manifest: any) => string | null} check — returns evidence text, or null
 */
export const MANIFEST_RULES = [
  {
    id: 'PKG-LIFECYCLE-SCRIPTS',
    severity: 'critical',
    title: 'Declares install lifecycle scripts',
    check: (m) => {
      const scripts = m?.scripts ?? {}
      const hit = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'prepublish'].filter((k) => typeof scripts[k] === 'string' && scripts[k].trim() !== '')
      if (hit.length === 0) return null
      return `scripts: ${hit.join(', ')} → ${hit.map((k) => `${k}=${scripts[k]}`).join('; ')}`
    },
  },
  {
    id: 'PKG-NO-DSH-BUNDLE',
    severity: 'medium',
    title: 'Installed as a plugin but declares no dsh.bundle layer',
    check: (m) => (m?.dsh?.bundle ? null : 'package.json has no dsh.bundle declaration; it will load as a plain dependency, or is not really a plugin'),
  },
  {
    id: 'PKG-HAS-DEPENDENCIES',
    severity: 'low',
    title: 'Pulls in runtime dependencies',
    check: (m) => {
      const deps = Object.keys(m?.dependencies ?? {})
      return deps.length === 0 ? null : `${deps.length} runtime dependencies: ${deps.slice(0, 8).join(', ')}${deps.length > 8 ? ', …' : ''}`
    },
  },
]

/** Security-relevant substring list for patch-row ids/names (sandbox/approval/guard…). */
export const PROTECTED_ROW_KEYWORDS = [
  'sandbox', 'approval', 'permission', 'guard', 'policy', 'sandbox-exec',
  'landlock', 'security', 'allowlist', 'denylist',
]

export const VERDICT_RULES = {
  // any critical finding, or a score reaching 10, blocks
  blockScore: 10,
  // any high finding, or a score reaching 5, requires review
  reviewScore: 5,
}

/**
 * Aggregate findings into a verdict + score.
 * @param {{ id: string, severity: Severity }[]} findings
 */
export function scoreFindings(findings) {
  let score = 0
  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]))
  for (const f of findings) {
    score += SEVERITY_WEIGHT[f.severity] ?? 0
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1
  }
  const worst = SEVERITY_ORDER.find((s) => bySeverity[s] > 0) ?? null
  let verdict = 'pass'
  if (bySeverity.critical > 0 || score >= VERDICT_RULES.blockScore) verdict = 'block'
  else if (bySeverity.high > 0 || score >= VERDICT_RULES.reviewScore) verdict = 'review'
  return { score, bySeverity, worst, verdict }
}
