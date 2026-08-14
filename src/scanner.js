/**
 * Lexical surface scanner — zero dependencies.
 *
 * `stripSource` produces, per line, TWO projections of the source:
 *
 *   code — comments removed, string bodies blanked, regex literals blanked.
 *          Pattern rules run here so quoted or commented text can never
 *          produce false positives. Code inside template `${…}`
 *          interpolations STAYS visible so hidden code cannot slip through.
 *   raw  — comments removed but string bodies kept.
 *          Import-specifier rules run here: `import '…'` / `require('…')`
 *          carry their payload inside quotes, so those patterns need the
 *          contents — and they are anchored on import syntax, which keeps
 *          them safe against ordinary strings.
 *
 * String literals are additionally collected (text + line + kind) for
 * literal-level rules: URLs, opaque blobs, sensitive paths.
 *
 * State machine (explicit stacks, no recursion):
 *   CODE / LINE_COMMENT / BLOCK_COMMENT / SINGLE / DOUBLE / TEMPLATE.
 *   Inside TEMPLATE, `${` pushes an interpolation frame; its code is scanned
 *   as CODE (including nested strings) until its matching `}`.
 */

/**
 * @typedef {object} Literal
 * @property {number} line    — 1-based line of the opening quote
 * @property {string} text    — literal contents (no quotes)
 * @property {'single'|'double'|'template'} kind
 */

/**
 * @typedef {object} StrippedLine
 * @property {number} n       — 1-based line number
 * @property {string} code    — comments gone, string bodies blanked
 * @property {string} raw     — comments gone, string bodies kept
 */

/**
 * @typedef {object} StrippedSource
 * @property {StrippedLine[]} lines
 * @property {Literal[]} literals
 */

/**
 * @param {string} text
 * @returns {StrippedSource}
 */
export function stripSource(text) {
  /** @type {StrippedLine[]} */
  const lines = []
  /** @type {Literal[]} */
  const literals = []

  let line = 1
  let out = ''        // code projection of the current line
  let raw = ''        // raw projection of the current line
  let litText = ''
  let litKind = 'double'
  let litLine = 1

  const interpStack = []   // brace depth of each open ${ … }
  const templateStack = [] // open template literals
  let inBlockComment = false

  const emit = (ch) => { out += ch; raw += ch }
  const blank = () => { out += ' '; raw += ' ' }

  const pushLine = () => {
    lines.push({ n: line, code: out, raw })
    out = ''
    raw = ''
  }

  const beginLiteral = (kind) => {
    litKind = kind
    litText = ''
    litLine = line
  }

  const endLiteral = () => {
    if (litText !== '') literals.push({ line: litLine, text: litText, kind: litKind })
    litText = ''
  }

  const prevSignificant = () => {
    for (let i = out.length - 1; i >= 0; i--) {
      if (!/\s/.test(out[i])) return out[i]
    }
    return '\n'
  }

  /** A `/` starts a regex (not division) unless the previous significant char can end an expression. */
  const regexAllowed = () => !/[A-Za-z0-9_$)\]'"`]/.test(prevSignificant())

  /** Consume a regex literal starting at i; returns true if one was found. */
  const tryRegex = () => {
    let j = i + 1
    let inClass = false
    while (j < n && text[j] !== '\n') {
      const cj = text[j]
      if (cj === '\\') { j += 2; continue }
      if (cj === '[') inClass = true
      else if (cj === ']') inClass = false
      else if (cj === '/' && !inClass) {
        let k = j + 1
        while (k < n && /[a-z]/i.test(text[k])) k++
        const after = text[k]
        if (after === undefined || /[\s,;)\]}>.:?!&|=(]/.test(after) || k === n) {
          // blank the whole literal in both projections
          for (let s = i; s < k; s++) blank()
          return k
        }
        return null
      }
      j++
    }
    return null
  }

  let i = 0
  const n = text.length
  while (i < n) {
    const ch = text[i]
    const next = text[i + 1]

    // ---- comments (CODE only) ---------------------------------------------
    if (!inBlockComment && ch === '/' && next === '/') {
      i += 2
      while (i < n && text[i] !== '\n') i++
      continue
    }
    if (!inBlockComment && ch === '/' && next === '*') {
      inBlockComment = true
      blank(); blank()
      i += 2
      continue
    }
    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false
        blank(); blank()
        i += 2
      } else {
        if (ch === '\n') { pushLine(); line++ } else blank()
        i++
      }
      continue
    }

    // ---- template chunk consumption (must precede the open-backtick check,
    //      or a CLOSING backtick would open a second template) ----------------
    if (templateStack.length > 0 && interpStack.length === 0) {
      const c = text[i]
      if (c === '\\') { litText += text[i + 1] ?? ''; raw += c; raw += text[i + 1] ?? ''; i += 2; continue }
      if (c === '`') {
        endLiteral()
        templateStack.pop()
        emit('`')
        i++
        continue
      }
      if (c === '$' && next === '{') {
        endLiteral()
        emit('$'); emit('{')
        interpStack.push(0)
        i += 2
        continue
      }
      if (c === '\n') {
        // a template may span lines; keep per-line chunks as separate literals
        endLiteral()
        pushLine()
        line++
        beginLiteral('template')
        i++
        continue
      }
      litText += c
      raw += c
      i++
      continue
    }

    // ---- open a template literal --------------------------------------------
    if (interpStack.length === 0 && ch === '`') {
      templateStack.push(0)
      beginLiteral('template')
      emit('`')
      i++
      continue
    }

    // ---- strings (top-level code and inside ${…}; NOT inside template chunks)
    if (ch === "'" || ch === '"') {
      const quote = ch
      beginLiteral(quote === "'" ? 'single' : 'double')
      emit(quote)
      i++
      while (i < n) {
        const c = text[i]
        if (c === '\\') {
          litText += text[i + 1] === '\n' ? '' : text[i + 1]
          raw += c
          raw += text[i + 1] ?? ''
          i += 2
          continue
        }
        if (c === quote || c === '\n') break
        litText += c
        raw += c
        i++
      }
      emit(quote)
      if (text[i] === quote) i++ // newline terminators fall through to the newline branch
      endLiteral()
      continue
    }

    // ---- interpolation brace tracking ---------------------------------------
    if (interpStack.length > 0) {
      if (ch === '{') interpStack[interpStack.length - 1]++
      if (ch === '}') {
        if (interpStack[interpStack.length - 1] === 0) {
          interpStack.pop()
          emit('}')
          i++
          beginLiteral('template') // resume the surrounding template chunk
          continue
        }
        interpStack[interpStack.length - 1]--
      }
    }

    // ---- regex vs division ----------------------------------------------------
    if (ch === '/') {
      if (regexAllowed()) {
        const end = tryRegex()
        if (end !== null) { i = end; continue }
      }
      emit(ch)
      i++
      continue
    }

    // ---- default --------------------------------------------------------------
    if (ch === '\n') {
      pushLine()
      line++
      i++
      continue
    }
    emit(ch)
    i++
  }

  endLiteral()
  pushLine()

  return { lines, literals }
}

/**
 * Extract module specifiers from the raw projection: static import,
 * `require('x')`, dynamic `import('x')`.
 * @param {StrippedSource} src
 * @returns {{ specifiers: string[], dynamicRequires: number }}
 */
export function extractModules(src) {
  const specifiers = new Set()
  let dynamicRequires = 0
  const importRe = /import\s+[^;'"]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]/g
  const requireRe = /require\s*\(\s*['"]([^'"]+)['"]\s*\)|import\s*\(\s*['"]([^'"]+)['"]\s*\)/g
  const dynRe = /\brequire\s*\(\s*[^'")\s]/g
  for (const { raw } of src.lines) {
    for (const m of raw.matchAll(importRe)) specifiers.add(m[1] ?? m[2])
    for (const m of raw.matchAll(requireRe)) specifiers.add(m[1] ?? m[2])
    dynamicRequires += raw.match(dynRe)?.length ?? 0
  }
  return { specifiers: [...specifiers], dynamicRequires }
}
