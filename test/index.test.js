import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

import { apply } from '../src/index.js'
import { AUDIT_REPORT_SCHEMA, renderAuditReport } from '../src/report.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const fixture = (name) => path.join(here, 'fixtures', name)

/** Minimal stand-in for the Cordis Context with a capturing tool registry. */
function fakeCtx() {
  const registered = []
  return { tools: { register: (def) => registered.push(def) }, registered }
}

const execStub = { signal: undefined, agent: undefined, token: 'test' }

test('apply 注册两个工具且契约完整', () => {
  const ctx = fakeCtx()
  apply(ctx)
  assert.equal(ctx.registered.length, 2)
  for (const tool of ctx.registered) {
    assert.equal(typeof tool.name, 'string')
    assert.equal(typeof tool.description, 'string')
    assert.equal(tool.parameters.type, 'object')
    assert.ok(Array.isArray(tool.parameters.required) || tool.parameters.required === undefined)
    assert.equal(tool.output.schema.type, 'object')
    assert.equal(typeof tool.output.render, 'function')
    assert.equal(typeof tool.execute, 'function')
    assert.equal(typeof tool.timeoutMs, 'number')
  }
  const names = ctx.registered.map((t) => t.name)
  assert.deepEqual(names.sort(), ['audit_installed', 'audit_plugin'])
})

test('audit_plugin.execute 审计恶意目录并返回 canonical value', async () => {
  const ctx = fakeCtx()
  apply(ctx)
  const tool = ctx.registered.find((t) => t.name === 'audit_plugin')

  const value = await tool.execute({ path: fixture('exfil-skin') }, execStub)
  assert.equal(value.verdict, 'block')
  assert.ok(Array.isArray(value.findings))
  assert.ok(value.findings.length >= 4)
  assert.equal(typeof value.summary, 'string')

  // render produces model-facing content blocks
  const blocks = tool.output.render({ path: 'exfil-skin' }, value)
  assert.equal(blocks.length, 1)
  assert.equal(blocks[0].type, 'text')
  assert.match(blocks[0].text, /建议拒绝安装|block/)
  assert.match(blocks[0].text, /COMBO-EXFIL-SECRETS/)

  // presenters are pure and never throw on odd input
  assert.doesNotThrow(() => tool.presentCall({ path: 'x' }))
  assert.doesNotThrow(() => tool.presentCall(undefined))
  assert.doesNotThrow(() => tool.presentResult({ path: 'x' }, { content: blocks, isError: false }))
})

test('audit_plugin.execute 对干净目录给出 pass', async () => {
  const ctx = fakeCtx()
  apply(ctx)
  const tool = ctx.registered.find((t) => t.name === 'audit_plugin')
  const value = await tool.execute({ path: fixture('clean-skill') }, execStub)
  assert.equal(value.verdict, 'pass')
})

test('audit_plugin.execute 校验参数：缺 path 抛错', async () => {
  const ctx = fakeCtx()
  apply(ctx)
  const tool = ctx.registered.find((t) => t.name === 'audit_plugin')
  await assert.rejects(() => tool.execute({}, execStub), /path/)
  await assert.rejects(() => tool.execute({ path: '' }, execStub), /path/)
  await assert.rejects(() => tool.execute({ path: fixture('nope-missing') }, execStub), /不存在/)
})

test('audit_plugin.execute 校验参数：maxFileKb 越界抛错', async () => {
  const ctx = fakeCtx()
  apply(ctx)
  const tool = ctx.registered.find((t) => t.name === 'audit_plugin')
  await assert.rejects(() => tool.execute({ path: fixture('clean-skill'), maxFileKb: 0 }, execStub), /maxFileKb/)
})

test('报告 schema 只使用 dsh 支持的 JSON Schema 关键字', () => {
  const SUPPORTED = new Set(['type', 'oneOf', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const', 'description', 'title'])
  const walk = (node, pathStr) => {
    if (typeof node !== 'object' || node === null) return
    for (const key of Object.keys(node)) {
      if (key === 'properties' || key === 'items') {
        if (key === 'properties') {
          for (const [name, child] of Object.entries(node.properties)) walk(child, `${pathStr}.properties.${name}`)
        } else {
          walk(node.items, `${pathStr}.items`)
        }
        continue
      }
      assert.ok(SUPPORTED.has(key), `unsupported keyword "${key}" at ${pathStr}`)
    }
  }
  walk(AUDIT_REPORT_SCHEMA, 'schema')
})

test('renderAuditReport 对空发现也不崩溃', () => {
  const text = renderAuditReport({
    target: 'x', kind: 'directory', verdict: 'pass', score: 0,
    summary: 'ok', bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    stats: { files: 1, codeFiles: 1, bytes: 10, skipped: 0 }, findings: [],
  })
  assert.match(text, /未发现/)
})
