/**
 * dsh-plugin-sentinel — 插件安检机 / static security auditor for DSH plugins.
 *
 * Registers two model-facing tools through the RAW JSON-Schema
 * ToolDefinition path (the same one MCP-sourced tools use), so this package
 * imports nothing beyond Node built-ins and its own modules:
 *
 *   audit_plugin    audit a plugin directory or .tgz before installing it
 *   audit_installed audit every out-of-tree bundle in a profile
 *
 * The auditor never executes, installs, or writes anything it looks at.
 */

import path from 'node:path'
import { readFile, stat } from 'node:fs/promises'

import { auditDirectory, auditTarballBytes, auditProfile, resolveDshHome } from './audit.js'
import { AUDIT_REPORT_SCHEMA, PROFILE_REPORT_SCHEMA, renderAuditReport, renderProfileReport } from './report.js'

export const name = 'dsh-plugin-sentinel'
export const inject = ['tools']

const TARBALL_RE = /\.(?:tgz|tar(?:\.gz)?)$/

export function apply(ctx) {
  ctx.tools.register({
    name: 'audit_plugin',
    description:
      '在安装一个 DSH 插件（bundle）之前对其进行静态安全审计。传入插件源码目录或 .tgz 压缩包的本地路径，' +
      '返回按严重度排序的风险报告（安装期脚本、动态执行、凭据读取、网络外传、patch 层 !!js 表达式、静默禁用安全行等）。' +
      '当用户要求安装、下载或评估任何社区插件时先调用本工具；verdict=block 时不要安装并向用户说明风险。' +
      '本工具只读取、绝不执行被审计代码。tarball 审计全程在内存中完成，不落盘。',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string', description: '插件目录或 .tgz 文件的路径（相对当前工作目录或绝对路径）' },
        maxFileKb: { type: 'number', description: '单个文件的最大扫描体积（KB），超过则标记为不可审计，默认 256' },
      },
      required: ['path'],
      additionalProperties: false,
    },
    output: {
      schema: AUDIT_REPORT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: renderAuditReport(value) }],
    },
    timeoutMs: 120_000,
    isConcurrencySafe: () => true,
    presentCall: (args) => ({
      card: 'generic',
      title: `sentinel 审计 ${typeof args?.path === 'string' ? args.path : '?'}`,
      kind: 'search',
    }),
    presentResult: (args, result) => ({
      card: 'generic',
      title: `sentinel 审计 ${typeof args?.path === 'string' ? args.path : '?'} — ${summaryOf(result)}`,
      content: result?.content ?? undefined,
    }),
    async execute(args, exec) {
      const target = requireString(args, 'path')
      const options = {}
      if (args?.maxFileKb != null) {
        if (typeof args.maxFileKb !== 'number' || args.maxFileKb < 1 || args.maxFileKb > 10240) {
          throw new Error('maxFileKb must be a number between 1 and 10240')
        }
        options.maxFileKb = args.maxFileKb
      }

      const resolved = path.resolve(process.cwd(), target)
      const st = await stat(resolved).catch(() => null)
      if (!st) throw new Error(`路径不存在：${resolved}（如果是远程仓库，请先让用户克隆或下载到本地再审计）`)

      if (st.isDirectory()) {
        return await auditDirectory(resolved, options)
      }
      if (st.isFile() && TARBALL_RE.test(resolved)) {
        const bytes = new Uint8Array(await readFile(resolved))
        return auditTarballBytes(bytes, target, options)
      }
      throw new Error(`既不是目录也不是 .tgz/.tar 压缩包：${resolved}`)
    },
  })

  ctx.tools.register({
    name: 'audit_installed',
    description:
      '巡检当前（或指定）DSH profile 中已安装的全部社区插件 bundle，逐个输出静态安全审计结论。' +
      '当用户想确认"我装过的插件安不安全"、安装完成之后、或定期安全巡检时使用。官方内置 bundle（@deepseek-ai/*）会标记为 trusted 并跳过。',
    parameters: {
      type: 'object',
      properties: {
        profile: { type: 'string', description: 'profile 名称（默认 default），也可以直接传 profile 目录的绝对路径' },
        maxFileKb: { type: 'number', description: '单个文件的最大扫描体积（KB），默认 256' },
      },
      additionalProperties: false,
    },
    output: {
      schema: PROFILE_REPORT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: renderProfileReport(value) }],
    },
    timeoutMs: 300_000,
    isConcurrencySafe: () => true,
    presentCall: () => ({ card: 'generic', title: 'sentinel profile 巡检', kind: 'search' }),
    presentResult: (_args, result) => ({
      card: 'generic',
      title: `sentinel profile 巡检 — ${summaryOf(result)}`,
      content: result?.content ?? undefined,
    }),
    async execute(args, exec) {
      const options = {}
      if (args?.maxFileKb != null) {
        if (typeof args.maxFileKb !== 'number' || args.maxFileKb < 1 || args.maxFileKb > 10240) {
          throw new Error('maxFileKb must be a number between 1 and 10240')
        }
        options.maxFileKb = args.maxFileKb
      }

      const raw = typeof args?.profile === 'string' && args.profile.trim() !== '' ? args.profile.trim() : 'default'
      const profileDir = path.isAbsolute(raw) ? raw : path.join(resolveDshHome(), 'profiles', raw)
      const report = await auditProfile(profileDir, options)
      // auditProfile resolves errors into per-bundle entries; surface manifest failure as isError
      if (report.overallVerdict === 'error' && report.bundles.length === 0) {
        throw new Error(report.summary)
      }
      return report
    },
  })

  console.log('[dsh-plugin-sentinel] loaded — tools: audit_plugin, audit_installed')
}

// raw ToolDefinitions own their input validation
function requireString(args, key) {
  const v = args?.[key]
  if (typeof v !== 'string' || v.trim() === '') throw new Error(`缺少必填参数 ${key}（非空字符串）`)
  return v.trim()
}

function summaryOf(result) {
  // presentResult is pure: derive a short title from the rendered content only
  const first = result?.content?.[0]
  if (first?.type === 'text') {
    const m = first.text.match(/🚫|⚠️|✅/)
    if (m) return m[0]
  }
  return ''
}
