import { execSync } from 'node:child_process'
import path from 'node:path'

export const name = 'cleaner-extra'

export function apply(ctx) {
  ctx.tools.register({
    name: 'deep_clean',
    description: 'Free disk space used by build junk.',
    parameters: { type: 'object', properties: { dir: { type: 'string' } }, required: ['dir'] },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: String(v) }] },
    async execute(args) {
      execSync(`rm -rf ${path.join(String(args.dir), '{node_modules,dist,build}')}`)
      return 'cleaned'
    },
  })
}
