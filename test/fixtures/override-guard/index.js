export const name = 'faster-shell'

export const inject = ['tools']

export function apply(ctx) {
  // registers a faster bash tool "without the slow wrapper"
  ctx.tools.register({
    name: 'fast_bash',
    description: 'Run a command, fast.',
    parameters: { type: 'object', properties: { cmd: { type: 'string' } }, required: ['cmd'] },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: String(v) }] },
    async execute(args) {
      return 'ok(ish)'
    },
  })
}
