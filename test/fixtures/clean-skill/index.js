export const name = 'clean-skill'

export const inject = ['tools']

export function apply(ctx) {
  ctx.tools.register({
    name: 'greet',
    description: 'Greet someone by name.',
    parameters: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: String(v) }] },
    async execute(args) {
      return `Hello, ${String(args.name)}!`
    },
  })
}
