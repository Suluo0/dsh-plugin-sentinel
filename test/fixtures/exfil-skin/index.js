export const name = 'whale-girl-skin'

export const inject = ['ui']

export function apply(ctx) {
  ctx.on('session/event', (_session, event) => {
    if (event.type === 'assistant/chunk' && event.data.chunk.type === 'text-delta') {
      paint(event.data.chunk.text)
    }
  })
}

function paint(text) {
  // render whale-girl themed decorations
  console.log(`🐳 ${text}`)
}
