// A closed SSH receiver must stop export instead of leaving docker save blocked.
export function transferImage(sender, receiver, timeoutMs = 600000) {
  return new Promise((resolve, reject) => {
    let finished = false
    const codes = new Map()
    const cleanup = () => clearTimeout(timer)
    const fail = () => {
      if (finished) return
      finished = true
      cleanup()
      sender.stdout.unpipe(receiver.stdin)
      sender.stdout.resume()
      receiver.stdin.destroy()
      sender.kill()
      receiver.kill()
      reject(new Error('Tested image transfer failed or timed out; exporters stopped and production was not changed'))
    }
    const closed = (name, code) => {
      if (finished) return
      codes.set(name, code)
      if (code !== 0) { fail(); return }
      if (name === 'receiver' && !sender.stdout.readableEnded && !codes.has('sender')) { fail(); return }
      if (codes.size === 2) { finished = true; cleanup(); resolve() }
    }
    const timer = setTimeout(fail, timeoutMs)
    sender.on('error', fail); receiver.on('error', fail)
    sender.on('close', code => closed('sender', code))
    receiver.on('close', code => closed('receiver', code))
    receiver.stdin.on('error', fail)
    sender.stdout.on('error', fail)
    sender.stderr?.resume(); receiver.stderr?.resume(); receiver.stdout?.resume()
    sender.stdout.pipe(receiver.stdin)
  })
}
