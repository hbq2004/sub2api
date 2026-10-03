import { spawn } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const directory = 'D:/Desktop/sub2api/output/site-audit-20261002'
mkdirSync(directory, { recursive: true })
const packages = process.argv.slice(2)
const docker = 'C:/Users/hbq/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe'
const child = spawn(docker, ['run', '--rm', '--network', 'none', '-v', 'D:/Desktop/sub2api:/work', '-v', 'D:/Desktop/sub2api/.gomodcache:/go/pkg/mod', '-v', 'D:/Desktop/sub2api/.gocache:/root/.cache/go-build', '-w', '/work/backend', 'golang:1.27.0-alpine', 'go', 'test', '-json', '-tags=unit', ...packages, '-count=1'], { windowsHide: true })
const output = new Map()
const results = []
let buffer = ''
child.stdout.setEncoding('utf8')
child.stdout.on('data', chunk => {
  buffer += chunk
  while (buffer.includes('\n')) {
    const end = buffer.indexOf('\n')
    const line = buffer.slice(0, end)
    buffer = buffer.slice(end + 1)
    let event
    try { event = JSON.parse(line) } catch { continue }
    const key = `${event.Package}:${event.Test || ''}`
    if (event.Action === 'output') {
      output.set(key, ((output.get(key) || '') + event.Output).slice(-4000))
    }
    if (event.Action === 'pass' || event.Action === 'fail') {
      const record = { package: event.Package, test: event.Test, status: event.Action, elapsed: event.Elapsed }
      if (event.Action === 'fail') {
        record.output = output.get(key) || ''
        console.log(JSON.stringify(record))
      } else if (!event.Test) {
        console.log(`PASS ${event.Package}`)
      }
      results.push(record)
      output.delete(key)
    }
  }
})
child.stderr.on('data', chunk => process.stderr.write(chunk))
child.on('error', error => { console.error(error.message); process.exitCode = 1 })
child.on('close', code => {
  writeFileSync(path.join(directory, 'go-unit-report.json'), JSON.stringify({ passed: code === 0, results }, null, 2))
  console.log(JSON.stringify({ exitCode: code, testsPassed: results.filter(r => r.test && r.status === 'pass').length, testsFailed: results.filter(r => r.test && r.status === 'fail').length }))
  process.exitCode = code || 0
})
