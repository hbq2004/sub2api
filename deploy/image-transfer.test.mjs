import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { transferImage } from './image-transfer.mjs'

function processFixture() {
  const process = new EventEmitter()
  process.stdin = new PassThrough(); process.stdout = new PassThrough(); process.stderr = new PassThrough()
  process.killed = false; process.kill = () => { process.killed = true }
  return process
}
test('completes when export and receiver both succeed', async () => {
  const sender = processFixture(), receiver = processFixture()
  const result = transferImage(sender, receiver)
  sender.stdout.end()
  sender.emit('close', 0); receiver.emit('close', 0)
  await result
  assert.equal(sender.killed, false)
})
test('receiver failure stops the blocked exporter', async () => {
  const sender = processFixture(), receiver = processFixture()
  const result = transferImage(sender, receiver)
  receiver.emit('close', 255)
  await assert.rejects(result)
  assert.equal(sender.killed, true)
  assert.equal(receiver.killed, true)
})
test('broken transport stops both processes', async () => {
  const sender = processFixture(), receiver = processFixture()
  const result = transferImage(sender, receiver)
  receiver.stdin.emit('error', new Error('synthetic connection failure'))
  await assert.rejects(result)
  assert.equal(sender.killed, true)
})
test('timeout stops an unresponsive exporter and receiver', async () => {
  const sender = processFixture(), receiver = processFixture()
  await assert.rejects(transferImage(sender, receiver, 10))
  assert.equal(sender.killed, true)
  assert.equal(receiver.killed, true)
})
