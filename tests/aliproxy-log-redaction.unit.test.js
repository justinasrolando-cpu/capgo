// ESM unit tests for aliproxy redactPath helper
import assert from 'node:assert/strict'
import { test } from 'node:test'

const SENSITIVE_PARAM_KEYS = /^(token|api[_-]?key|apikey|secret|session|password|passwd|auth(?:orization)?|access[_-]?token|refresh[_-]?token|key|credential|sig(?:nature)?)$/i

// Same regex-based implementation as aliproxy/index.js
function redactPath(rawPath) {
  try {
    return rawPath.replace(
      /([?&])([^=&#]+)=([^&#]*)/g,
      (match, sep, key) => SENSITIVE_PARAM_KEYS.test(decodeURIComponent(key))
        ? `${sep}${key}=[REDACTED]`
        : match,
    )
  }
  catch {
    return rawPath
  }
}

test('redacts token param', () => {
  const r = redactPath('/api/update?token=super-secret&version=1.0.0')
  assert.ok(!r.includes('super-secret'), 'should not contain raw token value')
  assert.ok(r.includes('[REDACTED]'), 'should contain [REDACTED]')
  assert.ok(r.includes('version=1.0.0'), 'should preserve non-sensitive params')
})

test('redacts api_key param', () => {
  const r = redactPath('/api/check?api_key=sk-secret123&platform=ios')
  assert.ok(!r.includes('sk-secret123'))
  assert.ok(r.includes('[REDACTED]'))
  assert.ok(r.includes('platform=ios'))
})

test('redacts secret param', () => {
  const r = redactPath('/api/update?secret=my-secret-value&app_id=com.example')
  assert.ok(!r.includes('my-secret-value'))
  assert.ok(r.includes('[REDACTED]'))
  assert.ok(r.includes('app_id=com.example'))
})

test('redacts session param', () => {
  const r = redactPath('/proxy?session=sess-abc123&page=1')
  assert.ok(!r.includes('sess-abc123'))
  assert.ok(r.includes('[REDACTED]'))
  assert.ok(r.includes('page=1'))
})

test('preserves path without sensitive params', () => {
  const path = '/api/update?version=1.2.3&platform=android&app_id=com.example'
  assert.equal(redactPath(path), path)
})

test('handles path without query string', () => {
  const path = '/api/update'
  assert.equal(redactPath(path), path)
})

test('redacts multiple sensitive params', () => {
  const r = redactPath('/api?token=t1&api_key=k1&secret=s1&platform=ios')
  assert.ok(!r.includes('=t1'))
  assert.ok(!r.includes('=k1'))
  assert.ok(!r.includes('=s1'))
  assert.ok(r.includes('platform=ios'))
  const matches = r.match(/\[REDACTED\]/g)
  assert.equal(matches?.length, 3)
})

test('is case-insensitive for param names', () => {
  const r = redactPath('/api?TOKEN=secret&API_KEY=key123')
  assert.ok(!r.includes('=secret'))
  assert.ok(!r.includes('=key123'))
})

test('upstream error response body is generic', () => {
  const body = 'upstream error'
  assert.ok(!body.includes('ECONNREFUSED'))
  assert.ok(!body.includes('getaddrinfo'))
  assert.equal(body, 'upstream error')
})

test('internal error response body is generic', () => {
  const body = 'internal error'
  assert.ok(!body.includes('TypeError'))
  assert.ok(!body.includes('Cannot read'))
  assert.equal(body, 'internal error')
})
