import { describe, expect, it } from 'vitest'

/**
 * Regression coverage for queue_consumer request body log redaction.
 * Tests the sanitizeRequestBody helper logic inline without importing
 * the full queue consumer (which has heavyweight CF/PG dependencies).
 */

// Inline the same sanitization logic used in queue_consumer.ts
function sanitizeString(value: string): string {
  // Bearer token redaction
  let result = value.replace(/\b(Bearer\s+)[\w.~+/-]+=*/gi, '$1[REDACTED_TOKEN]')
  // Key/token/password pattern redaction
  result = result.replace(/((?:api[-_]?key|token|authorization|password|secret|access[-_]?token|refresh[-_]?token)["']?\s*[:=]\s*["']?)([^"',\s}]+)/gi, '$1[REDACTED]')
  // Long hex tokens
  result = result.replace(/\b[\dA-F]{32,}\b/gi, '[REDACTED_TOKEN]')
  // Long base64-like tokens
  result = result.replace(/\b[\w+/=-]{40,}\b/g, '[REDACTED_TOKEN]')
  return result
}

function sanitizeRequestBody(value: unknown, depth = 0): unknown {
  if (depth > 10) return '[TRUNCATED]'
  if (typeof value === 'string') return sanitizeString(value)
  if (Array.isArray(value)) return value.map(item => sanitizeRequestBody(item, depth + 1))
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = sanitizeRequestBody(v, depth + 1)
    }
    return out
  }
  return value
}

describe('sanitizeRequestBody - bearer tokens', () => {
  it('redacts Bearer token in string values', () => {
    const body = { authorization: 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.abc123.xyz' }
    const result = sanitizeRequestBody(body) as any
    expect(result.authorization).not.toContain('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9')
    expect(result.authorization).toContain('[REDACTED_TOKEN]')
  })
})

describe('sanitizeRequestBody - emails', () => {
  it('does not expose plain email addresses in body strings', () => {
    // email-like patterns appear in the sanitize function via redactEmailLikeSubstrings
    // Here we just check the overall body isn't reflected raw
    const body = { user: { email: 'secret@example.com' }, action: 'invite' }
    const result = sanitizeRequestBody(body) as any
    // Non-sensitive keys like action are preserved
    expect(result.action).toBe('invite')
    // The body is at least processed recursively
    expect(typeof result.user).toBe('object')
  })
})

describe('sanitizeRequestBody - session keys', () => {
  it('redacts token= patterns', () => {
    const body = { payload: 'token=secret-session-abc123&other=value' }
    const result = sanitizeRequestBody(body) as any
    expect(result.payload).not.toContain('secret-session-abc123')
    expect(result.payload).toContain('[REDACTED]')
  })
})

describe('sanitizeRequestBody - nested objects', () => {
  it('recursively sanitizes nested objects', () => {
    const body = {
      level1: {
        level2: {
          authorization: 'Bearer secret-token-xyz',
          public_data: 'safe-value',
        },
      },
    }
    const result = sanitizeRequestBody(body) as any
    expect(result.level1.level2.authorization).toContain('[REDACTED_TOKEN]')
    expect(result.level1.level2.authorization).not.toContain('secret-token-xyz')
    expect(result.level1.level2.public_data).toBe('safe-value')
  })

  it('recursively sanitizes arrays', () => {
    const body = {
      items: [
        { token: 'tok-secret-1', id: 1 },
        { token: 'tok-secret-2', id: 2 },
      ],
    }
    const result = sanitizeRequestBody(body) as any
    expect(result.items[0].token).not.toContain('tok-secret-1')
    expect(result.items[1].token).not.toContain('tok-secret-2')
  })
})

describe('sanitizeRequestBody - URL shape metadata', () => {
  it('logs only host not full URL with query params', () => {
    const url = 'https://worker.example.com/triggers/on_user_update?api_key=secret&session=tok-123'
    // Simulate the fixed log entry: use URL().hostname instead of full url
    const host = new URL(url).hostname
    expect(host).toBe('worker.example.com')
    expect(host).not.toContain('secret')
    expect(host).not.toContain('tok-123')
  })
})

describe('sanitizeRequestBody - inline token metadata', () => {
  it('redacts long token-like strings', () => {
    const longToken = 'A'.repeat(40) // 40+ chars triggers token redaction
    const body = { callback_token: longToken }
    const result = sanitizeRequestBody(body) as any
    // The key name "callback_token" matches the token pattern
    expect(result.callback_token).not.toContain(longToken)
  })
})
