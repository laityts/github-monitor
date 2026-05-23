import { b64decode, b64encode, timingSafeEqual } from '../lib/crypto'

const ITERATIONS = 100_000

export async function hashPassword(plain: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const bits = await deriveBits(plain, salt, ITERATIONS)
  return `$pbkdf2$iter=${ITERATIONS}$${b64encode(salt)}$${b64encode(new Uint8Array(bits))}`
}

export async function verifyPassword(plain: string, stored: string): Promise<boolean> {
  const m = stored.match(/^\$pbkdf2\$iter=(\d+)\$([^$]+)\$([^$]+)$/)
  if (!m) return false
  const iter = parseInt(m[1]!, 10)
  if (!Number.isFinite(iter) || iter < 1) return false
  let salt: Uint8Array, expected: Uint8Array
  try { salt = b64decode(m[2]!); expected = b64decode(m[3]!) }
  catch { return false }
  const bits = await deriveBits(plain, salt, iter)
  const actual = new Uint8Array(bits)
  return timingSafeEqual(b64encode(actual), b64encode(expected))
}

async function deriveBits(plain: string, salt: Uint8Array, iterations: number): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(plain), 'PBKDF2', false, ['deriveBits'],
  )
  return crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    key, 256,
  )
}
