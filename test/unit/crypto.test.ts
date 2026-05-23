import { describe, expect, it } from 'vitest'
import { b64encode, b64decode, hmacSha256, randomBase64Url, sha256Hex, timingSafeEqual } from '../../src/lib/crypto'
import { hashPassword, verifyPassword } from '../../src/auth/password'

describe('lib/crypto', () => {
  it('b64encode/decode 互逆', () => {
    const bytes = new Uint8Array([1, 2, 3, 250])
    expect(b64decode(b64encode(bytes))).toEqual(bytes)
  })

  it('sha256Hex 输出 64 位十六进制', async () => {
    const hex = await sha256Hex('admin123')
    expect(hex).toMatch(/^[0-9a-f]{64}$/)
  })

  it('hmacSha256 同输入产生相同输出，不同输入不同', async () => {
    const a = await hmacSha256('secret', 'data')
    const b = await hmacSha256('secret', 'data')
    const c = await hmacSha256('secret', 'data2')
    expect(a).toBe(b)
    expect(a).not.toBe(c)
  })

  it('randomBase64Url 产生 URL 安全字符串', () => {
    const s = randomBase64Url(32)
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(s.length).toBeGreaterThan(30)
  })

  it('timingSafeEqual', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true)
    expect(timingSafeEqual('abc', 'abd')).toBe(false)
    expect(timingSafeEqual('abc', 'abcd')).toBe(false)
  })
})

describe('auth/password', () => {
  it('hash + verify 配对成功', async () => {
    const h = await hashPassword('s3cret!')
    expect(h).toMatch(/^\$pbkdf2\$iter=\d+\$[^$]+\$[^$]+$/)
    expect(await verifyPassword('s3cret!', h)).toBe(true)
  })

  it('错误密码拒绝', async () => {
    const h = await hashPassword('s3cret!')
    expect(await verifyPassword('wrong', h)).toBe(false)
  })

  it('每次 hash 产生不同 salt / 不同结果', async () => {
    const h1 = await hashPassword('same')
    const h2 = await hashPassword('same')
    expect(h1).not.toBe(h2)
    expect(await verifyPassword('same', h1)).toBe(true)
    expect(await verifyPassword('same', h2)).toBe(true)
  })

  it('损坏格式返回 false', async () => {
    expect(await verifyPassword('x', 'not-a-pbkdf2-string')).toBe(false)
  })
})
