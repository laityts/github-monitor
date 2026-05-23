import { describe, expect, it, beforeEach } from 'vitest'
import { makeKvMock, type MockEnv } from './kv-mock'
import { recordFailure, clearAttempts, isLockedOut } from '../../src/auth/rate-limit'

let env: MockEnv

beforeEach(() => {
  env = makeKvMock()
})

describe('auth/rate-limit', () => {
  it('5 次失败后锁定 10 分钟', async () => {
    for (let i = 0; i < 4; i++) {
      const r = await recordFailure(env, '1.1.1.1')
      expect(r.lockedOut).toBe(false)
    }
    const r5 = await recordFailure(env, '1.1.1.1')
    expect(r5.lockedOut).toBe(true)

    const status = await isLockedOut(env, '1.1.1.1')
    expect(status.lockedOut).toBe(true)
    if (status.lockedOut) expect(status.remainingMs).toBeGreaterThan(0)
  })

  it('成功登录后 clearAttempts 清零', async () => {
    for (let i = 0; i < 3; i++) await recordFailure(env, '2.2.2.2')
    await clearAttempts(env, '2.2.2.2')
    const status = await isLockedOut(env, '2.2.2.2')
    expect(status.lockedOut).toBe(false)
  })

  it('不同 IP 隔离', async () => {
    for (let i = 0; i < 5; i++) await recordFailure(env, '3.3.3.3')
    expect((await isLockedOut(env, '3.3.3.3')).lockedOut).toBe(true)
    expect((await isLockedOut(env, '4.4.4.4')).lockedOut).toBe(false)
  })

  it('未尝试过的 IP 不锁定', async () => {
    expect((await isLockedOut(env, '9.9.9.9')).lockedOut).toBe(false)
  })
})
