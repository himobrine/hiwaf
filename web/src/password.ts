/** 强密码策略：与后端 `service/auth.py:password_error` 保持同一套规则（前端只做提示）。 */

export const PASSWORD_MIN_LEN = 12
export const PASSWORD_MAX_LEN = 128
export const PASSWORD_MIN_DISTINCT = 8

const WEAK = new Set([
  'password', 'password1', 'password123', 'passw0rd', 'p@ssw0rd',
  '123456', '1234567', '12345678', '123456789', '1234567890',
  'qwerty', 'qwerty123', 'abc123', 'admin', 'admin123', 'administrator',
  'letmein', 'welcome', 'welcome1', 'iloveyou', 'monkey', 'dragon',
  'changeme', 'root', 'toor', 'guest', 'test', 'test123', 'waf', 'waf123',
])

const SEQUENCES = [
  '0123', '1234', '2345', '3456', '4567', '5678', '6789', '7890',
  'abcd', 'bcde', 'cdef', 'qwer', 'wert', 'asdf', 'sdfg', 'zxcv', 'xcvb',
  '!@#$', '@#$%', '#$%^',
]

export function passwordError(pw: string, username?: string): string | null {
  if (typeof pw !== 'string') return '密码格式错误'
  if (pw.length < PASSWORD_MIN_LEN) return `密码至少 ${PASSWORD_MIN_LEN} 位`
  if (pw.length > PASSWORD_MAX_LEN) return `密码最多 ${PASSWORD_MAX_LEN} 位`
  if (/\s/.test(pw)) return '密码不能包含空格/制表符'
  const low = pw.toLowerCase()
  if (username && username.length >= 3 && low.includes(username.toLowerCase())) {
    return '密码不能包含用户名'
  }
  if (WEAK.has(low)) return '密码太常见，请换一个'
  if (new Set(pw).size < PASSWORD_MIN_DISTINCT) {
    return `密码至少要有 ${PASSWORD_MIN_DISTINCT} 个不同字符`
  }
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].every((r) => r.test(pw))
  if (!classes) return '密码必须同时包含大写字母、小写字母、数字和特殊字符'
  if (/(.)\1{3,}/.test(pw)) return '密码包含过长的重复字符'
  if (SEQUENCES.some((s) => low.includes(s))) return '密码包含连续/键盘序列'
  return null
}

const SETS = [
  'ABCDEFGHJKLMNPQRSTUVWXYZ',
  'abcdefghijkmnopqrstuvwxyz',
  '23456789',
  '!@#$%^&*()-_=+',
]

function randInt(n: number): number {
  const a = new Uint32Array(1)
  crypto.getRandomValues(a)
  return a[0] % n
}

/** 生成一个满足策略的随机密码（每类至少 1 个，默认 16 位）。 */
export function generateStrongPassword(len = 16): string {
  const all = SETS.join('')
  const target = Math.max(len, PASSWORD_MIN_LEN)
  const build = () => {
    const chars = SETS.map((s) => s[randInt(s.length)])
    while (chars.length < target) chars.push(all[randInt(all.length)])
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randInt(i + 1)
      ;[chars[i], chars[j]] = [chars[j], chars[i]]
    }
    return chars.join('')
  }
  for (let i = 0; i < 20; i++) {
    const p = build()
    if (!passwordError(p)) return p
  }
  return build()
}