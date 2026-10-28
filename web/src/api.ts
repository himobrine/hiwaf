const BASE = (import.meta as any).env?.VITE_API_BASE || ''

let token = localStorage.getItem('waf_token') || ''

export function setToken(t: string) {
  token = t
  if (t) localStorage.setItem('waf_token', t)
  else localStorage.removeItem('waf_token')
}

export function getToken() {
  return token
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export async function api<T = any>(
  path: string,
  opts: { method?: string; body?: any } = {},
): Promise<T> {
  const headers: Record<string, string> = {}
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  if (token) headers['Authorization'] = 'Bearer ' + token

  const r = await fetch(BASE + path, {
    method: opts.method || 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  })

  const txt = await r.text()
  let data: any = {}
  if (txt) {
    try {
      data = JSON.parse(txt)
    } catch {
      data = { raw: txt }
    }
  }
  if (!r.ok) {
    let msg = data?.detail ?? data?.raw ?? r.statusText
    if (typeof msg !== 'string') msg = JSON.stringify(msg)
    if (r.status === 401) {
      setToken('')
      localStorage.removeItem('waf_user')
      window.dispatchEvent(new Event('waf:unauthorized'))
    }
    throw new ApiError(r.status, msg)
  }
  return data as T
}

/** multipart 上传（不手动设 Content-Type，浏览器带 boundary）。 */
export async function apiUpload<T = any>(path: string, form: FormData): Promise<T> {
  const headers: Record<string, string> = {}
  if (token) headers['Authorization'] = 'Bearer ' + token
  const r = await fetch(BASE + path, { method: 'POST', headers, body: form })
  const txt = await r.text()
  let data: any = {}
  if (txt) {
    try {
      data = JSON.parse(txt)
    } catch {
      data = { raw: txt }
    }
  }
  if (!r.ok) {
    let msg = data?.detail ?? data?.raw ?? r.statusText
    if (typeof msg !== 'string') msg = JSON.stringify(msg)
    if (r.status === 401) {
      setToken('')
      localStorage.removeItem('waf_user')
      window.dispatchEvent(new Event('waf:unauthorized'))
    }
    throw new ApiError(r.status, msg)
  }
  return data as T
}

/** 下载二进制（packet body）；审计由服务端在返回前完成，失败会返回 JSON detail。 */
export async function download(path: string, fallbackName: string): Promise<void> {
  const headers: Record<string, string> = {}
  if (token) headers['Authorization'] = 'Bearer ' + token
  const r = await fetch(BASE + path, { headers })
  if (!r.ok) {
    let msg = r.statusText
    try {
      const txt = await r.text()
      if (txt) {
        try {
          const d = JSON.parse(txt)
          msg = typeof d?.detail === 'string' ? d.detail : txt
        } catch {
          msg = txt
        }
      }
    } catch {
      /* ignore */
    }
    throw new ApiError(r.status, msg || '下载失败')
  }
  const blob = await r.blob()
  const cd = r.headers.get('content-disposition') || ''
  const m = /filename="([^"]+)"/i.exec(cd)
  const name = m?.[1] || fallbackName
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}

const p2 = (n: number) => String(n).padStart(2, '0')

export function fmtTs(ms?: number | null) {
  if (!ms) return '-'
  const d = new Date(ms)
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(
    d.getMinutes(),
  )}:${p2(d.getSeconds())}`
}

export function fmtNum(v?: number | null, digits = 4) {
  if (v === null || v === undefined || Number.isNaN(Number(v))) return '-'
  return Number(v).toFixed(digits)
}

export function fmtInt(v?: number | null) {
  if (v === null || v === undefined) return '-'
  return Number(v).toLocaleString()
}

export function fmtBytes(n?: number | null) {
  if (!n) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let x = Number(n)
  while (x >= 1024 && i < u.length - 1) {
    x /= 1024
    i++
  }
  return `${x.toFixed(i === 0 ? 0 : 1)} ${u[i]}`
}

export function fmtPct(v?: number | null, digits = 2) {
  if (v === null || v === undefined) return '-'
  return `${(Number(v) * 100).toFixed(digits)}%`
}
