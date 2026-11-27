import type { Config, Context } from '@netlify/edge-functions'

/**
 * 站点访问密码校验
 *
 * 在任何页面、脚本、代理接口返回之前，先校验访问者是否已输入正确的 PASSWORD 环境变量。
 * 未通过校验的页面请求会看到密码输入页；其他资源请求直接返回 401。
 * 校验通过后写入 HttpOnly Cookie（由密码派生的签名，密码修改后自动失效）。
 */

const COOKIE_NAME = 'libretv_auth'
const COOKIE_MAX_AGE = 90 * 24 * 60 * 60 // 90 天
const LOGIN_PATH = '/__auth'
const LOGOUT_PATH = '/__logout'

const encoder = new TextEncoder()

async function deriveToken(password: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode('libretv-site-access-v1'))
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

function safeNext(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/'
  if (value.startsWith(LOGIN_PATH) || value.startsWith(LOGOUT_PATH)) return '/'
  return value
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)
}

function isPageRequest(req: Request, url: URL): boolean {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false
  const accept = req.headers.get('accept') || ''
  if (accept.includes('text/html')) return true
  const p = url.pathname
  return p === '/' || p.endsWith('/') || p.endsWith('.html') || !p.split('/').pop()!.includes('.')
}

function loginPage(next: string, error: boolean, status: number): Response {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>LibreTV - 访问验证</title>
<link rel="icon" href="/image/logo.png">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#000;color:#fff;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
    background-image:radial-gradient(circle at 20% 20%,rgba(0,204,255,.12),transparent 40%),radial-gradient(circle at 80% 80%,rgba(255,0,170,.12),transparent 40%)}
  .card{width:min(92vw,380px);background:#111;border:1px solid #333;border-radius:14px;padding:32px 28px;box-shadow:0 20px 60px rgba(0,0,0,.6)}
  .brand{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:8px}
  .brand img{width:40px;height:40px}
  h1{font-size:28px;font-weight:700;background:linear-gradient(90deg,#00ccff,#ff00aa);-webkit-background-clip:text;background-clip:text;color:transparent}
  p.sub{text-align:center;color:#999;font-size:14px;margin-bottom:24px}
  input{width:100%;background:#000;border:1px solid #333;color:#fff;padding:12px 14px;border-radius:8px;font-size:16px;outline:none;transition:border-color .2s}
  input:focus{border-color:#00ccff}
  button{margin-top:16px;width:100%;padding:12px;border:0;border-radius:8px;font-size:16px;font-weight:600;color:#fff;cursor:pointer;
    background:linear-gradient(90deg,#00a8e8,#d6008f);transition:opacity .2s}
  button:hover{opacity:.9}
  .err{color:#ff4d6d;font-size:14px;margin-top:12px;text-align:center}
</style>
</head>
<body>
  <main class="card">
    <div class="brand"><img src="/image/logo.png" alt=""><h1>LibreTV</h1></div>
    <p class="sub">请输入访问密码以继续</p>
    <form method="POST" action="${LOGIN_PATH}">
      <input type="hidden" name="next" value="${escapeHtml(next)}">
      <input type="password" name="password" placeholder="密码..." autocomplete="current-password" autofocus required>
      <button type="submit">进入</button>
      ${error ? '<p class="err">密码错误，请重试</p>' : ''}
    </form>
  </main>
</body>
</html>`
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-robots-tag': 'noindex',
    },
  })
}

export default async (req: Request, context: Context) => {
  const url = new URL(req.url)
  const password = Netlify.env.get('PASSWORD') || ''

  // 未配置密码时拒绝访问（失败即关闭），避免站点意外公开
  if (!password) {
    return new Response('站点未配置访问密码 (PASSWORD)，暂时无法访问。', {
      status: 503,
      headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
    })
  }

  const expected = await deriveToken(password)
  const secure = url.protocol === 'https:'

  // 退出登录
  if (url.pathname === LOGOUT_PATH) {
    context.cookies.delete({ name: COOKIE_NAME, path: '/' })
    return new Response(null, { status: 303, headers: { location: '/', 'cache-control': 'no-store' } })
  }

  // 提交密码
  if (url.pathname === LOGIN_PATH) {
    if (req.method !== 'POST') {
      return loginPage(safeNext(url.searchParams.get('next')), false, 200)
    }
    let input = ''
    let next = '/'
    try {
      const form = await req.formData()
      input = String(form.get('password') || '')
      next = safeNext(String(form.get('next') || '/'))
    } catch {
      // 忽略格式错误的表单
    }
    if (input && safeEqual(await deriveToken(input), expected)) {
      context.cookies.set({
        name: COOKIE_NAME,
        value: expected,
        path: '/',
        httpOnly: true,
        secure,
        sameSite: 'Lax',
        maxAge: COOKIE_MAX_AGE,
      })
      return new Response(null, { status: 303, headers: { location: next, 'cache-control': 'no-store' } })
    }
    // 密码错误：稍作延迟以减缓暴力尝试
    await new Promise((r) => setTimeout(r, 800))
    return loginPage(next, true, 401)
  }

  // 已通过校验，放行
  const token = context.cookies.get(COOKIE_NAME)
  if (token && safeEqual(token, expected)) {
    return
  }

  // 未通过校验
  if (isPageRequest(req, url)) {
    return loginPage(safeNext(url.pathname + url.search), false, 401)
  }
  return new Response('Unauthorized', {
    status: 401,
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
  })
}

export const config: Config = {
  path: '/*',
  // 登录页需要使用的 Logo、PWA 清单与爬虫规则无需校验
  excludedPath: ['/image/*', '/manifest.json', '/robots.txt', '/favicon.ico'],
}
