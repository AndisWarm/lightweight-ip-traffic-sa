// token 存储键与"登录失效"自定义事件名统一放这里，供 request.js / auth-events.js / pinia 共用，避免魔法字符串散落各处。
export const TOKEN_KEY = 'sa_access_token'
export const AUTH_EXPIRED_EVENT = 'sa-auth-expired'

// 防重标记：同一轮登录失效只广播一次，避免多个请求同时 401 时反复弹提示/跳转。
let authExpiredNotified = false

export const getStoredToken = () => localStorage.getItem(TOKEN_KEY) || ''

export const setStoredToken = (token) => {
  // 写入新 token 时重置防重标记，允许下一次失效再次广播。
  authExpiredNotified = false
  if (token) {
    localStorage.setItem(TOKEN_KEY, token)
  } else {
    localStorage.removeItem(TOKEN_KEY)
  }
}

export const clearStoredToken = () => {
  localStorage.removeItem(TOKEN_KEY)
}

export const notifyAuthExpired = (message) => {
  // 用自定义事件解耦：拦截器不直接跳转/清态，而是广播事件，由 auth-events 监听器统一处理。
  if (authExpiredNotified) {
    return
  }
  authExpiredNotified = true
  window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT, {
    detail: {
      message,
    },
  }))
}
