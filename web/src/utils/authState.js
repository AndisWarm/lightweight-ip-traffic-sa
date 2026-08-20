export const TOKEN_KEY = 'sa_access_token'
export const AUTH_EXPIRED_EVENT = 'sa-auth-expired'

let authExpiredNotified = false

export const getStoredToken = () => localStorage.getItem(TOKEN_KEY) || ''

export const setStoredToken = (token) => {
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
