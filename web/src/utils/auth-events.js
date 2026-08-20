import { useUserStore } from '../pinia/modules/user'
import pinia from '../pinia'
import { AUTH_EXPIRED_EVENT } from './authState'
import router from '../router'

let authExpiredListenerInstalled = false

export const installAuthExpiredListener = () => {
  if (authExpiredListenerInstalled || typeof window === 'undefined') {
    return
  }
  authExpiredListenerInstalled = true
  window.addEventListener(AUTH_EXPIRED_EVENT, (event) => {
    const userStore = useUserStore(pinia)
    userStore.handleAuthExpired(event?.detail?.message)
    if (router.currentRoute.value.path !== '/login') {
      router.replace('/login')
    }
  })
}
