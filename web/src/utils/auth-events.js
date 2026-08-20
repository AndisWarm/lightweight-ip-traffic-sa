import { useUserStore } from '../pinia/modules/user'
import pinia from '../pinia'
import { AUTH_EXPIRED_EVENT } from './authState'
import router from '../router'

// 安装守卫：只允许挂载一次，防止重复注册导致同一 401 事件被处理多次。
let authExpiredListenerInstalled = false

// 401 事件总线设计：Axios 拦截器只负责"发现登录失效并广播"，真正的清态 + 跳登录页集中在这里监听完成。
// 好处是无论多少个接口同时返回 401，都只触发一次统一清理与跳转；且不在拦截器里直接 import 路由，避免循环依赖。
export const installAuthExpiredListener = () => {
  if (authExpiredListenerInstalled || typeof window === 'undefined') {
    return
  }
  authExpiredListenerInstalled = true
  window.addEventListener(AUTH_EXPIRED_EVENT, (event) => {
    const userStore = useUserStore(pinia)
    // 清空内存与 localStorage 的登录态，让所有依赖 userStore 的视图立即感知失效。
    userStore.handleAuthExpired(event?.detail?.message)
    // 当前不在登录页才跳转，避免在登录页自身重复 replace 造成无意义跳转。
    if (router.currentRoute.value.path !== '/login') {
      router.replace('/login')
    }
  })
}
