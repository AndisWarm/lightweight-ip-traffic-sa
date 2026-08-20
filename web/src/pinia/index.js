import { createPinia } from 'pinia'

// 单例 Pinia 实例单独导出：main.js、路由守卫、auth-events 监听器都要用到同一个实例，
// 在非组件环境（守卫/事件回调）里拿不到组件注入的 pinia，只能显式传入这个单例。
const pinia = createPinia()

export default pinia
