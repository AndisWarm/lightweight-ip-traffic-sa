import axios from 'axios'

import { getStoredToken, notifyAuthExpired } from '../utils/authState'

// 统一 baseURL 与超时：所有业务 API 复用这一个实例，避免每个模块重复配置地址与超时。
// baseURL 只写相对前缀 /api/v1，实际域名/端口由 Vite 开发代理转发，生产环境依赖同源部署或网关。
const service = axios.create({
  baseURL: '/api/v1',
  timeout: 10000,
})

// 请求拦截器：发请求前统一注入 Authorization: Bearer <token>，业务层无需手动拼接头。
service.interceptors.request.use((config) => {
  const token = getStoredToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截器：统一处理 HTTP 状态码级错误分流（401/403/5xx），页面组件只关心业务成功分支。
// 成功时原样返回完整响应对象，业务层统一读 resp.data.data（后端统一结构为 { code, message, data }）。
service.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status
    const responseMessage = error?.response?.data?.message
    let message = responseMessage || error.message || '请求失败'

    if (status === 401) {
      // 401：令牌缺失/过期。这里只广播"登录失效"事件，真正清 token + 跳登录页由 auth-events 监听器统一完成，
      // 避免多个请求同时 401 时重复清态、重复跳转。
      notifyAuthExpired(responseMessage || '登录已失效，请重新登录')
    }

    if (status === 403) {
      // 403：已登录但无权限执行该操作；优先采用后端返回的具体提示，否则用统一默认文案。
      message = responseMessage && responseMessage !== '无权访问当前资源'
        ? responseMessage
        : '当前账号无权执行此操作'
    }

    if (status >= 500 && !responseMessage) {
      // 5xx：服务端异常。只在后端未给出具体 message 时兜底，避免覆盖后端下发的可读错误。
      message = '系统开小差了，请稍后重试'
    }

    // 统一 reject 一个带统一文案的 Error，调用方 catch 到的都是可读信息，而非裸的 axios 错误对象。
    return Promise.reject(new Error(message))
  }
)

export default service
